"""Gateway entry point for the EasyPi agent."""

from __future__ import annotations

from typing import Any

from app.agent.core.actions import AgentActionPlanner, AgentActionRegistry
from app.agent.adapters.backup import BackupAdapter
from app.agent.adapters.ai_runtime import AIRuntimeAdapter
from app.agent.adapters.cameras import CamerasAdapter
from app.agent.adapters.cloud import CloudAdapter
from app.agent.adapters.files import FilesAdapter
from app.agent.adapters.help import HelpAdapter
from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.adapters.netprotection import NetProtectionAdapter
from app.agent.adapters.network_activity import NetworkActivityAdapter
from app.agent.adapters.network_toolkit import NetworkToolkitAdapter
from app.agent.adapters.personal_dns import PersonalDNSAdapter
from app.agent.adapters.provider import ProviderAdapter
from app.agent.adapters.remote_access import RemoteAccessAdapter
from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.settings import SettingsAdapter
from app.agent.adapters.setup import SetupAdapter
from app.agent.adapters.terminal import TerminalAdapter
from app.agent.adapters.users import UsersAdapter
from app.agent.adapters.users_auth import UsersAuthAdapter
from app.agent.adapters.wireguard import WireGuardAdapter
from app.agent.adapters.outbound_vpn import OutboundVpnAdapter
from app.agent.adapters.stealth import StealthAdapter
from app.agent.adapters.operations import OperationsAdapter
from app.agent.adapters.extended_diagnostics import ExtendedDiagnosticsAdapter
from app.agent.core.context import build_agent_context
from app.agent.core.contracts import AgentActionResult, AgentFact, AgentRequest, AgentResponse
from app.agent.core.fallback import build_unsupported_response
from app.agent.core.probes import AgentProbeRegistry
from app.agent.core.probe_routing import build_probe_response, normalize_probe_selections, select_probe
from app.agent.core.registry import AgentRegistry
from app.agent.core.response_builder import finalize_response
from app.agent.core.router import AgentRouter
from app.agent.core.sanitization import normalize_agent_request
from app.agent.modules.backup_agent import BackupAgent
from app.agent.modules.ai_runtime_agent import AIRuntimeAgent
from app.agent.modules.camera_backup_cloud_reasoning_agent import CameraBackupCloudReasoningAgent
from app.agent.modules.cameras_agent import CamerasAgent
from app.agent.modules.claude_provider_agent import ClaudeProviderAgent
from app.agent.modules.cloud_agent import CloudAgent
from app.agent.modules.dashboard_agent import DashboardAgent
from app.agent.modules.dashboard_incident_agent import DashboardIncidentAgent
from app.agent.modules.files_agent import FilesAgent
from app.agent.modules.guard_remote_setup_reasoning_agent import GuardRemoteSetupReasoningAgent
from app.agent.modules.help_agent import HelpAgent
from app.agent.modules.marketplace_agent import MarketplaceAgent
from app.agent.modules.monitoring_agent import MonitoringAgent
from app.agent.modules.netprotection_agent import NetProtectionAgent
from app.agent.modules.network_activity_agent import NetworkActivityAgent
from app.agent.modules.network_toolkit_agent import NetworkToolkitAgent
from app.agent.modules.personal_dns_agent import PersonalDNSAgent
from app.agent.modules.remote_dashboard_services_reasoning_agent import RemoteDashboardServicesReasoningAgent
from app.agent.modules.remote_access_agent import RemoteAccessAgent
from app.agent.modules.security_agent import SecurityAgent
from app.agent.modules.settings_agent import SettingsAgent
from app.agent.modules.setup_guard_network_reasoning_agent import SetupGuardNetworkReasoningAgent
from app.agent.modules.setup_agent import SetupAgent
from app.agent.modules.system_services_agent import SystemServicesAgent
from app.agent.modules.terminal_agent import TerminalAgent
from app.agent.modules.users_agent import UsersAgent
from app.agent.modules.users_auth_reasoning_agent import UsersAuthReasoningAgent
from app.agent.modules.users_security_settings_reasoning_agent import UsersSecuritySettingsReasoningAgent
from app.agent.modules.vpn_dashboard_security_reasoning_agent import VPNDashboardSecurityReasoningAgent
from app.agent.modules.wireguard_agent import WireGuardAgent
from app.agent.modules.outbound_vpn_agent import OutboundVpnAgent
from app.agent.modules.stealth_agent import StealthAgent
from app.agent.modules.jobs_agent import JobsAgent
from app.agent.modules.notifications_agent import NotificationsAgent
from app.agent.modules.rollback_agent import RollbackAgent


class AgentGateway:
    """Routes a request to the best matching agent module."""

    def __init__(
        self,
        registry: AgentRegistry,
        router: AgentRouter,
        action_registry: AgentActionRegistry | None = None,
        action_planner: AgentActionPlanner | None = None,
        probe_registry: AgentProbeRegistry | None = None,
    ) -> None:
        self.registry = registry
        self.router = router
        self.action_registry = action_registry or AgentActionRegistry()
        self.action_planner = action_planner or AgentActionPlanner()
        self.probe_registry = probe_registry or AgentProbeRegistry()

    async def explain(self, request: AgentRequest) -> AgentResponse:
        request = normalize_agent_request(request)
        context = build_agent_context(request)
        selected_probes = normalize_probe_selections(select_probe(request))

        # An explicit diagnostic intent is authoritative and must not depend on
        # an unrelated module winning the generic router. This also permits one
        # question to request several independent read-only probes.
        if selected_probes:
            probe_results: list[tuple[str, dict[str, Any]]] = []
            for probe_id, parameters in selected_probes:
                probe_results.append((probe_id, await self.probe_registry.run(probe_id, parameters)))
            return finalize_response(build_probe_response(request, probe_results))

        module = self.router.select(request)
        if module is None:
            return build_unsupported_response(request, context)

        try:
            response = await module.explain(request)
        except Exception as exc:
            response = AgentResponse(
                # TargetType also contains the routing-only value ``auto``, which
                # is not a valid fact category.  A bounded gateway failure is a
                # service-level fact regardless of the requested route.
                category="service",
                target=request.target or request.entity_id or request.route or "diagnostic-source",
                matched=True,
                title="Diagnostic source unavailable",
                summary="A required diagnostic source failed, so the current state cannot be confirmed.",
                confidence="low",
                section=request.route,
                subsection=request.tab,
                module=getattr(module, "name", None),
                source_status="unavailable",
                source_errors=[f"{type(exc).__name__}: {exc}"],
                facts=[AgentFact("Source failure", f"{type(exc).__name__}: {exc}", "warning")],
                recommendations=["Restore the failing source and retry the diagnostic."],
                reason_chain=["The selected diagnostic module could not finish reading its required source."],
            )
        if response is not None:
            response = finalize_response(response)
            # State-changing recommendations require current, internally
            # consistent evidence.  Never mint a confirmation capability from
            # stale, partial, conflicting, or unavailable source data.
            if response.source_status == "ok":
                response.actions = self.action_planner.suggest(request, response)
            else:
                response.actions = []
            for action in response.actions:
                if action.requires_confirmation:
                    action.confirmation_token = self.action_registry.issue_confirmation(
                        action.action_id,
                        action.parameters,
                        actor_user_id=request.actor_user_id,
                    )
            return finalize_response(response)

        return build_unsupported_response(request, context)

    async def execute_action(
        self,
        action_id: str,
        *,
        parameters: dict[str, Any] | None = None,
        confirmation_token: str | None = None,
        actor_user_id: int | None = None,
        follow_up_request: AgentRequest | None = None,
    ) -> AgentActionResult:
        result = await self.action_registry.execute(
            action_id,
            parameters,
            confirmation_token=confirmation_token,
            actor_user_id=actor_user_id,
        )
        if result.success and follow_up_request is not None:
            result.follow_up = await self.explain(normalize_agent_request(follow_up_request))
        return result

    async def run_probe(
        self,
        probe_id: str,
        *,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self.probe_registry.run(probe_id, parameters)


def build_default_agent_gateway(
    *,
    netprotection: Any | None = None,
    tailscale: Any | None = None,
    threat_monitor: Any | None = None,
    now_provider=None,
) -> AgentGateway:
    """Build the default gateway used by the diagnostics endpoint."""

    netprotection_adapter = NetProtectionAdapter(netprotection)
    service_status_adapter = ServiceStatusAdapter(
        netprotection=netprotection,
        tailscale=tailscale,
        threat_monitor=threat_monitor,
    )
    remote_access_adapter = RemoteAccessAdapter(tailscale=tailscale)
    backup_adapter = BackupAdapter()
    ai_runtime_adapter = AIRuntimeAdapter()
    cameras_adapter = CamerasAdapter()
    cloud_adapter = CloudAdapter()
    files_adapter = FilesAdapter()
    help_adapter = HelpAdapter()
    monitoring_adapter = MonitoringAdapter()
    network_activity_adapter = NetworkActivityAdapter()
    network_toolkit_adapter = NetworkToolkitAdapter()
    personal_dns_adapter = PersonalDNSAdapter()
    provider_adapter = ProviderAdapter(ai_runtime_adapter)
    security_adapter = SecurityAdapter(threat_monitor=threat_monitor)
    setup_adapter = SetupAdapter()
    settings_adapter = SettingsAdapter()
    terminal_adapter = TerminalAdapter()
    users_auth_adapter = UsersAuthAdapter()
    users_adapter = UsersAdapter()
    wireguard_adapter = WireGuardAdapter()
    outbound_vpn_adapter = OutboundVpnAdapter()
    stealth_adapter = StealthAdapter()
    operations_adapter = OperationsAdapter()
    action_registry = AgentActionRegistry()
    probe_registry = AgentProbeRegistry()
    extended_diagnostics_adapter = ExtendedDiagnosticsAdapter()

    registry = AgentRegistry(
        modules=[
            GuardRemoteSetupReasoningAgent(
                netprotection_adapter,
                service_status_adapter,
                setup_adapter,
            ),
            SetupGuardNetworkReasoningAgent(
                setup_adapter,
                netprotection_adapter,
                network_activity_adapter,
            ),
            RemoteDashboardServicesReasoningAgent(
                service_status_adapter,
                monitoring_adapter,
            ),
            DashboardIncidentAgent(
                monitoring_adapter,
                service_status_adapter,
                backup_adapter,
                cameras_adapter,
                wireguard_adapter,
                security_adapter,
                setup_adapter,
                cloud_adapter,
                users_auth_adapter,
            ),
            VPNDashboardSecurityReasoningAgent(
                wireguard_adapter,
                security_adapter,
                monitoring_adapter,
            ),
            ClaudeProviderAgent(provider_adapter),
            PersonalDNSAgent(personal_dns_adapter, netprotection_adapter),
            NetProtectionAgent(netprotection_adapter, now_provider=now_provider),
            RemoteAccessAgent(remote_access_adapter),
            SystemServicesAgent(service_status_adapter),
            SecurityAgent(security_adapter),
            DashboardAgent(
                monitoring_adapter,
                service_status_adapter,
                backup_adapter,
                cameras_adapter,
                wireguard_adapter,
                security_adapter,
            ),
            MonitoringAgent(monitoring_adapter),
            NetworkActivityAgent(network_activity_adapter),
            NetworkToolkitAgent(network_toolkit_adapter),
            WireGuardAgent(wireguard_adapter),
            OutboundVpnAgent(outbound_vpn_adapter),
            StealthAgent(stealth_adapter),
            JobsAgent(operations_adapter),
            NotificationsAgent(operations_adapter),
            RollbackAgent(operations_adapter),
            CameraBackupCloudReasoningAgent(cameras_adapter, backup_adapter, cloud_adapter),
            CamerasAgent(cameras_adapter),
            BackupAgent(backup_adapter),
            CloudAgent(cloud_adapter),
            HelpAgent(help_adapter),
            MarketplaceAgent(),
            FilesAgent(files_adapter),
            TerminalAgent(terminal_adapter),
            UsersSecuritySettingsReasoningAgent(
                users_auth_adapter,
                settings_adapter,
                security_adapter,
            ),
            UsersAuthReasoningAgent(users_auth_adapter),
            UsersAgent(users_adapter),
            SettingsAgent(settings_adapter),
            SetupAgent(setup_adapter),
            AIRuntimeAgent(ai_runtime_adapter),
        ]
    )
    _register_default_actions(
        action_registry,
        netprotection_adapter=netprotection_adapter,
        service_status_adapter=service_status_adapter,
        remote_access_adapter=remote_access_adapter,
        backup_adapter=backup_adapter,
        cameras_adapter=cameras_adapter,
        setup_adapter=setup_adapter,
        security_adapter=security_adapter,
        users_auth_adapter=users_auth_adapter,
        wireguard_adapter=wireguard_adapter,
        ai_runtime_adapter=ai_runtime_adapter,
        cloud_adapter=cloud_adapter,
        network_toolkit_adapter=network_toolkit_adapter,
    )
    _register_default_probes(probe_registry, extended_diagnostics_adapter)
    router = AgentRouter(registry)
    return AgentGateway(
        registry,
        router,
        action_registry=action_registry,
        action_planner=AgentActionPlanner(),
        probe_registry=probe_registry,
    )


def _register_default_probes(
    registry: AgentProbeRegistry,
    adapter: ExtendedDiagnosticsAdapter,
) -> None:
    """Register every explicit extended diagnostic surface with strict parameters."""

    definitions: dict[str, tuple[set[str], set[str]]] = {
        "health.dependencies": (set(), set()),
        "camera.ptz": ({"camera_id"}, {"camera_id"}),
        "camera.discovery": ({"target", "interface"}, set()),
        "camera.live": ({"camera_id"}, {"camera_id"}),
        "dns.profiles": ({"target", "entity_id"}, set()),
        "dns.rewrites": ({"target", "entity_id"}, set()),
        "prism.pipeline": ({"target"}, set()),
        "threat_monitor.journal": ({"target"}, set()),
        "tailscale.routes": ({"target", "entity_id"}, set()),
        "tailscale.funnel": ({"target"}, set()),
        "tasks.runtime": ({"task_id"}, set()),
        "services.runtime": ({"service_name"}, {"service_name"}),
        "notifications.delivery": ({"target", "entity_id"}, set()),
        "cloud.metadata": ({"target", "entity_id"}, set()),
        "files.outcome": ({"target", "entity_id"}, set()),
        "terminal.live": ({"target", "entity_id"}, set()),
        "auth.workflow": ({"target", "entity_id"}, set()),
        "wireguard.artifacts": ({"target", "entity_id"}, set()),
        "marketplace.runtime": ({"target", "entity_id"}, set()),
        "ai.inference": ({"target", "entity_id"}, set()),
        "backup.integrity": ({"snapshot_id"}, {"snapshot_id"}),
        "personal_dns.tenancy": ({"target", "entity_id", "actor_user_id"}, {"actor_user_id"}),
        "devices.admission": ({"device_id"}, set()),
        "heuristics.alerts": ({"severity", "limit"}, set()),
        "netprotection.components": ({"target"}, set()),
    }
    for probe_id, (allowed, required) in definitions.items():
        async def handler(parameters: dict[str, Any], *, current_probe_id: str = probe_id) -> dict[str, Any]:
            return await adapter.run(current_probe_id, parameters)

        registry.register(probe_id, handler, allowed_keys=allowed, required_keys=required)


def _register_default_actions(
    registry: AgentActionRegistry,
    *,
    netprotection_adapter: NetProtectionAdapter,
    service_status_adapter: ServiceStatusAdapter,
    remote_access_adapter: RemoteAccessAdapter,
    backup_adapter: BackupAdapter,
    cameras_adapter: CamerasAdapter,
    setup_adapter: SetupAdapter,
    security_adapter: SecurityAdapter,
    users_auth_adapter: UsersAuthAdapter,
    wireguard_adapter: WireGuardAdapter,
    ai_runtime_adapter: AIRuntimeAdapter,
    cloud_adapter: CloudAdapter,
    network_toolkit_adapter: NetworkToolkitAdapter,
) -> None:
    async def restore_internet(parameters: dict[str, Any]) -> dict[str, Any]:
        client_ip = str(parameters.get("client_ip") or "").strip()
        if not client_ip:
            return {"success": False, "message": "Missing client_ip for restore action."}
        return await netprotection_adapter.restore_internet(client_ip)

    async def allow_domain(parameters: dict[str, Any]) -> dict[str, Any]:
        domain = str(parameters.get("domain") or "").strip()
        if not domain:
            return {"success": False, "message": "Missing domain for allow action."}
        return await netprotection_adapter.add_to_whitelist(domain)

    async def block_domain(parameters: dict[str, Any]) -> dict[str, Any]:
        domain = str(parameters.get("domain") or "").strip()
        if not domain:
            return {"success": False, "message": "Missing domain for block action."}
        return await netprotection_adapter.add_to_blacklist(domain)

    async def create_full_backup(_: dict[str, Any]) -> dict[str, Any]:
        return await backup_adapter.create_backup(backup_type="full", name=None)

    async def cancel_running_backup(_: dict[str, Any]) -> dict[str, Any]:
        return await backup_adapter.cancel_latest_running_backup()

    async def start_camera_recording(parameters: dict[str, Any]) -> dict[str, Any]:
        camera_name = str(parameters.get("camera_name") or "").strip()
        if not camera_name:
            return {"success": False, "message": "Missing camera_name for camera action."}
        return await cameras_adapter.start_recording(camera_name)

    async def stop_camera_recording(parameters: dict[str, Any]) -> dict[str, Any]:
        camera_name = str(parameters.get("camera_name") or "").strip()
        if not camera_name:
            return {"success": False, "message": "Missing camera_name for camera action."}
        return await cameras_adapter.stop_recording(camera_name)

    async def run_permissions_setup(parameters: dict[str, Any]) -> dict[str, Any]:
        username = str(parameters.get("username") or "").strip() or None
        return await setup_adapter.setup_permissions(username)

    async def revoke_sessions(parameters: dict[str, Any]) -> dict[str, Any]:
        username = str(parameters.get("username") or "").strip()
        if not username:
            return {"success": False, "message": "Missing username for revoke sessions action."}
        return await users_auth_adapter.revoke_sessions(username)

    async def disable_2fa(parameters: dict[str, Any]) -> dict[str, Any]:
        username = str(parameters.get("username") or "").strip()
        if not username:
            return {"success": False, "message": "Missing username for disable 2FA action."}
        return await users_auth_adapter.disable_2fa(username)

    registry.register(
        "netprotection.restore_internet",
        restore_internet,
        allowed_keys={"client_ip", "client_name"},
        required_keys={"client_ip"},
    )
    registry.register(
        "netprotection.allow_domain",
        allow_domain,
        allowed_keys={"domain"},
        required_keys={"domain"},
    )
    registry.register(
        "netprotection.block_domain",
        block_domain,
        allowed_keys={"domain"},
        required_keys={"domain"},
    )
    registry.register("netprotection.restart_service", lambda _: netprotection_adapter.restart_service(), allowed_keys=set())
    registry.register("netprotection.start_service", lambda _: netprotection_adapter.start_service(), allowed_keys=set())
    registry.register("netprotection.stop_service", lambda _: netprotection_adapter.stop_service(), allowed_keys=set())
    registry.register("netprotection.enable_protection", lambda _: netprotection_adapter.enable_protection(), allowed_keys=set())
    registry.register("netprotection.disable_protection", lambda _: netprotection_adapter.disable_protection(), allowed_keys=set())
    registry.register("remote_access.start_tailscale", lambda _: remote_access_adapter.start(), allowed_keys=set())
    registry.register("remote_access.stop_tailscale", lambda _: remote_access_adapter.stop(), allowed_keys=set())
    registry.register("remote_access.logout_tailscale", lambda _: remote_access_adapter.logout(), allowed_keys=set())
    registry.register("threat_monitor.start", lambda _: service_status_adapter.start_threat_monitoring(), allowed_keys=set())
    registry.register("threat_monitor.stop", lambda _: service_status_adapter.stop_threat_monitoring(), allowed_keys=set())
    registry.register("backup.create_full", create_full_backup, allowed_keys=set())
    registry.register("backup.cancel_latest_running", cancel_running_backup, allowed_keys=set())
    registry.register(
        "camera.start_recording",
        start_camera_recording,
        allowed_keys={"camera_name"},
        required_keys={"camera_name"},
    )
    registry.register(
        "camera.stop_recording",
        stop_camera_recording,
        allowed_keys={"camera_name"},
        required_keys={"camera_name"},
    )
    registry.register("setup.permissions_setup", run_permissions_setup, allowed_keys={"username"})
    registry.register("setup.restart_services", lambda _: setup_adapter.restart_services(), allowed_keys=set())
    registry.register("security.fix_firewall", lambda _: security_adapter.fix_firewall(), allowed_keys=set())
    registry.register("security.fix_password_auth", lambda _: security_adapter.fix_password_auth(), allowed_keys=set())
    registry.register("security.fix_filesystem_readonly", lambda _: security_adapter.fix_filesystem_readonly(), allowed_keys=set())
    registry.register("security.start_outdated_packages_fix", lambda _: security_adapter.start_outdated_packages_fix(), allowed_keys=set())
    registry.register(
        "users.revoke_sessions",
        revoke_sessions,
        allowed_keys={"username"},
        required_keys={"username"},
    )
    registry.register(
        "users.disable_2fa",
        disable_2fa,
        allowed_keys={"username"},
        required_keys={"username"},
    )
    registry.register("wireguard.restart_service", lambda _: wireguard_adapter.restart_service(), allowed_keys=set())
    registry.register("ai.start_ollama", lambda _: ai_runtime_adapter.start_ollama(), allowed_keys=set())
    registry.register("ai.stop_ollama", lambda _: ai_runtime_adapter.stop_ollama(), allowed_keys=set())
    registry.register("cloud.start_telegram_bot", lambda _: cloud_adapter.start_telegram_bot(), allowed_keys=set())
    registry.register("cloud.stop_telegram_bot", lambda _: cloud_adapter.stop_telegram_bot(), allowed_keys=set())
    registry.register("network_toolkit.fix_gateway_mode", lambda _: network_toolkit_adapter.fix_gateway_mode(), allowed_keys=set())
