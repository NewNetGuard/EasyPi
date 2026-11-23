from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.backup import BackupJob
from app.schemas.action_preview import ActionPreviewRequest, ActionPreviewResponse
from app.services.rollback_service import RollbackService


class ActionPreviewService:
    def __init__(self, *, rollback_service: RollbackService | None = None) -> None:
        self.rollback_service = rollback_service or RollbackService()

    def build_preview(self, payload: ActionPreviewRequest, db: Session) -> ActionPreviewResponse:
        if payload.action_id == "backup.restore":
            return self._preview_backup_restore(int(payload.target_id), db)
        if payload.action_id == "backup.delete":
            return self._preview_backup_delete(int(payload.target_id), db)
        if payload.action_id == "backup.cancel":
            return self._preview_backup_cancel(int(payload.target_id), db)
        if payload.action_id == "rollback.restore":
            return self._preview_rollback_restore(payload.target_id)
        if payload.action_id == "rollback.delete":
            return self._preview_rollback_delete(payload.target_id)
        if payload.action_id == "security.fix_firewall":
            return self._preview_security_fix_firewall()
        if payload.action_id == "security.fix_ssh_root_login":
            return self._preview_security_fix_ssh_root_login()
        if payload.action_id == "security.fix_password_auth":
            return self._preview_security_fix_password_auth()
        if payload.action_id == "security.fix_filesystem_readonly":
            return self._preview_security_fix_filesystem_readonly()
        if payload.action_id == "security.fix_outdated_packages":
            return self._preview_security_fix_outdated_packages()
        if payload.action_id == "dns.deploy":
            return self._preview_dns_deploy(payload.target_id)
        if payload.action_id == "wireguard.install":
            return self._preview_wireguard_install()
        if payload.action_id == "wireguard.reset":
            return self._preview_wireguard_reset()
        if payload.action_id == "wireguard.uninstall":
            return self._preview_wireguard_uninstall()
        if payload.action_id == "remote-access.install":
            return self._preview_remote_access_install()
        if payload.action_id == "remote-access.uninstall":
            return self._preview_remote_access_uninstall()
        raise ValueError(f"Unsupported action preview: {payload.action_id}")

    def _preview_backup_restore(self, backup_id: int, db: Session) -> ActionPreviewResponse:
        backup = self._get_backup(backup_id, db)
        return ActionPreviewResponse(
            action_id="backup.restore",
            title=f"Restore backup: {backup.name}",
            target_label=backup.name,
            summary="This will overwrite the current EasyPi state with the selected backup archive.",
            risk_level="high",
            destructive=True,
            affects=[
                "Current EasyPi configuration files",
                "Stored application state and service data from the backup scope",
                "Changes made after this backup was created",
            ],
            service_impact=[
                "EasyPi backend services may restart to load restored configuration",
                "Network-facing features may briefly become unavailable while restored state is applied",
            ],
            rollback_available=False,
            rollback_hint="Create a fresh safe snapshot in Rollback Center before restoring if you may need a way back.",
            recommended_checks=[
                "Confirm the backup date and name match the point you want to return to.",
                "Download the backup archive if you want an offline copy before restoring.",
                "Create a safe snapshot first if current settings are worth preserving.",
            ],
        )

    def _preview_backup_delete(self, backup_id: int, db: Session) -> ActionPreviewResponse:
        backup = self._get_backup(backup_id, db)
        return ActionPreviewResponse(
            action_id="backup.delete",
            title=f"Delete backup: {backup.name}",
            target_label=backup.name,
            summary="This removes the saved backup archive and its record from EasyPi.",
            risk_level="medium",
            destructive=True,
            affects=[
                "The backup record in System Backup",
                "The backup archive stored on disk",
            ],
            service_impact=[],
            rollback_available=False,
            rollback_hint="Download the archive first if you may need it later.",
            recommended_checks=[
                "Verify you do not need this backup for recovery.",
                "Download the archive before deleting if you want to keep a copy.",
            ],
        )

    def _preview_backup_cancel(self, backup_id: int, db: Session) -> ActionPreviewResponse:
        backup = self._get_backup(backup_id, db)
        return ActionPreviewResponse(
            action_id="backup.cancel",
            title=f"Cancel backup: {backup.name}",
            target_label=backup.name,
            summary="This stops the running backup job before it completes.",
            risk_level="low",
            destructive=False,
            affects=[
                "The current running backup job",
            ],
            service_impact=[],
            rollback_available=True,
            rollback_hint="You can start a new backup again later from System Backup.",
            recommended_checks=[
                "Cancel only if you no longer need the current backup run.",
            ],
        )

    def _preview_rollback_restore(self, snapshot_id: str) -> ActionPreviewResponse:
        snapshot = self.rollback_service.get_snapshot(snapshot_id)
        return ActionPreviewResponse(
            action_id="rollback.restore",
            title=f"Restore safe snapshot: {snapshot.name}",
            target_label=snapshot.name,
            summary="This puts EasyPi back to the saved configuration state from the selected snapshot.",
            risk_level="high",
            destructive=True,
            affects=[
                "Current EasyPi configuration files",
                "Changes made after the snapshot was created",
                "DNS, VPN, Guard Security, Remote Access, and related settings that depend on config state",
            ],
            service_impact=[
                "EasyPi backend services may restart after restored config is applied",
                "Network-facing services can briefly reload while settings are rolled back",
            ],
            rollback_available=False,
            rollback_hint="Create a new safe snapshot first if you may want to return to the current state later.",
            recommended_checks=[
                "Confirm this snapshot was taken before the change you want to undo.",
                "Download the snapshot archive if you want an external copy before restoring.",
                "Make sure nobody else is actively editing settings while rollback runs.",
            ],
        )

    def _preview_rollback_delete(self, snapshot_id: str) -> ActionPreviewResponse:
        snapshot = self.rollback_service.get_snapshot(snapshot_id)
        return ActionPreviewResponse(
            action_id="rollback.delete",
            title=f"Delete safe snapshot: {snapshot.name}",
            target_label=snapshot.name,
            summary="This permanently removes the selected rollback point and its archive.",
            risk_level="medium",
            destructive=True,
            affects=[
                "The rollback snapshot record",
                "The snapshot archive stored on disk",
                "Your ability to return to this exact saved config state",
            ],
            service_impact=[],
            rollback_available=False,
            rollback_hint="Download the snapshot archive before deleting if you may need it later.",
            recommended_checks=[
                "Verify a newer rollback point exists if this is your only snapshot.",
                "Download the archive first if you want to keep the restore point outside EasyPi.",
            ],
        )

    def _preview_security_fix_firewall(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="security.fix_firewall",
            title="Enable firewall hardening",
            target_label="System firewall",
            summary="This enables UFW and adds baseline allow rules so EasyPi remains reachable while the firewall is turned on.",
            risk_level="medium",
            destructive=False,
            affects=[
                "Firewall policy on the EasyPi host",
                "Inbound access to SSH and web ports",
            ],
            service_impact=[
                "Network access rules update immediately",
                "Incorrect custom rules can still require follow-up review",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you may need to restore the current network policy.",
            recommended_checks=[
                "Confirm you know which SSH port the server is using.",
                "Make sure web access should stay open on ports 80 and 443.",
            ],
        )

    def _preview_security_fix_ssh_root_login(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="security.fix_ssh_root_login",
            title="Disable SSH root login",
            target_label="SSH configuration",
            summary="This updates sshd_config to block direct root SSH access and restarts SSH.",
            risk_level="medium",
            destructive=False,
            affects=[
                "SSH server configuration",
                "Direct root login over SSH",
            ],
            service_impact=[
                "SSH service restarts after the config change",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you want an immediate path back to the current SSH config.",
            recommended_checks=[
                "Verify you still have a non-root admin account that can use sudo.",
                "Keep the current SSH session open while testing the new login path.",
            ],
        )

    def _preview_security_fix_password_auth(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="security.fix_password_auth",
            title="Disable SSH password authentication",
            target_label="SSH authentication",
            summary="This switches SSH to key-based access only and restarts the SSH service.",
            risk_level="high",
            destructive=False,
            affects=[
                "SSH authentication policy",
                "All users who currently log in with passwords",
            ],
            service_impact=[
                "SSH service restarts after the config change",
                "Users without working SSH keys can lose remote access",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you may need to restore password-based SSH quickly.",
            recommended_checks=[
                "Confirm at least one admin account can log in with a tested SSH key.",
                "Keep an existing SSH session open until you verify the new policy works.",
            ],
        )

    def _preview_security_fix_filesystem_readonly(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="security.fix_filesystem_readonly",
            title="Schedule filesystem check and reboot",
            target_label="Filesystem recovery",
            summary="This schedules a filesystem check and reboots the device so the system can try to recover from read-only disk state.",
            risk_level="high",
            destructive=False,
            affects=[
                "Current EasyPi runtime session",
                "Filesystem check state on next boot",
                "All services while the device reboots",
            ],
            service_impact=[
                "The device will reboot shortly after scheduling the fix",
                "EasyPi services will be unavailable until boot finishes",
            ],
            rollback_available=False,
            rollback_hint="No automatic rollback applies during fsck. Make sure you have backups of important data.",
            recommended_checks=[
                "Confirm the device can reboot now without interrupting other users.",
                "Make sure power is stable before starting filesystem repair.",
            ],
        )

    def _preview_security_fix_outdated_packages(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="security.fix_outdated_packages",
            title="Update outdated packages",
            target_label="System packages",
            summary="This starts a background package upgrade job to apply pending system updates.",
            risk_level="medium",
            destructive=False,
            affects=[
                "OS packages managed by apt",
                "Security patch level and package versions",
            ],
            service_impact=[
                "Some services may restart during or after package upgrades",
                "A reboot may still be needed for certain updates",
            ],
            rollback_available=False,
            rollback_hint="Create a fresh backup or safe snapshot first if you want a clean recovery point before patching.",
            recommended_checks=[
                "Make sure the filesystem is writable before starting updates.",
                "Avoid interrupting power or forcing reboot while updates are running.",
            ],
        )

    def _preview_dns_deploy(self, target_id: str) -> ActionPreviewResponse:
        target = target_id or "remote VPS"
        return ActionPreviewResponse(
            action_id="dns.deploy",
            title=f"Deploy Personal DNS to {target}",
            target_label=target,
            summary="This connects to your VPS over SSH, installs dependencies, deploys NetProtection, and opens the required DNS and admin ports.",
            risk_level="high",
            destructive=False,
            affects=[
                "The remote VPS package set and Docker runtime",
                "Remote firewall rules and open ports",
                "Remote NetProtection / Personal DNS services",
            ],
            service_impact=[
                "The VPS will change network-facing services during deployment",
                "Future cleanup or manual rollback on the VPS may be needed if deployment is interrupted",
            ],
            rollback_available=False,
            rollback_hint="There is no automatic remote rollback yet. Keep SSH access available so you can inspect or clean up the VPS afterward.",
            recommended_checks=[
                "Confirm SSH credentials and sudo/root access are correct.",
                "Make sure the VPS can open the required DNS and admin ports.",
                "Keep a note of the current VPS state before running the deploy.",
            ],
        )

    def _preview_wireguard_install(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="wireguard.install",
            title="Install WireGuard server",
            target_label="WireGuard runtime",
            summary="This installs WireGuard packages, generates server keys, enables IP forwarding, and configures the VPN service.",
            risk_level="high",
            destructive=False,
            affects=[
                "Installed system packages",
                "Firewall / NAT rules",
                "WireGuard config and key material",
            ],
            service_impact=[
                "The WireGuard service will be enabled on the system",
                "Network routing and port exposure change once setup finishes",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot before installation if you want a fast path back to the current network state.",
            recommended_checks=[
                "Confirm your public endpoint or IP is correct.",
                "Make sure UDP port 51820 can be reached through your router/firewall.",
            ],
        )

    def _preview_wireguard_reset(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="wireguard.reset",
            title="Reset WireGuard configuration",
            target_label="WireGuard runtime",
            summary="This removes the current WireGuard configuration and client definitions but keeps the product installed.",
            risk_level="high",
            destructive=True,
            affects=[
                "Current WireGuard config",
                "All existing WireGuard peers and generated client data",
            ],
            service_impact=[
                "Connected VPN clients will stop working until the server is reconfigured",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you may need to restore the current VPN configuration.",
            recommended_checks=[
                "Download any client configs you still need before resetting.",
                "Confirm you really want to rebuild WireGuard from scratch.",
            ],
        )

    def _preview_wireguard_uninstall(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="wireguard.uninstall",
            title="Uninstall WireGuard",
            target_label="WireGuard runtime",
            summary="This removes the WireGuard service and deletes its configuration and client setup on the server.",
            risk_level="high",
            destructive=True,
            affects=[
                "Installed WireGuard runtime",
                "Server VPN configuration and client data",
            ],
            service_impact=[
                "All WireGuard VPN access will stop until the server is installed again",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you may want to restore the current VPN setup later.",
            recommended_checks=[
                "Download any client configs you want to keep.",
                "Confirm no one still depends on this VPN before uninstalling.",
            ],
        )

    def _preview_remote_access_install(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="remote-access.install",
            title="Install Tailscale",
            target_label="Remote Access runtime",
            summary="This installs the Tailscale runtime on EasyPi so remote access can be configured later.",
            risk_level="medium",
            destructive=False,
            affects=[
                "Installed system packages",
                "Remote Access runtime on the EasyPi host",
            ],
            service_impact=[
                "The Tailscale service will be installed and may start during setup",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you want a clean path back before adding a new remote access runtime.",
            recommended_checks=[
                "Make sure the server has internet access for installation.",
                "Keep your Tailscale auth key ready if you plan to enable access right after install.",
            ],
        )

    def _preview_remote_access_uninstall(self) -> ActionPreviewResponse:
        return ActionPreviewResponse(
            action_id="remote-access.uninstall",
            title="Uninstall Tailscale",
            target_label="Remote Access runtime",
            summary="This removes Tailscale and clears remote access runtime data from the server.",
            risk_level="high",
            destructive=True,
            affects=[
                "Installed Tailscale runtime",
                "Remote access availability for this EasyPi instance",
            ],
            service_impact=[
                "Remote access over Tailscale will stop until the runtime is installed again",
            ],
            rollback_available=True,
            rollback_hint="Create a safe snapshot first if you may want to restore the current remote access setup.",
            recommended_checks=[
                "Confirm you no longer need current Tailscale connectivity.",
                "Make sure you still have another management path to EasyPi after uninstalling.",
            ],
        )

    def _get_backup(self, backup_id: int, db: Session) -> BackupJob:
        backup = db.query(BackupJob).filter(BackupJob.id == backup_id).first()
        if not backup:
            raise ValueError("Backup not found")
        return backup


action_preview_service = ActionPreviewService()
