"""Runtime operations for NetProtection."""

import sys

from app.services.netprotection_components.runtime_context import (
    Any,
    AppleMusicFlowPolicy,
    CandidateFlow,
    DailymotionFlowPolicy,
    DeezerFlowPolicy,
    Dict,
    DisneyFlowPolicy,
    EASYPI_ROOT,
    EpicGamesFlowPolicy,
    FLOW_LOGGER_AVAILABLE,
    FacebookFlowPolicy,
    FlowLogStorage,
    FlowLogger,
    GooglePlayFlowPolicy,
    HboFlowPolicy,
    IPAnonymizer,
    InstagramFlowPolicy,
    List,
    MinecraftFlowPolicy,
    NETPROTECTION_AVAILABLE,
    NetProtectionServer,
    Optional,
    Path,
    PinterestFlowPolicy,
    PlayStationFlowPolicy,
    PrimeVideoFlowPolicy,
    RobloxFlowPolicy,
    SignalFlowPolicy,
    SnapchatFlowPolicy,
    SoundCloudFlowPolicy,
    SpotifyFlowPolicy,
    SteamFlowPolicy,
    TikTokFlowPolicy,
    TinderFlowPolicy,
    TumblrFlowPolicy,
    TwitchFlowPolicy,
    VimeoFlowPolicy,
    WeChatFlowPolicy,
    XboxFlowPolicy,
    _cert_has_san,
    _short_err,
    asyncio,
    json,
    load_np_config,
    logger,
    os,
    time,
    validate_flowgraph_candidate_event,
)


def _legacy_runtime():
    """Return the stable facade so existing runtime overrides stay effective."""
    return sys.modules["app.services.netprotection_service"]


class RuntimeMixin:
    """Internal behavior mixed into the stable service facade."""

    async def initialize(self) -> None:
        """Initialize NetProtection components."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load query log config from file if exists
        config_file = self.data_dir / "query_log_config.json"
        if config_file.exists():
            try:
                self._query_log_config.update(json.loads(config_file.read_text()))
            except Exception as e:
                logger.warning(f"Failed to load query log config: {e}")

        # Initialize Flow Logger (SQLite-based query logging) with security features
        if FLOW_LOGGER_AVAILABLE:
            try:
                from easypi_netprotection.chronicle.flow_log import SaltManager

                # Create salt manager for stable IP hashing
                salt_manager = SaltManager(
                    salt_file=self.data_dir / ".salt",
                    rotation_days=30,
                    double_window=True,
                )

                anonymizer = IPAnonymizer(salt_manager=salt_manager)

                storage = FlowLogStorage(
                    self.flow_log_path,
                    max_size_mb=500,
                    fail_open=True,  # Don't break DNS on logging failures
                )
                await storage.initialize()

                self._flow_logger = FlowLogger(
                    storage,
                    anonymizer,
                    enabled=self._query_log_config.get("enabled", True),
                    retention_days=min(
                        self._query_log_config.get("retention_days", 7), 90
                    ),
                    # Privacy controls
                    store_evidence=self._query_log_config.get("store_evidence", True),
                    evidence_max_length=500,
                    store_response_ips=self._query_log_config.get(
                        "store_response_ips", True
                    ),
                    response_ips_max_count=10,
                    # DoS protection
                    buffer_max_size=10000,
                    drop_on_overflow=True,
                    # Fail-open
                    fail_open=True,
                    max_consecutive_failures=10,
                )
                await self._flow_logger.start()
                logger.info("FlowLogger initialized with security features")
            except Exception as e:
                logger.error(f"Failed to initialize FlowLogger: {e}")
                self._flow_logger = None

        # Initialize threat intelligence database
        if NETPROTECTION_AVAILABLE:
            try:
                from easypi_netprotection.threat_intel import (
                    ThreatDatabase,
                    DomainExporter,
                )

                self._threat_db = ThreatDatabase(str(self.db_path))
                await self._threat_db.initialize()

                self._domain_exporter = DomainExporter(
                    str(self.db_path), export_dir=str(self.data_dir / "export")
                )

                logger.info("NetProtection threat intel initialized")
            except Exception as e:
                logger.error(f"Failed to initialize threat intel: {e}")

        # Start DNS server in background (unless standalone mode)
        standalone = os.environ.get("NETPROTECTION_STANDALONE", "").lower() in (
            "1",
            "true",
            "yes",
        )
        if standalone:
            logger.info(
                "Standalone mode: DNS server managed by systemd easypi-netprotection.service"
            )
        else:
            await self._start_dns_server()

        # Auto-sync clients to profiles on startup
        try:
            await self._sync_blocklist()
            logger.info("Auto-synced clients to NetProtection profiles on startup")
        except Exception as e:
            logger.warning(f"Failed to auto-sync clients on startup: {e}")

        await self._setup_prism_shadow()

        if self._prism_flow_policy_task is None or self._prism_flow_policy_task.done():
            self._prism_flow_policy_task = asyncio.create_task(
                self._prism_flow_policy_loop()
            )
            logger.info("Prism candidate flow policy started")

        # Start fail-closed queue worker (consumes requests from DNS engine).
        if (
            self._fail_closed_worker_task is None
            or self._fail_closed_worker_task.done()
        ):
            self._fail_closed_worker_task = asyncio.create_task(
                self._fail_closed_worker_loop()
            )
            logger.info("Fail-closed worker started")

        # Start fail-safe monitor (restarts the resolver if it stops responding).
        if self._failsafe_monitor_task is None or self._failsafe_monitor_task.done():
            self._failsafe_monitor_task = asyncio.create_task(
                self._failsafe_monitor_loop()
            )
            logger.info("Fail-safe monitor started")

    async def _start_dns_server(self) -> None:
        """Start the DNS server in background."""
        if not NETPROTECTION_AVAILABLE:
            logger.warning("NetProtection DNS server not available (module not loaded)")
            return

        try:
            # Check if port 5454 is available (dedicated NetProtection port)
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(("0.0.0.0", 5454))
                sock.close()
            except OSError as e:
                logger.warning(
                    f"Port 5454 not available: {e}. DNS server not started (may be running standalone)."
                )
                return

            # Load configuration
            config = load_np_config()

            # Create and start server
            self._server = NetProtectionServer(config=config)

            # Start in background task
            asyncio.create_task(self._run_dns_server())

            logger.info("NetProtection DNS server starting on port 5454...")
        except Exception as e:
            logger.error(f"Failed to start DNS server: {e}")

    async def _setup_prism_shadow(self) -> None:
        """Restore observation-only Prism counters after service startup."""
        import subprocess

        runner_path = EASYPI_ROOT / "scripts" / "runner"
        if not runner_path.exists():
            logger.warning(f"Prism shadow runner not found: {runner_path}")
            return

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/setup_prism_shadow.sh",
                    "enable",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info(f"Prism shadow restored: {result.stdout.strip()}")
                return
            err_msg = _short_err(result.stderr or result.stdout) or "unknown error"
            logger.warning(f"Prism shadow setup failed: {err_msg}")
        except Exception as exc:
            logger.warning(f"Failed to restore Prism shadow rules: {exc}")

    def _build_prism_flow_policies(self, state_path: Path) -> dict[str, Any]:
        """Build the ordered policy registry used for validation and authorization."""
        devices_path = self.data_dir / "devices.json"

        def resolve_mac(mac: str) -> str:
            return self._resolve_ipv4_from_mac(mac)

        policy_types = (
            ("apple_music", AppleMusicFlowPolicy),
            ("dailymotion", DailymotionFlowPolicy),
            ("deezer", DeezerFlowPolicy),
            ("disney", DisneyFlowPolicy),
            ("epicgames", EpicGamesFlowPolicy),
            ("google_play", GooglePlayFlowPolicy),
            ("hbo", HboFlowPolicy),
            ("instagram", InstagramFlowPolicy),
            ("minecraft", MinecraftFlowPolicy),
            ("pinterest", PinterestFlowPolicy),
            ("playstation", PlayStationFlowPolicy),
            ("amazon_video", PrimeVideoFlowPolicy),
            ("roblox", RobloxFlowPolicy),
            ("snapchat", SnapchatFlowPolicy),
            ("signal", SignalFlowPolicy),
            ("soundcloud", SoundCloudFlowPolicy),
            ("spotify", SpotifyFlowPolicy),
            ("steam", SteamFlowPolicy),
            ("tinder", TinderFlowPolicy),
            ("twitch", TwitchFlowPolicy),
            ("tumblr", TumblrFlowPolicy),
            ("vimeo", VimeoFlowPolicy),
            ("wechat", WeChatFlowPolicy),
            ("xbox", XboxFlowPolicy),
        )
        policies = {
            name: policy_type(devices_path, resolve_mac)
            for name, policy_type in policy_types
        }
        policies["facebook"] = FacebookFlowPolicy(devices_path)
        policies["tiktok"] = TikTokFlowPolicy(
            devices_path,
            Path("/var/lib/easypi/prism/tiktok-endpoints.json"),
            [Path(f"{state_path}.1"), state_path],
            resolve_mac,
        )
        validation_order = (
            "apple_music",
            "dailymotion",
            "deezer",
            "disney",
            "epicgames",
            "facebook",
            "google_play",
            "hbo",
            "instagram",
            "minecraft",
            "pinterest",
            "playstation",
            "amazon_video",
            "roblox",
            "snapchat",
            "signal",
            "soundcloud",
            "spotify",
            "steam",
            "tinder",
            "twitch",
            "tumblr",
            "vimeo",
            "wechat",
            "xbox",
            "tiktok",
        )
        return {name: policies[name] for name in validation_order}

    @staticmethod
    def _validate_prism_candidate(
        value: object, *, now: float, policies: dict[str, Any]
    ) -> CandidateFlow | None:
        candidate = validate_flowgraph_candidate_event(value, now=now)
        if candidate is not None:
            return candidate
        for policy in policies.values():
            candidate = policy.validate_candidate_event(value, now=now)
            if candidate is not None:
                return candidate
        return None

    async def _prism_flow_policy_loop(self) -> None:
        """Apply short exact-flow blocks for fresh, validated PRISM candidates."""
        state_path = Path("/var/lib/easypi/prism/flowgraph.jsonl")
        policies = RuntimeMixin._build_prism_flow_policies(self, state_path)

        follower = _legacy_runtime().CandidateLogFollower(
            state_path,
            validator=lambda value, *, now: RuntimeMixin._validate_prism_candidate(
                value, now=now, policies=policies
            ),
        )
        enforcer: asyncio.subprocess.Process | None = None
        enforcer_started_at: float | None = None
        next_enforcer_start = 0.0
        enforcer_retry_seconds = _legacy_runtime().PRISM_FLOW_ENFORCER_RETRY_SECONDS
        try:
            while True:
                try:
                    if enforcer is not None and enforcer.returncode is not None:
                        now = time.monotonic()
                        logger.warning(
                            "Prism flow enforcer exited with code %s",
                            enforcer.returncode,
                        )
                        await enforcer.wait()
                        enforcer = None
                        if (
                            enforcer_started_at is not None
                            and now - enforcer_started_at
                            >= _legacy_runtime().PRISM_FLOW_ENFORCER_STABLE_SECONDS
                        ):
                            enforcer_retry_seconds = (
                                _legacy_runtime().PRISM_FLOW_ENFORCER_RETRY_SECONDS
                            )
                        enforcer_started_at = None
                        next_enforcer_start = now + enforcer_retry_seconds
                        enforcer_retry_seconds = min(
                            _legacy_runtime().PRISM_FLOW_ENFORCER_MAX_RETRY_SECONDS,
                            enforcer_retry_seconds * 2,
                        )
                    now = time.monotonic()
                    if enforcer is None and now >= next_enforcer_start:
                        try:
                            enforcer = await self._start_prism_flow_enforcer()
                            enforcer_started_at = time.monotonic()
                        except Exception as exc:
                            next_enforcer_start = now + enforcer_retry_seconds
                            enforcer_retry_seconds = min(
                                _legacy_runtime().PRISM_FLOW_ENFORCER_MAX_RETRY_SECONDS,
                                enforcer_retry_seconds * 2,
                            )
                            logger.warning(
                                "Prism flow enforcer start failed: %s",
                                _short_err(str(exc)),
                            )

                    candidates = follower.poll()
                    from app.services.mobile_prism_broker import mobile_prism_broker

                    for confirmation in mobile_prism_broker.pop_confirmed():
                        command = confirmation.command
                        confirmed_candidate = CandidateFlow(
                            timestamp=confirmation.confirmed_at,
                            flow_id=command.id,
                            client_ip=command.client_ip,
                            client_port=command.client_port,
                            server_ip=command.server_ip,
                            server_port=command.server_port,
                            confidence=command.confidence,
                            retry_guard=False,
                            protocol=command.protocol,
                            policy=command.policy,
                        )
                        logger.info(
                            "Prism mobile confirmed flow owner=%s client=%s server=%s:%s",
                            confirmation.package_name,
                            command.client_ip,
                            command.server_ip,
                            command.server_port,
                        )
                        await self._apply_prism_candidate(
                            confirmed_candidate,
                            handoff_on_failure=False,
                        )
                    for candidate in candidates:
                        policy = policies.get(candidate.policy)
                        if policy is not None and not policy.is_blocked_client(
                            candidate.client_ip
                        ):
                            continue
                        if enforcer is not None:
                            try:
                                await self._stream_prism_candidate(enforcer, candidate)
                                continue
                            except (
                                BrokenPipeError,
                                ConnectionError,
                                RuntimeError,
                                asyncio.TimeoutError,
                            ) as exc:
                                logger.warning(
                                    "Prism flow enforcer write failed: %s",
                                    _short_err(str(exc)),
                                )
                                await self._stop_prism_flow_enforcer(enforcer)
                                enforcer = None
                                enforcer_started_at = None
                                next_enforcer_start = (
                                    time.monotonic() + enforcer_retry_seconds
                                )
                                enforcer_retry_seconds = min(
                                    _legacy_runtime().PRISM_FLOW_ENFORCER_MAX_RETRY_SECONDS,
                                    enforcer_retry_seconds * 2,
                                )
                        await self._apply_prism_candidate(candidate)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        f"Prism candidate policy poll failed: {_short_err(str(exc))}"
                    )
                await asyncio.sleep(_legacy_runtime().PRISM_FLOW_POLICY_POLL_SECONDS)
        finally:
            if enforcer is not None:
                await self._stop_prism_flow_enforcer(enforcer)

    async def _start_prism_flow_enforcer(self) -> asyncio.subprocess.Process:
        runner_path = EASYPI_ROOT / "scripts" / "runner"
        if not runner_path.exists():
            raise FileNotFoundError("Prism runner not found")
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "-n",
            str(runner_path),
            "settings/setup_prism_shadow.sh",
            "flow-block-stream",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(0)
        if process.returncode is not None:
            raise RuntimeError(
                f"Prism flow enforcer exited during startup ({process.returncode})"
            )
        logger.info("Prism low-latency flow enforcer started")
        return process

    async def _stream_prism_candidate(
        self,
        process: asyncio.subprocess.Process,
        candidate: CandidateFlow,
    ) -> None:
        if (
            process.returncode is not None
            or process.stdin is None
            or process.stdout is None
        ):
            raise RuntimeError("Prism flow enforcer is not available")
        process.stdin.write(candidate.enforcement_request())
        await process.stdin.drain()
        result = await asyncio.wait_for(process.stdout.readline(), timeout=0.25)
        if result != b"ok\n":
            raise RuntimeError("Prism flow enforcer rejected the candidate")
        enforcement_lag_ms = max(0.0, (time.time() - candidate.timestamp) * 1000.0)
        logger.info(
            "Prism submitted candidate flow policy=%s client=%s server=%s:%s "
            "retry_guard=%s enforcement_lag_ms=%.1f",
            candidate.policy,
            candidate.client_ip,
            candidate.server_ip,
            candidate.server_port,
            candidate.retry_guard,
            enforcement_lag_ms,
        )

    async def _stop_prism_flow_enforcer(
        self,
        process: asyncio.subprocess.Process,
    ) -> None:
        if process.stdin is not None:
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
            return
        except asyncio.TimeoutError:
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()

    async def _apply_prism_candidate(
        self,
        candidate: CandidateFlow,
        *,
        handoff_on_failure: bool = True,
    ) -> None:
        runner_path = EASYPI_ROOT / "scripts" / "runner"
        if not runner_path.exists():
            if handoff_on_failure:
                self._handoff_prism_candidate(candidate)
            return
        action = "flow-block" if candidate.retry_guard else "flow-block-exact"
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "-n",
            str(runner_path),
            "settings/setup_prism_shadow.sh",
            action,
            candidate.client_ip,
            str(candidate.client_port),
            candidate.server_ip,
            candidate.protocol,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            logger.warning("Prism candidate flow block timed out")
            if handoff_on_failure:
                self._handoff_prism_candidate(candidate)
            return
        if process.returncode == 0:
            logger.info(
                "Prism blocked candidate flow policy=%s client=%s server=%s:%s "
                "retry_guard=%s",
                candidate.policy,
                candidate.client_ip,
                candidate.server_ip,
                candidate.server_port,
                candidate.retry_guard,
            )
            return
        detail = (stderr or stdout).decode(errors="replace")
        logger.warning(f"Prism candidate flow block failed: {_short_err(detail)}")
        if handoff_on_failure:
            self._handoff_prism_candidate(candidate)

    @staticmethod
    def _handoff_prism_candidate(candidate: CandidateFlow) -> None:
        # If the gateway could not enforce an exact flow, hand the already
        # validated tuple to a linked phone currently using this client IP.
        # Import lazily to keep NetProtection startup independent from the
        # mobile API and its database models.
        from app.services.mobile_prism_broker import mobile_prism_broker

        queued = mobile_prism_broker.enqueue_candidate(candidate)
        if queued:
            logger.info(
                "Prism handed failed gateway flow to %s linked mobile device(s) "
                "client=%s server=%s:%s",
                queued,
                candidate.client_ip,
                candidate.server_ip,
                candidate.server_port,
            )

    async def _run_dns_server(self) -> None:
        """Run the DNS server (background task)."""
        try:
            await self._server.start()
            logger.info("NetProtection DNS server is running")
            await self._server.wait_for_shutdown()
        except Exception as e:
            logger.error(f"DNS server error: {e}")
        finally:
            if self._server:
                await self._server.stop()

    async def stop(self) -> None:
        """Stop the DNS server."""
        if self._prism_flow_policy_task:
            self._prism_flow_policy_task.cancel()
            try:
                await self._prism_flow_policy_task
            except asyncio.CancelledError:
                pass
            self._prism_flow_policy_task = None
        if self._fail_closed_worker_task:
            self._fail_closed_worker_task.cancel()
            try:
                await self._fail_closed_worker_task
            except asyncio.CancelledError:
                pass
            self._fail_closed_worker_task = None
        if self._failsafe_monitor_task:
            self._failsafe_monitor_task.cancel()
            try:
                await self._failsafe_monitor_task
            except asyncio.CancelledError:
                pass
            self._failsafe_monitor_task = None
        if self._server:
            self._server.request_shutdown()
            await asyncio.sleep(1)  # Give it time to stop
            logger.info("NetProtection DNS server stopped")
        if self._flow_logger:
            await self._flow_logger.stop()
            self._flow_logger = None
        if self._threat_db:
            await self._threat_db.close()
            self._threat_db = None

    async def get_status(self) -> Dict[str, Any]:
        """Get NetProtection status including systemd service state."""
        is_running = self._server is not None
        service_status = "unknown"
        systemd_checked = False

        # Check actual DNS server state if available
        if is_running and hasattr(self._server, "state"):
            from easypi_netprotection.server import ServerState

            is_running = self._server.state == ServerState.RUNNING

        # Check systemd service status
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl",
                "is-active",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            service_status = stdout.decode().strip()
            systemd_checked = True
            if service_status in ("active", "activating"):
                is_running = True
        except Exception:
            pass

        # Fallback: check if port 53 is in use
        if not is_running and not systemd_checked:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(("0.0.0.0", 53))
                sock.close()
                is_running = False  # Port is free = not running
            except OSError:
                is_running = True  # Port in use = running

        # Check transparent DNS status
        transparent_dns = False
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "iptables",
                "-t",
                "nat",
                "-S",
                "PREROUTING",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                rules = stdout.decode(errors="ignore")
                # Match both REDIRECT and DNAT rules for port 53
                if ("--dport 53" in rules) and (
                    "-j REDIRECT" in rules or "-j DNAT" in rules
                ):
                    transparent_dns = True
            else:
                raise RuntimeError(
                    stderr.decode(errors="ignore").strip() or "iptables failed"
                )
        except Exception:
            # Try getting from config if iptables check fails
            config = await self.get_config()
            transparent_dns = config.get("transparent_dns", False)

        return {
            "running": is_running,
            "service_status": service_status,
            "protection_enabled": is_running,
            "transparent_dns": transparent_dns,
            "version": "1.0.0",
            "dns_port": 53,
            "dns_addresses": ["0.0.0.0:53"],
            "upstream_dns": [
                "https://dns.quad9.net/dns-query",
                "tls://1.1.1.1:853",
            ],
            "bootstrap_dns": ["9.9.9.9", "1.1.1.1"],
            "available": NETPROTECTION_AVAILABLE,
        }

    async def get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        if self.config_path.exists():
            return json.loads(self.config_path.read_text())

        return {
            "protection_enabled": True,
            "safe_search": False,
            "parental_control": False,
            "cache_size": 10000,
            "cache_ttl": 300,
            "block_response": "0.0.0.0",
            "upstream_dns": [
                "https://dns.quad9.net/dns-query",
                "tls://1.1.1.1:853",
            ],
            "shield_profile": "balanced",
        }

    async def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update configuration."""
        current = await self.get_config()
        current.update(config)

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(current, indent=2))

        return current

    def _get_netprotection_toml_path(self) -> Path:
        env_path = os.environ.get("NETPROTECTION_CONFIG")
        if env_path:
            return Path(env_path)
        if os.path.exists("/opt/EasyPi/config/netprotection.toml"):
            return Path("/opt/EasyPi/config/netprotection.toml")
        return Path("config/netprotection.toml")

    async def get_encrypted_dns_settings(self) -> Dict[str, Any]:
        """Get Encrypted DNS (DoH/DoT) settings from NetProtection config."""
        if not NETPROTECTION_AVAILABLE:
            return {"success": False, "error": "NetProtection module not available"}

        from easypi_netprotection.config import NetProtectionSettings

        config_path = self._get_netprotection_toml_path()
        settings = NetProtectionSettings.from_toml(config_path)
        enc = settings.encrypted_dns

        def tls_paths_ready(cert_path: Path, key_path: Path) -> bool:
            try:
                return (
                    cert_path.exists()
                    and key_path.exists()
                    and os.access(cert_path, os.R_OK)
                    and os.access(key_path, os.R_OK)
                    and _cert_has_san(cert_path)
                )
            except Exception:
                return False

        cert_ready = tls_paths_ready(Path(enc.tls_cert_path), Path(enc.tls_key_path))
        if not cert_ready:
            cert_ready = tls_paths_ready(
                Path("/opt/EasyPi/certs/cert.pem"),
                Path("/opt/EasyPi/certs/key.pem"),
            )
        if not cert_ready:
            cert_ready = tls_paths_ready(
                Path("/etc/ssl/certs/easypi-selfsigned.crt"),
                Path("/etc/ssl/private/easypi-selfsigned.key"),
            )

        return {
            "success": True,
            "data": {
                "doh_enabled": enc.doh_enabled,
                "dot_enabled": enc.dot_enabled,
                "doh_address": enc.doh_address,
                "doh_port": enc.doh_port,
                "doh_path": enc.doh_path,
                "dot_address": enc.dot_address,
                "dot_port": enc.dot_port,
                "tls_ready": cert_ready,
            },
        }

    async def update_encrypted_dns_settings(
        self, updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update Encrypted DNS (DoH/DoT) settings and restart NetProtection."""
        if not NETPROTECTION_AVAILABLE:
            return {"success": False, "error": "NetProtection module not available"}

        from easypi_netprotection.config import NetProtectionSettings

        config_path = self._get_netprotection_toml_path()
        settings = NetProtectionSettings.from_toml(config_path)
        enc = settings.encrypted_dns

        for key, value in updates.items():
            if hasattr(enc, key):
                setattr(enc, key, value)

        settings.encrypted_dns = enc
        settings.to_toml(config_path)

        await self._reload_netprotection()
        return await self.get_encrypted_dns_settings()

    async def generate_tls_certs(self, force: bool = False) -> Dict[str, Any]:
        """Generate TLS certificates for encrypted DNS endpoints.

        When ``force`` is True, renew the server certificate even if it is still
        valid. The installation Root CA is preserved."""
        if not NETPROTECTION_AVAILABLE:
            return {"success": False, "error": "NetProtection module not available"}

        from easypi_netprotection.config import NetProtectionSettings

        config_path = self._get_netprotection_toml_path()
        settings = NetProtectionSettings.from_toml(config_path)
        cert_path = Path(settings.encrypted_dns.tls_cert_path)
        key_path = Path(settings.encrypted_dns.tls_key_path)

        def normalize_path(path: Path) -> Path:
            if path.is_absolute():
                return path.resolve()
            return (EASYPI_ROOT / path).resolve()

        cert_path = normalize_path(cert_path)
        key_path = normalize_path(key_path)
        cert_dir = cert_path.parent
        allowed_cert_dir = (EASYPI_ROOT / "certs").resolve()

        if (EASYPI_ROOT / "certs").is_symlink():
            return {
                "success": False,
                "error": "TLS certificate directory must not be a symlink",
                "details": f"Expected a real directory at {allowed_cert_dir}",
            }

        if (
            cert_dir != allowed_cert_dir
            or key_path.parent != allowed_cert_dir
            or cert_path.name != "cert.pem"
            or key_path.name != "key.pem"
        ):
            return {
                "success": False,
                "error": "TLS certificate paths are not allowed",
                "details": (
                    "Set tls_cert_path=/opt/EasyPi/certs/cert.pem and "
                    "tls_key_path=/opt/EasyPi/certs/key.pem in config."
                ),
            }

        if (
            not force
            and cert_path.exists()
            and key_path.exists()
            and _cert_has_san(cert_path)
        ):
            return {
                "success": True,
                "message": "TLS certificates already exist",
                "already_exists": True,
                "cert_path": str(cert_path),
                "key_path": str(key_path),
            }

        script_path = EASYPI_ROOT / "scripts" / "setup" / "generate_certs.sh"
        if not script_path.exists():
            return {"success": False, "error": "Certificate generator not found"}

        async def run_cmd(
            cmd: List[str], env: Optional[Dict[str, str]] = None
        ) -> tuple[int, str, str]:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await proc.communicate()
            return proc.returncode, stdout.decode().strip(), stderr.decode().strip()

        def can_write_cert_dir() -> bool:
            try:
                if cert_dir.exists():
                    return os.access(cert_dir, os.W_OK)
                return os.access(cert_dir.parent, os.W_OK)
            except Exception:
                return False

        env = os.environ.copy()
        env["EASYPI_CERT_DIR"] = str(cert_dir)
        ca_material_exists = (cert_dir / "ca.pem").exists() or (
            cert_dir / "ca-key.pem"
        ).exists()
        cert_action = "renew" if force and ca_material_exists else "ca-signed"

        last_error = ""

        # Prefer direct execution if current user can write the cert directory.
        if can_write_cert_dir():
            code, stdout, stderr = await run_cmd(
                ["/bin/bash", str(script_path), cert_action],
                env=env,
            )
            if code == 0 and cert_path.exists() and key_path.exists():
                await self._reload_netprotection()
                return {
                    "success": True,
                    "message": (
                        "TLS server certificate renewed; existing local CA preserved"
                        if cert_action == "renew"
                        else "TLS certificates generated"
                    ),
                    "cert_path": str(cert_path),
                    "key_path": str(key_path),
                }
            last_error = stderr or stdout

        # Fallback to runner (sudo) for protected paths.
        runner_path = EASYPI_ROOT / "scripts" / "runner"
        wrapper_path = EASYPI_ROOT / "scripts" / "settings" / "generate_tls_certs.sh"
        if runner_path.exists() and wrapper_path.exists():
            code, stdout, stderr = await run_cmd(
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/generate_tls_certs.sh",
                    str(cert_dir),
                    cert_action,
                ]
            )
            if code == 0 and cert_path.exists() and key_path.exists():
                await self._reload_netprotection()
                return {
                    "success": True,
                    "message": (
                        "TLS server certificate renewed; existing local CA preserved"
                        if cert_action == "renew"
                        else "TLS certificates generated"
                    ),
                    "cert_path": str(cert_path),
                    "key_path": str(key_path),
                }
            return {
                "success": False,
                "error": "Failed to generate TLS certificates",
                "details": stderr or stdout or last_error,
            }

        return {
            "success": False,
            "error": "TLS certificate generation requires elevated permissions",
            "details": last_error or "Runner script not found or not installed",
        }

    @staticmethod
    def _last_json_line(text: str) -> Optional[Dict[str, Any]]:
        """Parse the last JSON object a runner script printed on stdout."""
        import json as _json

        for line in reversed((text or "").splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return _json.loads(line)
                except Exception:
                    continue
        return None

    async def trusted_cert_status(self) -> Dict[str, Any]:
        """Report whether DoH/DoT serve a trusted (Let's Encrypt) cert or self-signed,
        plus the domain, expiry and DDNS-updater state."""
        runner = EASYPI_ROOT / "scripts" / "runner"
        wrapper = EASYPI_ROOT / "scripts" / "settings" / "letsencrypt_duckdns.sh"
        if not (runner.exists() and wrapper.exists()):
            return {"available": False}
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "-n",
                str(runner),
                "settings/letsencrypt_duckdns.sh",
                "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
        except Exception as exc:
            return {"available": False, "error": str(exc)}
        data = self._last_json_line(out.decode("utf-8", "replace"))
        if data is None:
            return {
                "available": False,
                "error": (err.decode()[-200:] if err else "no output"),
            }
        data["available"] = True
        return data

    async def setup_trusted_cert(
        self, fqdn: str, token: str, email: str = ""
    ) -> Dict[str, Any]:
        """Obtain a trusted Let's Encrypt certificate for a DuckDNS domain and wire it
        into the DoH/DoT listeners: copy the cert into the engine's readable dir,
        restart the engine, install the renewal hook and a DDNS updater. Via the
        secure runner (root). DNS-01 propagation can take up to ~a minute."""
        fqdn = (fqdn or "").strip().lower().rstrip(".")
        token = (token or "").strip()
        email = (email or "").strip()
        if not fqdn.endswith(".duckdns.org"):
            return {"success": False, "error": "Domain must be a *.duckdns.org name"}
        if not token:
            return {"success": False, "error": "DuckDNS token is required"}
        runner = EASYPI_ROOT / "scripts" / "runner"
        wrapper = EASYPI_ROOT / "scripts" / "settings" / "letsencrypt_duckdns.sh"
        if not (runner.exists() and wrapper.exists()):
            return {"success": False, "error": "Runner or wrapper script not installed"}
        args = [
            "sudo",
            "-n",
            str(runner),
            "settings/letsencrypt_duckdns.sh",
            "issue",
            fqdn,
        ]
        if email:
            args.append(email)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(
                proc.communicate((token + "\n").encode("utf-8")),
                timeout=240,
            )
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Timed out (DNS propagation can be slow) — try again",
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}
        data = self._last_json_line(out.decode("utf-8", "replace"))
        if data is None:
            return {
                "success": False,
                "error": (err.decode()[-300:] if err else "no output from issuer"),
            }
        return data

    async def restart_service(self) -> Dict[str, Any]:
        """Restart NetProtection DNS service via systemd."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "systemctl",
                "restart",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                err = (stderr.decode().strip() if stderr else "") or "restart failed"
                logger.error(f"Failed to restart NetProtection: {err}")
                return {"success": False, "error": err}

            service_status = "unknown"
            try:
                status_proc = await asyncio.create_subprocess_exec(
                    "systemctl",
                    "is-active",
                    "easypi-netprotection",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                status_out, _ = await status_proc.communicate()
                service_status = status_out.decode().strip()
            except Exception as exc:
                logger.warning(
                    "Could not read NetProtection service status after restart: %s", exc
                )

            if service_status not in ("active", "activating"):
                return {
                    "success": False,
                    "error": f"Service not active after restart (status: {service_status})",
                }

            logger.info("NetProtection service restarted")
            return {"success": True, "message": "NetProtection restarted"}
        except Exception as e:
            logger.error(f"Failed to restart NetProtection: {e}")
            return {"success": False, "error": str(e)}

    async def start_service(self) -> Dict[str, Any]:
        """Start NetProtection DNS service via systemd."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "systemctl",
                "start",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                service_status = "unknown"
                try:
                    status_proc = await asyncio.create_subprocess_exec(
                        "systemctl",
                        "is-active",
                        "easypi-netprotection",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    status_out, _ = await status_proc.communicate()
                    service_status = status_out.decode().strip()
                except Exception:
                    pass

                if service_status not in ("active", "activating"):
                    error = f"Service did not start (status: {service_status})"
                    logger.error(f"Failed to start NetProtection: {error}")
                    return {"success": False, "error": error}

                logger.info("NetProtection service started")
                return {"success": True, "message": "NetProtection started"}
            else:
                error = stderr.decode().strip()
                logger.error(f"Failed to start NetProtection: {error}")
                return {"success": False, "error": error}
        except Exception as e:
            logger.error(f"Failed to start NetProtection: {e}")
            return {"success": False, "error": str(e)}

    async def stop_service(self) -> Dict[str, Any]:
        """Stop NetProtection DNS service via systemd."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "systemctl",
                "stop",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                service_status = "unknown"
                try:
                    status_proc = await asyncio.create_subprocess_exec(
                        "systemctl",
                        "is-active",
                        "easypi-netprotection",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    status_out, _ = await status_proc.communicate()
                    service_status = status_out.decode().strip()
                except Exception:
                    pass

                if service_status in ("active", "activating"):
                    error = f"Service still running (status: {service_status})"
                    logger.error(f"Failed to stop NetProtection: {error}")
                    return {"success": False, "error": error}

                logger.info("NetProtection service stopped")
                return {"success": True, "message": "NetProtection stopped"}
            else:
                error = stderr.decode().strip()
                logger.error(f"Failed to stop NetProtection: {error}")
                return {"success": False, "error": error}
        except Exception as e:
            logger.error(f"Failed to stop NetProtection: {e}")
            return {"success": False, "error": str(e)}

    async def toggle_transparent_dns(self, enabled: bool) -> Dict[str, Any]:
        """
        Enable/disable transparent DNS interception via iptables.

        When enabled, all DNS traffic (port 53) from the local network is
        intercepted and redirected to NetProtection, regardless of which
        DNS server devices have configured.
        """
        try:
            config = await self.get_config()

            async def _detect_local_ip_and_iface() -> tuple[str, str]:
                proc = await asyncio.create_subprocess_exec(
                    "ip",
                    "route",
                    "get",
                    "1.1.1.1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode != 0:
                    return "", ""
                output = stdout.decode(errors="ignore")
                # Parse: 1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100
                parts = output.split()
                local_ip = ""
                interface = ""
                for i, p in enumerate(parts):
                    if p == "src" and i + 1 < len(parts):
                        local_ip = parts[i + 1]
                    if p == "dev" and i + 1 < len(parts):
                        interface = parts[i + 1]
                return local_ip, interface

            if enabled:
                local_ip, interface = await _detect_local_ip_and_iface()
                if not local_ip or not interface:
                    return {
                        "success": False,
                        "error": "Failed to detect local IP/interface for Transparent DNS",
                    }
            else:
                # Prefer the last known state from config to remove exact rules.
                local_ip = str(config.get("transparent_dns_ip") or "").strip()
                interface = str(config.get("transparent_dns_interface") or "").strip()
                if not local_ip or not interface:
                    local_ip, interface = await _detect_local_ip_and_iface()
                if not local_ip or not interface:
                    return {
                        "success": False,
                        "error": "Failed to detect local IP/interface for Transparent DNS",
                    }

            runner_path = EASYPI_ROOT / "scripts" / "runner"
            firewall_args = [
                "sudo",
                "-n",
                str(runner_path),
                "settings/network_firewall.sh",
            ]
            if enabled:
                old_ip = str(config.get("transparent_dns_ip") or local_ip).strip()
                old_iface = str(
                    config.get("transparent_dns_interface") or interface
                ).strip()
                firewall_args.extend(
                    [
                        "transparent-dns-enable",
                        interface,
                        local_ip,
                        old_iface,
                        old_ip,
                    ]
                )
            else:
                firewall_args.extend(["transparent-dns-disable", interface, local_ip])

            proc = await asyncio.create_subprocess_exec(
                *firewall_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                return {
                    "success": False,
                    "error": stderr.decode(errors="ignore").strip()
                    or "Failed to update transparent DNS firewall rules",
                }

            if enabled:
                # Store state in config
                config["transparent_dns"] = True
                config["transparent_dns_interface"] = interface
                config["transparent_dns_ip"] = local_ip
                await self.update_config(config)

                logger.info(f"Transparent DNS enabled on {interface} -> {local_ip}")
                return {
                    "success": True,
                    "message": f"Transparent DNS enabled - all DNS traffic on {interface} will be intercepted",
                    "enabled": True,
                    "interface": interface,
                    "local_ip": local_ip,
                }
            else:
                # Store state in config
                config["transparent_dns"] = False
                await self.update_config(config)

                logger.info("Transparent DNS disabled")
                return {
                    "success": True,
                    "message": "Transparent DNS disabled",
                    "enabled": False,
                }
        except Exception as e:
            logger.error(f"Failed to toggle transparent DNS: {e}")
            return {"success": False, "error": str(e)}
