"""StealthDeploymentMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.stealth_components.context import (
    Any,
    CLIENT_LOG,
    CONFIG_NAME,
    Dict,
    Ed25519PrivateKey,
    List,
    META_NAME,
    NGINX_PATCH_NAME,
    NGINX_TOOL,
    NGINX_TOOL_SHARE,
    Optional,
    Path,
    REMOTE_SERVER_DIR,
    SCRIPT_REL,
    SECRET_SCRIPT_REL,
    SERVER_BIN,
    X25519PrivateKey,
    _DUCKDNS_DOMAIN,
    _DeploymentLease,
    _HEX32,
    _deployment_locked,
    _friendly_ssh_err,
    _gen_psk,
    _gen_x25519_public,
    _normalize_server_addr,
    asyncio,
    base64,
    detect_routing_conflict,
    get_easypi_root,
    get_netprotection_data_dir,
    hashlib,
    hmac,
    httpx,
    io,
    ipaddress,
    json,
    logger,
    logging,
    os,
    posixpath,
    re,
    require_public_ipv4,
    routing_claim,
    serialization,
    socket,
    ssl,
    subprocess,
    time,
    wraps,
)


class StealthDeploymentMixin:
    @_deployment_locked("server-deploy")
    async def deploy_server(self) -> Dict[str, Any]:
        meta = self._meta()
        ssh = meta["ssh"]
        if not (ssh["host"] and self._has_ssh_auth(ssh)):
            return {
                "success": False,
                "log": "Set the VPS host + SSH credentials first.",
            }
        if not (meta["psk_key"] and meta["reality_public"]):
            return {
                "success": False,
                "log": "Generate the PSK and public marker first (Client tab).",
            }
        if not os.path.exists(SERVER_BIN):
            return {"success": False, "log": f"Server binary missing at {SERVER_BIN}."}
        ip_shield = True
        if not ssh.get("acme_terms_accepted"):
            return {
                "success": False,
                "log": "Accept the Let's Encrypt Subscriber Agreement before deploying IP Shield.",
            }
        try:
            secured = await asyncio.to_thread(self._ensure_secure_credentials)
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "log": f"Secure SSH credential setup failed: {exc}",
            }
        if not secured.get("success"):
            return secured
        meta = self._meta()
        ssh = meta["ssh"]
        try:
            endpoint_ip = self._ip_shield_address(meta)
        except ValueError as exc:
            return {"success": False, "log": str(exc)}
        remote = REMOTE_SERVER_DIR
        try:
            if not _HEX32.fullmatch(str(meta.get("client_auth_key") or "")):
                meta["client_auth_key"] = _gen_psk()
                self._save_meta(meta)
                if self._meta().get("client_auth_key") != meta["client_auth_key"]:
                    raise ValueError("Could not persist independent client credentials")
            server_cfg = self._server_config_json(meta)
            nginx_cfg = self._nginx_frontend_config(meta)
        except ValueError as exc:
            return {"success": False, "log": str(exc)}
        unit = self._server_systemd_unit()
        network_unit = self._network_systemd_unit()
        domain_identity = str(ssh.get("domain") or "")
        domain_tls_active = bool(
            ssh.get("domain_tls_deployed") and domain_identity
        )
        cert_identity = domain_identity if domain_tls_active else endpoint_ip
        cert_service = self._certificate_renewal_service(identity=cert_identity)
        cert_timer = (
            "[Unit]\nDescription=Schedule Chameleon IP Shield certificate renewal\n"
            # A calendar schedule never "elapses". The former relative
            # OnUnitActiveSec trigger stopped forever after a redeploy restarted
            # the timer, so the certificate silently stopped renewing.
            "[Timer]\nOnBootSec=15min\nOnCalendar=*-*-* 00/12:00:00\n"
            "RandomizedDelaySec=2h\nPersistent=true\n"
            "Unit=chameleon-cert-renew.service\n"
            "[Install]\nWantedBy=timers.target\n"
        )

        def _do() -> Dict[str, Any]:
            log: List[str] = []
            try:
                c = self._connect(ssh)

                def run_checked(command: str, label: str, timeout: int = 180) -> str:
                    _, stdout, stderr = c.exec_command(command, timeout=timeout)
                    output = stdout.read().decode(errors="ignore").strip()
                    error = stderr.read().decode(errors="ignore").strip()
                    rc = stdout.channel.recv_exit_status()
                    detail = "\n".join(part for part in (output, error) if part)
                    if rc != 0 and label in {"TUN/firewall setup", "Chameleon restart"}:
                        _, journal_out, _ = c.exec_command(
                            "journalctl -u chameleon-network.service --no-pager "
                            "-n 20 -o cat 2>/dev/null",
                            timeout=10,
                        )
                        journal = journal_out.read().decode(errors="ignore").strip()
                        if journal:
                            detail = "\n".join(part for part in (detail, journal) if part)
                    suffix = f" — {detail[-800:]}" if detail else ""
                    log.append(f"{label}: {'ok' if rc == 0 else 'failed'}{suffix}")
                    if rc != 0:
                        raise RuntimeError(
                            f"{label} failed{(': ' + detail[-500:]) if detail else ''}"
                        )
                    return output

                log.append(f"Connected to {ssh['user']}@{ssh['host']}:{ssh['port']}")
                # Fresh Debian/Ubuntu ships nftables only — no `iptables` command. The
                # server needs it for TUN NAT/forwarding; without it it falls back to a
                # UDP-only relay that can't carry TCP (no internet through the tunnel).
                run_checked(
                    "command -v iptables >/dev/null 2>&1 && echo present || "
                    "{ apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive "
                    "apt-get install -y -qq iptables >/dev/null 2>&1; "
                    "command -v iptables >/dev/null 2>&1 && echo installed || echo MISSING; }",
                    "iptables",
                    timeout=180,
                )
                run_checked(
                    "/opt/chameleon-certbot/bin/certbot --version 2>/dev/null | "
                    "grep -qx 'certbot 5.4.0' || { rm -rf /opt/chameleon-certbot; "
                    "apt-get update -qq >/dev/null 2>&1; "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv >/dev/null 2>&1; "
                    "python3 -m venv /opt/chameleon-certbot; "
                    "/opt/chameleon-certbot/bin/pip install --disable-pip-version-check "
                    "--no-cache-dir -q certbot==5.4.0; }",
                    "Certbot 5.4 installation",
                    timeout=300,
                )
                run_checked(
                    "command -v flock >/dev/null 2>&1 || { "
                    "apt-get update -qq >/dev/null 2>&1; "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    "util-linux >/dev/null 2>&1; }; command -v flock >/dev/null 2>&1",
                    "Certificate operation lock",
                    timeout=180,
                )
                run_checked(
                    "install -d -o root -g root -m 0755 "
                    "/etc/systemd/system/certbot.service.d && "
                    "install -d -o root -g root -m 0755 /etc/tmpfiles.d",
                    "VPS guard directory",
                    timeout=30,
                )
                sftp = c.open_sftp()
                with sftp.file(
                    "/usr/local/sbin/chameleon-certbot-standalone", "w"
                ) as f:
                    f.write(self._standalone_certbot_wrapper())
                sftp.chmod("/usr/local/sbin/chameleon-certbot-standalone", 0o700)
                with sftp.file("/usr/local/sbin/easypi-vps-guard", "w") as f:
                    f.write(self._vps_guard_script())
                sftp.chmod("/usr/local/sbin/easypi-vps-guard", 0o700)
                with sftp.file(
                    "/etc/systemd/system/easypi-vps-guard.service", "w"
                ) as f:
                    f.write(self._vps_guard_unit())
                with sftp.file(
                    "/etc/systemd/system/certbot.service.d/easypi-vps-guard.conf",
                    "w",
                ) as f:
                    f.write(self._certbot_guard_override())
                with sftp.file(
                    "/etc/tmpfiles.d/easypi-vps-guard.conf", "w"
                ) as f:
                    f.write(
                        "f /run/xtables.lock 0600 root root -\n"
                        "f /run/easypi-certbot.lock 0600 root root -\n"
                    )
                sftp.close()
                run_checked(
                    "systemd-tmpfiles --create /etc/tmpfiles.d/easypi-vps-guard.conf && "
                    "systemctl daemon-reload && "
                    "systemctl enable --now easypi-vps-guard.service",
                    "VPS public HTTP and ping guard",
                    timeout=30,
                )
                if cert_identity == endpoint_ip:
                    run_checked(
                        self._ip_certificate_issue_command(endpoint_ip),
                        "IP certificate issuance",
                        timeout=240,
                    )
                else:
                    run_checked(
                        self._domain_certificate_setup_command(cert_identity),
                        "Domain certificate setup",
                        timeout=360,
                    )
                    # Certbot now remembers standalone HTTP-01. Publish the
                    # matching port-80 wrapper unit before deleting legacy DNS
                    # hooks so an interrupted redeploy still renews correctly.
                    sftp = c.open_sftp()
                    with sftp.file(
                        "/etc/systemd/system/chameleon-cert-renew.service", "w"
                    ) as f:
                        f.write(cert_service)
                    sftp.close()
                    run_checked(
                        "systemctl daemon-reload",
                        "HTTP renewal activation",
                        timeout=30,
                    )
                run_checked(
                    self._legacy_duckdns_cleanup_command(),
                    "Legacy DuckDNS cleanup",
                    timeout=30,
                )
                run_checked(
                    f"test -s /etc/letsencrypt/live/{cert_identity}/fullchain.pem && "
                    f"test -s /etc/letsencrypt/live/{cert_identity}/privkey.pem",
                    "TLS certificate verification",
                    timeout=20,
                )
                run_checked(
                    "if command -v nginx >/dev/null 2>&1; then echo present; else "
                    "apt-get update -qq >/dev/null 2>&1; "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx "
                    ">/dev/null 2>&1; command -v nginx >/dev/null 2>&1; "
                    "install -d -o root -g root -m 0700 /var/lib/easypi-chameleon; "
                    "touch /var/lib/easypi-chameleon/nginx-installed; "
                    "if [ -L /etc/nginx/sites-enabled/default ] && "
                    "[ \"$(readlink -f /etc/nginx/sites-enabled/default)\" = "
                    '"/etc/nginx/sites-available/default" ]; then '
                    "rm -f /etc/nginx/sites-enabled/default; fi; echo installed; fi",
                    "nginx TLS frontend",
                    timeout=240,
                )
                run_checked(
                    "getent group chameleon >/dev/null || groupadd --system chameleon; "
                    "id -u chameleon >/dev/null 2>&1 || "
                    "useradd --system --gid chameleon --home-dir /opt/chameleon-server "
                    "--no-create-home --shell /usr/sbin/nologin chameleon; "
                    f"install -d -o root -g chameleon -m 0751 {remote}; "
                    f"install -d -o root -g root -m 0755 {remote}/site; "
                    f"install -d -o root -g chameleon -m 0750 {remote}/tls",
                    "Chameleon service account",
                    timeout=30,
                )
                sftp = c.open_sftp()
                # Upload beside the live executable, then atomically replace it.
                # Writing the running inode directly can fail with ETXTBSY and
                # risks leaving a truncated server after an interrupted deploy.
                upload_path = f"{remote}/.chameleon-server.upload"
                sftp.put(SERVER_BIN, upload_path)
                sftp.chmod(upload_path, 0o700)
                run_checked(
                    f"mv -f -- {upload_path} {remote}/chameleon-server && "
                    f"chown root:chameleon {remote}/chameleon-server && "
                    f"chmod 0750 {remote}/chameleon-server",
                    "Atomic binary install",
                    timeout=30,
                )
                log.append(f"Uploaded chameleon-server -> {remote}/chameleon-server")
                # Secrets remain root-owned and are readable only by Chameleon.
                with sftp.file(f"{remote}/server_config.json", "w") as f:
                    f.write(server_cfg)
                sftp.chmod(f"{remote}/server_config.json", 0o640)
                # Preserve existing revocations on redeploy. The new server
                # never accepts legacy shared-key sessions as mobile identities.
                try:
                    sftp.stat(f"{remote}/mobile_clients.json")
                except OSError:
                    with sftp.file(f"{remote}/mobile_clients.json", "w") as f:
                        f.write('{"version":1,"devices":[]}')
                sftp.chmod(f"{remote}/mobile_clients.json", 0o640)
                log.append("Wrote server_config.json (PSK + public marker)")
                site_source = get_easypi_root() / "chameleon" / "server" / "site"
                if not (site_source / "index.html").is_file():
                    raise RuntimeError(
                        "Chameleon cover site is missing from the EasyPi installation"
                    )
                c.exec_command(f"mkdir -p {remote}/site")[1].channel.recv_exit_status()
                for asset in site_source.iterdir():
                    if asset.is_file():
                        sftp.put(str(asset), f"{remote}/site/{asset.name}")
                        sftp.chmod(f"{remote}/site/{asset.name}", 0o644)
                nginx_upload = "/etc/nginx/conf.d/.easypi-chameleon.conf.upload"
                with sftp.file(nginx_upload, "w") as f:
                    f.write(nginx_cfg)
                sftp.chmod(nginx_upload, 0o600)
                with sftp.file("/usr/local/sbin/chameleon-install-cert", "w") as f:
                    f.write(self._certificate_install_script())
                sftp.chmod("/usr/local/sbin/chameleon-install-cert", 0o700)
                with sftp.file("/usr/local/sbin/chameleon-network-setup", "w") as f:
                    f.write(self._network_setup_script())
                sftp.chmod("/usr/local/sbin/chameleon-network-setup", 0o700)
                # systemd unit
                with sftp.file(
                    "/etc/systemd/system/chameleon-server.service", "w"
                ) as f:
                    f.write(unit)
                with sftp.file(
                    "/etc/systemd/system/chameleon-network.service", "w"
                ) as f:
                    f.write(network_unit)
                log.append("Installed systemd unit")
                with sftp.file(
                    "/etc/systemd/system/chameleon-cert-renew.service", "w"
                ) as f:
                    f.write(cert_service)
                with sftp.file(
                    "/etc/systemd/system/chameleon-cert-renew.timer", "w"
                ) as f:
                    f.write(cert_timer)
                sftp.close()
                run_checked(
                    f"chown root:chameleon {remote}/server_config.json && "
                    f"chown root:chameleon {remote}/mobile_clients.json && "
                    f"chown root:root {remote}/site && chmod 0755 {remote}/site && "
                    f"find {remote}/site -type f -exec chown root:root {{}} + && "
                    + self._tls_material_install_command(
                        cert_identity, install_only=True
                    ),
                    "Restricted Chameleon files",
                    timeout=30,
                )
                run_checked(
                    "set -eu; "
                    "target=/etc/nginx/conf.d/easypi-chameleon.conf; "
                    "upload=/etc/nginx/conf.d/.easypi-chameleon.conf.upload; "
                    "backup=/etc/nginx/conf.d/.easypi-chameleon.conf.backup; "
                    "rm -f \"$backup\"; "
                    "if [ -e \"$target\" ]; then cp -a \"$target\" \"$backup\"; fi; "
                    "install -o root -g root -m 0600 \"$upload\" \"$target\"; "
                    "rm -f \"$upload\"; "
                    "if ! nginx -t; then "
                    "if [ -e \"$backup\" ]; then mv -f \"$backup\" \"$target\"; "
                    "else rm -f \"$target\"; fi; "
                    "nginx -t >/dev/null 2>&1 || true; exit 1; fi; "
                    "rm -f \"$backup\"",
                    "nginx frontend configuration",
                    timeout=30,
                )
                # Ubuntu's nginx plus the WINDOW_UPDATE patch, rebuilt from the
                # installed package's own source after every Ubuntu update, and
                # the frontend's connection and memory limits.
                nginx_assets = get_easypi_root() / "chameleon" / "server" / "nginx"
                nginx_tool = nginx_assets / "easypi-chameleon-nginx"
                nginx_patch = nginx_assets / NGINX_PATCH_NAME
                if not (nginx_tool.is_file() and nginx_patch.is_file()):
                    raise RuntimeError(
                        "Chameleon nginx tools are missing from the EasyPi installation"
                    )
                run_checked(
                    f"install -d -o root -g root -m 0755 {NGINX_TOOL_SHARE}",
                    "nginx patch directory",
                    timeout=30,
                )
                sftp = c.open_sftp()
                sftp.put(str(nginx_tool), f"{NGINX_TOOL}.upload")
                sftp.chmod(f"{NGINX_TOOL}.upload", 0o700)
                sftp.put(str(nginx_patch), f"{NGINX_TOOL_SHARE}/{NGINX_PATCH_NAME}.upload")
                sftp.chmod(f"{NGINX_TOOL_SHARE}/{NGINX_PATCH_NAME}.upload", 0o644)
                sftp.close()
                nginx_state = run_checked(
                    f"mv -f -- {NGINX_TOOL}.upload {NGINX_TOOL} && "
                    f"mv -f -- {NGINX_TOOL_SHARE}/{NGINX_PATCH_NAME}.upload "
                    f"{NGINX_TOOL_SHARE}/{NGINX_PATCH_NAME} && "
                    f"{NGINX_TOOL} install",
                    "nginx WINDOW_UPDATE patch and limits",
                    timeout=3600,
                )
                if "running=patched" not in nginx_state:
                    log.append(
                        "WARNING: the WINDOW_UPDATE patch could not be built; the "
                        "packaged nginx runs and the tunnel works without it."
                    )
                # enable + (re)start
                run_checked("systemctl daemon-reload", "systemd reload", timeout=30)
                run_checked(
                    "systemctl enable chameleon-network",
                    "Network setup enable",
                    timeout=30,
                )
                run_checked(
                    "systemctl enable chameleon-server", "Chameleon enable", timeout=30
                )
                run_checked(
                    "systemctl enable --now chameleon-cert-renew.timer",
                    "certificate renewal timer",
                    timeout=30,
                )
                run_checked(
                    "systemctl restart chameleon-network",
                    "TUN/firewall setup",
                    timeout=30,
                )
                # A previous release may still own public port 443. Stop it
                # before starting the new loopback-only backend and nginx.
                run_checked(
                    "systemctl stop chameleon-server 2>/dev/null || true",
                    "Previous Chameleon stop",
                    timeout=30,
                )
                run_checked(
                    "systemctl restart chameleon-server",
                    "Chameleon restart",
                    timeout=30,
                )
                run_checked(
                    "systemctl enable nginx.service >/dev/null 2>&1; "
                    "if systemctl is-active --quiet nginx.service; then "
                    "systemctl reload nginx.service; else systemctl restart nginx.service; fi; "
                    "systemctl is-active --quiet nginx.service",
                    "nginx public frontend activation",
                    timeout=30,
                )
                # verify — include the startup journal (the [tun] line reveals whether
                # kernel forwarding came up or fell back to "legacy UDP relay only").
                _, out, _ = c.exec_command(
                    "sleep 1; systemctl is-active chameleon-server; "
                    "systemctl is-active --quiet nginx.service || echo NGINX_INACTIVE; "
                    "ss -H -ltn 'sport = :443' | grep -q . || echo PUBLIC_443_MISSING; "
                    "backend=$(ss -H -ltn 'sport = :9080' | awk '{print $4}'); "
                    "[ \"$backend\" = 127.0.0.1:9080 ] || echo BACKEND_BIND_INVALID:$backend; "
                    "ip link show dev chameleon0 >/dev/null 2>&1 || echo TUN_MISSING; "
                    "echo '--- log ---'; "
                    "journalctl -u chameleon-server --no-pager -n 25 2>/dev/null | "
                    "sed -E 's/^.*chameleon-server\\[[0-9]+\\]: //'",
                    timeout=20,
                )
                status = out.read().decode(errors="ignore").strip()
                active = status.splitlines()[0].strip() == "active" if status else False
                if "TUN_MISSING" in status or "required kernel tunnel unavailable" in status:
                    active = False
                    log.append(
                        "ERROR: required kernel tunnel did NOT come up (no forwarding) — "
                        "the VPS likely lacks /dev/net/tun or iptables (common on "
                        "container/OpenVZ VPS). A KVM VPS with TUN is required."
                    )
                if any(
                    marker in status
                    for marker in (
                        "NGINX_INACTIVE",
                        "PUBLIC_443_MISSING",
                        "BACKEND_BIND_INVALID",
                    )
                ):
                    active = False
                    log.append(
                        "ERROR: the public nginx frontend or private Chameleon backend "
                        "is not bound as required."
                    )
                log.append("--- status ---\n" + status)
                c.close()
                return {"success": active, "active": active, "log": "\n".join(log)}
            except Exception as e:  # noqa: BLE001
                log.append(f"ERROR: {e}{_friendly_ssh_err(str(e))}")
                return {"success": False, "log": "\n".join(log)}

        result = await asyncio.to_thread(_do)
        return await self._finish_deploy(result, ip_shield)

    async def _finish_deploy(
        self, result: Dict[str, Any], ip_shield: bool
    ) -> Dict[str, Any]:
        if result.get("success"):
            current = self._meta()
            # The deployed VPS may hold a different (or empty) registry.
            current["mobile_registry_digest"] = ""
            self._save_meta(current)
            if ip_shield:
                current["ssh"]["ip_shield_deployed"] = True
                current["shield_preset"] = "ip"
                self._save_meta(current)
            if current.get("enabled"):
                client_status = await self.enable(confirm_routing_conflict=True)
                if not client_status.get("connected"):
                    result["success"] = False
                    result["log"] += (
                        "\nServer deployed and active, but the local Stealth client did not connect. "
                        "Traffic remains blocked by the kill switch; check the server log or disable Stealth."
                    )
                else:
                    result["log"] += "\nLocal Stealth client restarted and connected."
        return result

    @_deployment_locked("server-stop")
    async def stop_server(self) -> Dict[str, Any]:
        ssh = self._meta()["ssh"]
        if not (ssh["host"] and self._has_ssh_auth(ssh)):
            return {
                "success": False,
                "log": "Set the VPS host + SSH credentials first.",
            }
        try:
            secured = await asyncio.to_thread(self._ensure_secure_credentials)
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "log": f"Secure SSH credential setup failed: {exc}",
            }
        if not secured.get("success"):
            return secured
        ssh = self._meta()["ssh"]

        def _do() -> Dict[str, Any]:
            try:
                c = self._connect(ssh)
                _, out, _ = c.exec_command(
                    "systemctl stop chameleon-server chameleon-network; "
                    "systemctl is-active chameleon-server",
                    timeout=20,
                )
                st = out.read().decode(errors="ignore").strip()
                c.close()
                return {"success": True, "log": f"Stopped. state: {st or 'inactive'}"}
            except Exception as e:  # noqa: BLE001
                return {
                    "success": False,
                    "log": f"Stop failed: {e}{_friendly_ssh_err(str(e))}",
                }

        return await asyncio.to_thread(_do)

    @_deployment_locked("server-uninstall")
    async def uninstall_server(self) -> Dict[str, Any]:
        """Remove chameleon-server from the VPS: stop + disable + delete unit + dir."""
        ssh = self._meta()["ssh"]
        if not (ssh["host"] and self._has_ssh_auth(ssh)):
            return {
                "success": False,
                "log": "Set the VPS host + SSH credentials first.",
            }
        try:
            secured = await asyncio.to_thread(self._ensure_secure_credentials)
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "log": f"Secure SSH credential setup failed: {exc}",
            }
        if not secured.get("success"):
            return secured
        ssh = self._meta()["ssh"]
        remote = REMOTE_SERVER_DIR

        def _do() -> Dict[str, Any]:
            log: List[str] = []
            try:
                c = self._connect(ssh)
                for cmd in (
                    "systemctl stop chameleon-server chameleon-network 2>/dev/null",
                    "systemctl disable chameleon-server 2>/dev/null",
                    "systemctl disable chameleon-network 2>/dev/null",
                    "systemctl disable --now chameleon-cert-renew.timer 2>/dev/null",
                    "systemctl disable --now easypi-vps-guard.service 2>/dev/null",
                    "test ! -x /usr/local/sbin/easypi-vps-guard || "
                    "/usr/local/sbin/easypi-vps-guard remove",
                    "rm -f /etc/systemd/system/chameleon-server.service",
                    "rm -f /etc/systemd/system/chameleon-network.service",
                    "rm -f /etc/systemd/system/chameleon-cert-renew.service",
                    "rm -f /etc/systemd/system/chameleon-cert-renew.timer",
                    "rm -f /etc/systemd/system/easypi-vps-guard.service",
                    "rm -f /etc/systemd/system/certbot.service.d/easypi-vps-guard.conf",
                    "rm -f /etc/tmpfiles.d/easypi-vps-guard.conf",
                    "rm -f /usr/local/sbin/chameleon-network-setup",
                    "rm -f /usr/local/sbin/chameleon-install-cert",
                    "rm -f /usr/local/sbin/easypi-vps-guard",
                    # Put the packaged nginx back before nginx may be removed.
                    f"test ! -x {NGINX_TOOL} || {NGINX_TOOL} remove",
                    f"rm -f {NGINX_TOOL}; rm -rf {NGINX_TOOL_SHARE}",
                    "rm -f /etc/nginx/conf.d/easypi-chameleon.conf "
                    "/etc/nginx/conf.d/.easypi-chameleon.conf.upload "
                    "/etc/nginx/conf.d/.easypi-chameleon.conf.backup; "
                    "if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; "
                    "then systemctl reload nginx.service 2>/dev/null || true; fi",
                    "if [ -e /var/lib/easypi-chameleon/nginx-installed ] && "
                    "! find -L /etc/nginx/conf.d /etc/nginx/sites-enabled -maxdepth 1 "
                    "-type f -name '*.conf' -o -type f 2>/dev/null | grep -q .; then "
                    "systemctl disable --now nginx.service 2>/dev/null || true; fi; "
                    "rm -rf /var/lib/easypi-chameleon",
                    "systemctl daemon-reload",
                    f"rm -rf '{remote}'",
                ):
                    _, out, _ = c.exec_command(cmd, timeout=30)
                    rc = out.channel.recv_exit_status()
                    log.append(f"$ {cmd}  (rc={rc})")
                c.close()
                return {
                    "success": True,
                    "log": "Removed chameleon-server from the VPS.\n" + "\n".join(log),
                }
            except Exception as e:  # noqa: BLE001
                return {
                    "success": False,
                    "log": f"Uninstall failed: {e}{_friendly_ssh_err(str(e))}",
                }

        result = await asyncio.to_thread(_do)
        if result.get("success"):
            meta = self._meta()
            meta["ssh"]["ip_shield_deployed"] = False
            meta["mobile_registry_digest"] = ""
            self._save_meta(meta)
        return result

    async def server_logs(self) -> Dict[str, Any]:
        """Fetch the chameleon-server journal from the VPS (for diagnosis)."""
        ssh = self._meta()["ssh"]
        if not (ssh["host"] and self._has_ssh_auth(ssh)):
            return {
                "success": False,
                "log": "Set the VPS host + SSH credentials first.",
            }

        def _do() -> Dict[str, Any]:
            try:
                c = self._connect(ssh)
                _, out, _ = c.exec_command(
                    "systemctl is-active chameleon-server; echo '--- journal ---'; "
                    "journalctl -u chameleon-server --no-pager -n 80 2>/dev/null | "
                    "sed -E 's/^.*chameleon-server\\[[0-9]+\\]: //'",
                    timeout=25,
                )
                log = out.read().decode(errors="ignore").strip()
                c.close()
                hint = ""
                if "kernel tunnel disabled" in log:
                    hint = (
                        "\n\n⚠ Kernel tunnel is DOWN → no forwarding (rx stays 0). The VPS "
                        "likely has no /dev/net/tun or no iptables (container/OpenVZ). Use a "
                        "KVM VPS, or install iptables / enable TUN."
                    )
                return {"success": True, "log": (log or "(empty)") + hint}
            except Exception as e:  # noqa: BLE001
                return {
                    "success": False,
                    "log": f"Fetch failed: {e}{_friendly_ssh_err(str(e))}",
                }

        return await asyncio.to_thread(_do)
