"""StealthSshMixin implementation."""

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


class StealthSshMixin:
    _LEGACY_DUCKDNS_CLEANUP_MARKER = ".stealth-duckdns-token-cleanup-v1"

    @staticmethod
    def _has_ssh_auth(ssh: Dict[str, Any]) -> bool:
        return bool(
            ssh.get("ssh_key_installed")
            or ssh.get("ssh_password_stored")
            or ssh.get("password")
        )

    def _ssh_password(self, ssh: Dict[str, Any]) -> str:
        if ssh.get("ssh_password_stored"):
            return self._secret_read("ssh-password")
        return str(ssh.get("password") or "")

    def cleanup_legacy_duckdns_token(self) -> bool:
        """Remove obsolete Stealth DuckDNS credentials once per installation.

        The marker is published only after both the root-owned encrypted
        credential and any legacy metadata fields have been removed. A failed
        attempt therefore remains retryable on the next backend startup.
        """
        marker = self._data_dir / self._LEGACY_DUCKDNS_CLEANUP_MARKER
        if marker.is_file() and not marker.is_symlink():
            return False

        self._secret_delete("duckdns-token")

        if self._meta_path.exists():
            stored = json.loads(self._meta_path.read_text(encoding="utf-8"))
            if not isinstance(stored, dict):
                raise RuntimeError("Stealth metadata has an invalid format")
            stored.pop("duckdns_token", None)
            stored.pop("duckdns_token_stored", None)
            ssh = stored.get("ssh")
            if isinstance(ssh, dict):
                ssh.pop("duckdns_token", None)
                ssh.pop("duckdns_token_stored", None)
            self._data_dir.mkdir(parents=True, exist_ok=True)
            temporary_meta = self._data_dir / (
                f".{self._meta_path.name}.legacy-cleanup-{os.getpid()}-{os.urandom(6).hex()}"
            )
            try:
                temporary_meta.write_text(json.dumps(stored), encoding="utf-8")
                temporary_meta.chmod(0o600)
                os.replace(temporary_meta, self._meta_path)
            finally:
                temporary_meta.unlink(missing_ok=True)

        self._data_dir.mkdir(parents=True, exist_ok=True)
        temporary_marker = self._data_dir / (
            f".{self._LEGACY_DUCKDNS_CLEANUP_MARKER}-{os.getpid()}-{os.urandom(6).hex()}"
        )
        try:
            temporary_marker.write_text("complete\n", encoding="ascii")
            temporary_marker.chmod(0o600)
            os.replace(temporary_marker, marker)
        finally:
            temporary_marker.unlink(missing_ok=True)
        return True

    def _migrate_legacy_secrets(self) -> None:
        current = self._meta()
        ssh = current["ssh"]
        changed = False
        password = str(ssh.get("password") or "")
        modes: List[str] = []
        if password and not ssh.get("ssh_password_stored"):
            modes.append(self._secret_store("ssh-password", password))
            ssh["ssh_password_stored"] = True
            ssh["password"] = ""
            changed = True
        # Normally completed during backend startup. Keeping this call here
        # also self-heals installations where the startup attempt failed.
        self.cleanup_legacy_duckdns_token()
        if modes:
            ssh["credential_protection"] = self._credential_label(
                "host+tpm2" if any("tpm2" in mode for mode in modes) else "host"
            )
            changed = True
        if changed:
            self._save_meta(current)

    @staticmethod
    def _new_ssh_identity() -> tuple[str, str, str]:
        private_key = Ed25519PrivateKey.generate()
        private_text = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ).decode("utf-8")
        public_text = (
            private_key.public_key()
            .public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH,
            )
            .decode("ascii")
        )
        key_blob = base64.b64decode(public_text.split()[1], validate=True)
        digest = (
            base64.b64encode(hashlib.sha256(key_blob).digest())
            .decode("ascii")
            .rstrip("=")
        )
        return private_text, f"{public_text} easypi-stealth", f"SHA256:{digest}"

    @staticmethod
    def _discover_public_ipv6(connection: Any) -> str:
        """Return the VPS's stable global IPv6 address, or "" when it has none.

        Phones dial it before the IPv4 address: on some mobile networks the
        VPS's IPv4 transit is lossy while its IPv6 path is clean. Temporary,
        deprecated and tentative addresses are skipped; only a public unicast
        address is accepted, so a hostile reply cannot point phones elsewhere
        than at a public host (the tunnel itself is still authenticated).
        """
        try:
            _, stdout, _ = connection.exec_command(
                "ip -6 -o addr show scope global", timeout=10
            )
            output = stdout.read(64 * 1024).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - IPv6 is optional; IPv4 still works.
            return ""
        return StealthSshMixin._parse_public_ipv6(output)

    @staticmethod
    def _parse_public_ipv6(output: str) -> str:
        for line in output.splitlines():
            fields = line.split()
            if "inet6" not in fields or {"temporary", "deprecated", "tentative"} & set(fields):
                continue
            position = fields.index("inet6") + 1
            if position >= len(fields):
                continue
            value = fields[position].split("/", 1)[0]
            try:
                address = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            if address.is_global and not address.ipv4_mapped:
                return str(address)
        return ""

    @staticmethod
    def _install_authorized_key(connection: Any, public_line: str) -> None:
        _, stdout, stderr = connection.exec_command(
            'umask 077; mkdir -p -- "$HOME/.ssh"; chmod 700 -- "$HOME/.ssh"; '
            'touch -- "$HOME/.ssh/authorized_keys"; chmod 600 -- "$HOME/.ssh/authorized_keys"',
            timeout=20,
        )
        error = stderr.read().decode(errors="ignore").strip()
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError(
                f"Failed to prepare remote authorized_keys{(': ' + error[-200:]) if error else ''}"
            )
        sftp = connection.open_sftp()
        try:
            home = sftp.normalize(".")
            authorized = posixpath.join(home, ".ssh", "authorized_keys")
            try:
                with sftp.file(authorized, "r") as handle:
                    existing = handle.read(1024 * 1024 + 1)
                if isinstance(existing, bytes):
                    existing = existing.decode("utf-8", errors="strict")
            except OSError:
                existing = ""
            if len(existing.encode("utf-8")) > 1024 * 1024:
                raise RuntimeError("Remote authorized_keys is unexpectedly large")
            key_prefix = " ".join(public_line.split()[:2])
            lines = [line.rstrip("\r") for line in existing.splitlines()]
            if not any(
                " ".join(line.split()[:2]) == key_prefix
                for line in lines
                if line.strip()
            ):
                lines.append(public_line)
            payload = "\n".join(line for line in lines if line.strip()) + "\n"
            temp_path = authorized + f".easypi-{os.urandom(6).hex()}"
            with sftp.file(temp_path, "w") as handle:
                handle.write(payload)
                handle.flush()
            sftp.chmod(temp_path, 0o600)
            sftp.posix_rename(temp_path, authorized)
        finally:
            sftp.close()

    def _ensure_secure_credentials(self) -> Dict[str, Any]:
        """Migrate legacy secrets, install an Ed25519 key, verify it, then erase the password."""
        self._migrate_legacy_secrets()
        current = self._meta()
        ssh = current["ssh"]
        if not (
            ssh.get("host") and ssh.get("host_key_data") and self._has_ssh_auth(ssh)
        ):
            return {
                "success": False,
                "log": "Save the VPS credentials and trust its SSH host key first.",
            }

        if not ssh.get("ssh_key_installed"):
            connection = self._connect(ssh, force_password=True)
            private_text, public_line, fingerprint = self._new_ssh_identity()
            try:
                mode = self._secret_store("ssh-private-key", private_text)
                self._install_authorized_key(connection, public_line)
            except Exception:
                try:
                    self._secret_delete("ssh-private-key")
                except Exception:
                    pass
                raise
            finally:
                connection.close()
            current = self._meta()
            current_ssh = current["ssh"]
            current_ssh["ssh_key_installed"] = True
            current_ssh["ssh_key_verified"] = False
            current_ssh["ssh_key_fingerprint"] = fingerprint
            current_ssh["credential_protection"] = self._credential_label(mode)
            self._save_meta(current)
            ssh = current_ssh

        # A fresh key-only connection proves that sshd accepts the installed key.
        verification = self._connect(ssh)
        try:
            public_ipv6 = self._discover_public_ipv6(verification)
        finally:
            verification.close()
        try:
            self._secret_delete("ssh-password")
        except Exception:
            return {
                "success": False,
                "log": "SSH key verified, but the stored password could not be removed.",
            }
        current = self._meta()
        current_ssh = current["ssh"]
        current_ssh["ssh_key_verified"] = True
        current_ssh["password"] = ""
        current_ssh["ssh_password_stored"] = False
        current_ssh["public_ipv6"] = public_ipv6
        self._save_meta(current)
        return {
            "success": True,
            "log": "SSH Ed25519 key installed and verified; stored SSH password removed.",
        }

    # ── server settings + SSH deploy (Server tab) ─────────────────────────────
    def save_server(
        self,
        host: str,
        user: str,
        port: int,
        password: str,
        remote_path: str,
        acme_terms_accepted: bool = False,
        domain: str = "",
    ) -> Dict[str, Any]:
        normalized_host = require_public_ipv4(host, label="Stealth VPS")
        try:
            new_port = int(port or 22)
        except Exception:
            new_port = 22
        if not 1 <= new_port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        requested_path = (remote_path or REMOTE_SERVER_DIR).rstrip("/")
        if requested_path != REMOTE_SERVER_DIR:
            raise ValueError(f"remote_path must be {REMOTE_SERVER_DIR}")
        normalized_domain = self._normalize_duckdns_domain(domain)

        meta = self._meta()
        ssh = meta["ssh"]
        old_host = ssh.get("host")
        old_port = int(ssh.get("port") or 22)
        ssh["host"] = normalized_host
        endpoint_changed = bool(
            old_host and (old_host != ssh["host"] or old_port != new_port)
        )
        if endpoint_changed:
            ssh["ip_shield_deployed"] = False
            ssh["domain_tls_deployed"] = False
            ssh["host_key_type"] = ""
            ssh["host_key_data"] = ""
            ssh["host_key_sha256"] = ""
            had_ssh_key = bool(ssh.get("ssh_key_installed"))
            had_stored_password = bool(ssh.get("ssh_password_stored"))
            ssh["ssh_key_installed"] = False
            ssh["ssh_key_verified"] = False
            ssh["ssh_key_fingerprint"] = ""
            ssh["ssh_password_stored"] = False
            if had_ssh_key:
                self._secret_delete("ssh-private-key")
            if had_stored_password:
                self._secret_delete("ssh-password")
        ssh["user"] = (user or "root").strip()
        ssh["port"] = new_port
        if password:  # blank keeps the stored credential
            mode = self._secret_store("ssh-password", password)
            ssh["password"] = ""
            ssh["ssh_password_stored"] = True
            ssh["credential_protection"] = self._credential_label(mode)
        ssh["remote_path"] = REMOTE_SERVER_DIR
        ssh["acme_terms_accepted"] = bool(acme_terms_accepted)
        if normalized_domain != ssh.get("domain", ""):
            ssh["domain_tls_deployed"] = False
        ssh["domain"] = normalized_domain
        self._secret_delete("duckdns-token")
        self._save_meta(meta)
        return {"success": True, **self.server_state()}

    def server_state(self) -> Dict[str, Any]:
        ssh = self._meta()["ssh"]
        return {
            "ssh_host": ssh["host"],
            "ssh_user": ssh["user"],
            "ssh_port": ssh["port"],
            "has_password": bool(ssh.get("ssh_password_stored") or ssh.get("password")),
            "ssh_key_installed": bool(ssh.get("ssh_key_installed")),
            "ssh_key_verified": bool(ssh.get("ssh_key_verified")),
            "ssh_key_fingerprint": ssh.get("ssh_key_fingerprint", ""),
            "credential_protection": ssh.get("credential_protection", ""),
            "remote_path": ssh["remote_path"],
            "acme_terms_accepted": bool(ssh.get("acme_terms_accepted")),
            "ip_shield_deployed": bool(ssh.get("ip_shield_deployed")),
            "domain": ssh.get("domain", ""),
            "domain_tls_deployed": bool(ssh.get("domain_tls_deployed")),
            "ssh_host_key_trusted": bool(ssh.get("host_key_data")),
            "ssh_host_key_fingerprint": ssh.get("host_key_sha256", ""),
        }

    @staticmethod
    def _normalize_duckdns_domain(value: str) -> str:
        domain = (value or "").strip().lower().rstrip(".")
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix) :]
        domain = domain.split("/", 1)[0]
        if not domain:
            return ""
        if not _DUCKDNS_DOMAIN.fullmatch(domain):
            raise ValueError("Domain must be a single *.duckdns.org hostname")
        return domain

    @staticmethod
    def _ip_shield_address(meta: Dict[str, Any]) -> str:
        address = str(meta.get("server_address") or "").strip()
        host, separator, port = address.rpartition(":")
        if not separator or port != "443":
            raise ValueError(
                "IP Shield requires the client endpoint to use public IPv4 port 443"
            )
        raw_ssh_host = str(meta.get("ssh", {}).get("host") or "").strip()
        ssh_host = (
            require_public_ipv4(raw_ssh_host, label="Stealth VPS")
            if raw_ssh_host
            else ""
        )
        try:
            endpoint_ip = require_public_ipv4(host, label="IP Shield endpoint")
        except ValueError:
            ssh = meta.get("ssh", {})
            if not ssh_host:
                raise ValueError(
                    "Save the Stealth VPS IPv4 address before using a domain endpoint"
                ) from None
            domain = StealthSshMixin._normalize_duckdns_domain(host)
            if domain != ssh.get("domain") or not ssh.get("domain_tls_deployed"):
                raise ValueError(
                    "Domain HTTPS must be configured before using a domain endpoint"
                )
            return ssh_host
        if ipaddress.ip_address(endpoint_ip).version != 4:
            raise ValueError("IP Shield currently requires a public IPv4 address")
        # Client settings are intentionally saved before the Server tab in the
        # setup flow.  Once an SSH VPS has been saved, deployment and enable
        # still require both independently entered addresses to match.
        if ssh_host and endpoint_ip != ssh_host:
            raise ValueError("IP Shield endpoint must match the VPS SSH address")
        return endpoint_ip

    def _connect(self, ssh: Dict[str, Any], force_password: bool = False):
        # ONE clean connection. Do NOT retry: OpenSSH 10's PerSourcePenalties
        # throttles a source IP that opens many connections quickly (it resets the
        # handshake with "Not allowed at this time" → paramiko "EOF during
        # negotiation"), so retrying only deepens the penalty. _friendly_ssh_err()
        # turns that into actionable advice.
        import paramiko

        host = require_public_ipv4(ssh["host"], label="Stealth VPS")
        port = int(ssh["port"])
        key_type = str(ssh.get("host_key_type") or "")
        key_data = str(ssh.get("host_key_data") or "")
        expected_fingerprint = str(ssh.get("host_key_sha256") or "")
        if not (key_type and key_data and expected_fingerprint):
            raise ValueError(
                "SSH host key is not trusted. Click Check SSH, verify the fingerprint, then trust it."
            )
        try:
            pinned_key = paramiko.PKey.from_type_string(
                key_type, base64.b64decode(key_data, validate=True)
            )
        except Exception as exc:
            raise ValueError(
                "Stored SSH host key is invalid; verify and trust the VPS again"
            ) from exc
        if not hmac.compare_digest(
            self._host_key_fingerprint(pinned_key), expected_fingerprint
        ):
            raise ValueError(
                "Stored SSH host key fingerprint is invalid; verify and trust the VPS again"
            )
        c = paramiko.SSHClient()
        c.load_system_host_keys()
        host_key_name = host if port == 22 else f"[{host}]:{port}"
        c.get_host_keys().add(host_key_name, key_type, pinned_key)
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        password: Optional[str] = None
        pkey = None
        if ssh.get("ssh_key_installed") and not force_password:
            try:
                pkey = paramiko.Ed25519Key.from_private_key(
                    io.StringIO(self._secret_read("ssh-private-key"))
                )
            except Exception as exc:
                raise ValueError(
                    "Stored SSH private key is unavailable or invalid"
                ) from exc
        else:
            password = self._ssh_password(ssh)
            if not password:
                raise ValueError("SSH password is not available")
        c.connect(
            host,
            port=port,
            username=ssh["user"],
            password=password,
            pkey=pkey,
            timeout=20,
            banner_timeout=25,
            auth_timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
        return c

    @staticmethod
    def _host_key_fingerprint(key: Any) -> str:
        digest = (
            base64.b64encode(hashlib.sha256(key.asbytes()).digest())
            .decode("ascii")
            .rstrip("=")
        )
        return f"SHA256:{digest}"

    @classmethod
    def _read_remote_host_key(cls, ssh: Dict[str, Any]) -> Dict[str, str]:
        """Read the unauthenticated SSH identity for explicit TOFU confirmation."""
        import paramiko

        host = require_public_ipv4(ssh["host"], label="Stealth VPS")
        sock = socket.create_connection((host, int(ssh["port"])), timeout=20)
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=20)
            key = transport.get_remote_server_key()
            return {
                "key_type": key.get_name(),
                "key_data": key.get_base64(),
                "fingerprint": cls._host_key_fingerprint(key),
            }
        finally:
            transport.close()

    @_deployment_locked("ssh-credential-setup")
    async def trust_ssh_host_key(self, expected_fingerprint: str) -> Dict[str, Any]:
        meta = self._meta()
        ssh = meta["ssh"]
        if not ssh.get("host"):
            return {"success": False, "log": "Set the VPS host first."}

        def _do() -> Dict[str, Any]:
            try:
                observed = self._read_remote_host_key(ssh)
                if not hmac.compare_digest(
                    observed["fingerprint"], expected_fingerprint.strip()
                ):
                    return {
                        "success": False,
                        "log": "SSH host key changed before confirmation. Do not trust it; check the VPS console.",
                    }
                current = self._meta()
                current_ssh = current["ssh"]
                same_endpoint = current_ssh.get("host") == ssh.get("host") and int(
                    current_ssh.get("port") or 22
                ) == int(ssh.get("port") or 22)
                if not same_endpoint:
                    return {
                        "success": False,
                        "log": "SSH host or port changed before confirmation.",
                    }
                current_ssh["host_key_type"] = observed["key_type"]
                current_ssh["host_key_data"] = observed["key_data"]
                current_ssh["host_key_sha256"] = observed["fingerprint"]
                self._save_meta(current)
                try:
                    secured = self._ensure_secure_credentials()
                except Exception as exc:  # noqa: BLE001
                    message = f"SSH credential setup failed: {exc}{_friendly_ssh_err(str(exc))}"
                    return {
                        "success": False,
                        "host_key_trusted": True,
                        "credentials_ready": False,
                        "error": message,
                        "log": f"Trusted SSH host key {observed['fingerprint']}.\n{message}",
                    }
                if not secured.get("success"):
                    message = str(secured.get("log") or "SSH credential setup failed.")
                    return {
                        "success": False,
                        "host_key_trusted": True,
                        "credentials_ready": False,
                        "error": message,
                        "log": f"Trusted SSH host key {observed['fingerprint']}.\n{message}",
                    }
                return {
                    "success": True,
                    "host_key_trusted": True,
                    "credentials_ready": True,
                    "log": f"Trusted SSH host key {observed['fingerprint']}.\n{secured['log']}",
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "success": False,
                    "log": f"Host-key check failed: {exc}{_friendly_ssh_err(str(exc))}",
                }

        return await asyncio.to_thread(_do)

    @_deployment_locked("ssh-credential-check")
    async def check_ssh(self) -> Dict[str, Any]:
        meta = self._meta()
        ssh = meta["ssh"]
        if not (ssh["host"] and self._has_ssh_auth(ssh)):
            return {
                "success": False,
                "log": "Set the VPS host + SSH credentials first.",
            }

        def _do() -> Dict[str, Any]:
            try:
                if not ssh.get("host_key_data"):
                    observed = self._read_remote_host_key(ssh)
                    return {
                        "success": False,
                        "needs_trust": True,
                        "fingerprint": observed["fingerprint"],
                        "key_type": observed["key_type"],
                        "log": (
                            "SSH host identity confirmation required.\n"
                            f"Server: {ssh['host']}:{ssh['port']}\n"
                            f"Fingerprint: {observed['fingerprint']}\n"
                            "No SSH credentials were sent. Compare this fingerprint with the one shown by your VPS provider, then click Trust host key."
                        ),
                    }
                secured = self._ensure_secure_credentials()
                if not secured.get("success"):
                    return secured
                return {
                    "success": True,
                    "log": f"SSH OK to {ssh['user']}@{ssh['host']}:{ssh['port']}\n{secured['log']}",
                }
            except Exception as e:  # noqa: BLE001
                return {
                    "success": False,
                    "log": f"SSH failed: {e}{_friendly_ssh_err(str(e))}",
                }

        return await asyncio.to_thread(_do)
