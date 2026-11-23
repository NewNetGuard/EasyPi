"""
Terminal Security Module

Provides hardened security for terminal WebSocket access:
- IP binding for tokens (token stolen = useless without same IP)
- User-Agent binding (browser fingerprint)
- Session limits (max 2 per user, 10 total)
- Auto IP blocking after failed attempts
- Private network restriction
- Shorter token lifetime (20s)
"""

import time
import hashlib
import logging
import os
import json
from pathlib import Path
from typing import Optional, Dict, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)

# ============== Security Configuration ==============

# Maximum concurrent terminal sessions per user
MAX_TERMINAL_SESSIONS_PER_USER = 2

# Maximum total concurrent terminal sessions
MAX_TOTAL_TERMINAL_SESSIONS = 10

# WS Token lifetime (seconds) - shorter = more secure
WS_TOKEN_LIFETIME = 20  # 20 seconds

# IP whitelist for terminal access (empty = allow all private IPs by default)
# Add specific IPs here for extra restriction, e.g.: {"192.168.1.100", "192.168.1.101"}
TERMINAL_IP_WHITELIST: Set[str] = set()

# Optional CIDR ranges allowed in addition to private IPs (comma-separated)
# Example to allow Tailscale: EASYPI_TERMINAL_ALLOWED_CIDRS="100.64.0.0/10"
_raw_cidrs = os.environ.get("EASYPI_TERMINAL_ALLOWED_CIDRS", "").strip()
TERMINAL_ALLOWED_CIDRS: Set[str] = set()
if _raw_cidrs:
    for cidr in _raw_cidrs.split(","):
        cidr = cidr.strip()
        if cidr:
            TERMINAL_ALLOWED_CIDRS.add(cidr)

# Tailscale IPv4 range (CGNAT). Enabled automatically when Tailscale remote access is on.
TAILSCALE_ALLOWED_CIDRS: Set[str] = {"100.64.0.0/10"}
_TAILSCALE_STATE_CACHE: dict[str, float | bool] = {
    "enabled": False,
    "expires_at": 0.0,
}
_TAILSCALE_STATE_TTL_SECONDS = 30


def _tailscale_enabled() -> bool:
    """Check if Tailscale remote access is enabled (cached)."""
    now = time.time()
    if _TAILSCALE_STATE_CACHE["expires_at"] > now:
        return bool(_TAILSCALE_STATE_CACHE["enabled"])

    enabled = False
    try:
        from app.core.paths import get_data_dir
        data_dir = os.environ.get("EASYPI_DATA_DIR")
        if data_dir:
            state_path = Path(data_dir) / "tailscale_state.json"
        else:
            state_path = get_data_dir() / "tailscale_state.json"
        if state_path.exists():
            state = json.loads(state_path.read_text())
            enabled = bool(state.get("enabled"))
    except Exception:
        enabled = False

    _TAILSCALE_STATE_CACHE["enabled"] = enabled
    _TAILSCALE_STATE_CACHE["expires_at"] = now + _TAILSCALE_STATE_TTL_SECONDS
    return enabled

# Dangerous command patterns to log (not block - admin should have freedom)
DANGEROUS_COMMANDS = [
    'rm -rf /',
    'rm -rf /*',
    'mkfs.',
    ':(){ :|:& };:',
    'dd if=/dev/zero of=/dev/sd',
    'chmod -R 777 /',
    '> /dev/sda',
    'mv /* /dev/null',
]


@dataclass
class TerminalToken:
    """Secure terminal token with IP and User-Agent binding"""
    user_id: int
    username: str
    client_ip: str
    user_agent_hash: str
    created_at: float
    expires_at: float
    session_fingerprint: str
    session_jti: str
    
    def is_valid(self, client_ip: str, user_agent: str) -> Tuple[bool, str]:
        """Validate token with IP and user agent binding"""
        now = time.time()
        
        # Check expiration
        if now >= self.expires_at:
            return False, "Token expired"
        
        # CRITICAL: Check IP binding - token is useless if stolen
        if client_ip != self.client_ip:
            logger.warning(
                f"SECURITY: Terminal token IP mismatch for user {self.username}: "
                f"token_ip={self.client_ip}, request_ip={client_ip}"
            )
            return False, "IP address mismatch - token bound to different IP"
        
        # Check user agent binding (prevents token reuse from different browser)
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        if ua_hash != self.user_agent_hash:
            logger.warning(
                f"SECURITY: Terminal token UA mismatch for user {self.username} from {client_ip}"
            )
            return False, "Browser fingerprint mismatch"
        
        return True, "Valid"


class TerminalSecurityManager:
    """Centralized terminal security management with auto-blocking"""
    
    def __init__(self):
        # Token storage: token_str -> TerminalToken
        self._tokens: Dict[str, TerminalToken] = {}
        
        # Active sessions: user_id -> set of session_ids
        self._active_sessions: Dict[int, Set[str]] = defaultdict(set)
        
        # Failed attempts tracking: ip -> (count, first_attempt_time)
        self._failed_attempts: Dict[str, Tuple[int, float]] = {}
        
        # Auto-blocked IPs: ip -> block_until_timestamp
        self._blocked_ips: Dict[str, float] = {}
        
    def cleanup(self):
        """Remove expired tokens and unblock IPs"""
        now = time.time()
        
        # Cleanup expired tokens
        expired = [k for k, v in self._tokens.items() if v.expires_at < now]
        for k in expired:
            del self._tokens[k]
        
        # Cleanup expired IP blocks
        unblock = [ip for ip, until in self._blocked_ips.items() if until < now]
        for ip in unblock:
            del self._blocked_ips[ip]
            logger.info(f"Auto-unblocked IP {ip} from terminal access")
        
        # Cleanup old failed attempts (older than 1 hour)
        old_attempts = [
            ip for ip, (_, first_time) in self._failed_attempts.items() 
            if now - first_time > 3600
        ]
        for ip in old_attempts:
            del self._failed_attempts[ip]
    
    def is_ip_allowed(self, client_ip: str) -> Tuple[bool, str]:
        """Check if IP is allowed for terminal access"""
        self.cleanup()
        
        # Check if IP is auto-blocked due to suspicious activity
        if client_ip in self._blocked_ips:
            block_until = self._blocked_ips[client_ip]
            remaining = int(block_until - time.time())
            logger.warning(f"Blocked IP {client_ip} attempted terminal access")
            return False, f"IP temporarily blocked ({remaining}s remaining)"
        
        # Check whitelist if configured
        if TERMINAL_IP_WHITELIST:
            if client_ip not in TERMINAL_IP_WHITELIST:
                logger.warning(f"Terminal access denied - IP {client_ip} not in whitelist")
                return False, "IP not in terminal access whitelist"
        else:
            # Default: only allow private/local IPs
            if not self._is_private_ip(client_ip):
                logger.warning(f"SECURITY: Terminal access from PUBLIC IP denied: {client_ip}")
                return False, "Terminal access restricted to private network"
        
        return True, "Allowed"
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local or explicitly allowed by CIDR."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return True
            allowed_cidrs = set(TERMINAL_ALLOWED_CIDRS)
            if _tailscale_enabled():
                allowed_cidrs.update(TAILSCALE_ALLOWED_CIDRS)
            for cidr in allowed_cidrs:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    logger.warning("Invalid CIDR in EASYPI_TERMINAL_ALLOWED_CIDRS: %s", cidr)
            return False
        except Exception:
            # If can't parse, deny by default
            return False
    
    def can_create_session(self, user_id: int) -> Tuple[bool, str]:
        """Check if user can create new terminal session"""
        self.cleanup()
        
        # Check per-user limit
        user_sessions = len(self._active_sessions.get(user_id, set()))
        if user_sessions >= MAX_TERMINAL_SESSIONS_PER_USER:
            logger.warning(f"User {user_id} hit terminal session limit ({user_sessions})")
            return False, f"Maximum {MAX_TERMINAL_SESSIONS_PER_USER} concurrent terminals per user"
        
        # Check total system limit
        total_sessions = sum(len(s) for s in self._active_sessions.values())
        if total_sessions >= MAX_TOTAL_TERMINAL_SESSIONS:
            logger.warning(f"System terminal session limit reached ({total_sessions})")
            return False, "System terminal session limit reached"
        
        return True, "Allowed"

    def try_register_session(self, user_id: int, session_id: str) -> Tuple[bool, str]:
        """Atomically enforce session limits and reserve one session slot."""
        self.cleanup()
        user_sessions = self._active_sessions.get(user_id, set())
        if len(user_sessions) >= MAX_TERMINAL_SESSIONS_PER_USER:
            return False, f"Maximum {MAX_TERMINAL_SESSIONS_PER_USER} concurrent terminals per user"
        total_sessions = sum(len(sessions) for sessions in self._active_sessions.values())
        if total_sessions >= MAX_TOTAL_TERMINAL_SESSIONS:
            return False, "System terminal session limit reached"
        self._active_sessions[user_id].add(session_id)
        return True, "Allowed"
    
    def create_token(
        self,
        token_str: str,
        user_id: int,
        username: str,
        client_ip: str,
        user_agent: str,
        session_jti: str,
    ) -> TerminalToken:
        """Create a new secure terminal token bound to IP and User-Agent"""
        now = time.time()
        
        # Create unique session fingerprint
        fingerprint = hashlib.sha256(
            f"{user_id}:{client_ip}:{user_agent}:{now}".encode()
        ).hexdigest()[:16]
        
        # Hash user agent (not stored in plain text)
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        
        token = TerminalToken(
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            user_agent_hash=ua_hash,
            created_at=now,
            expires_at=now + WS_TOKEN_LIFETIME,
            session_fingerprint=fingerprint,
            session_jti=session_jti,
        )
        
        self._tokens[token_str] = token
        self.cleanup()
        
        logger.info(
            f"Terminal token created: user={username}, ip={client_ip}, "
            f"expires_in={WS_TOKEN_LIFETIME}s"
        )
        
        return token
    
    def verify_and_consume_token(
        self,
        token_str: str,
        client_ip: str,
        user_agent: str,
    ) -> Tuple[Optional[TerminalToken], str]:
        """Verify token and consume it (single-use). Returns (token, reason)"""
        self.cleanup()
        
        # Token not found
        if token_str not in self._tokens:
            self._record_failed_attempt(client_ip)
            return None, "Invalid or expired token"
        
        token = self._tokens[token_str]
        
        # ALWAYS delete token first (single-use, even if validation fails)
        del self._tokens[token_str]
        
        # Validate token bindings
        valid, reason = token.is_valid(client_ip, user_agent)
        if not valid:
            self._record_failed_attempt(client_ip)
            return None, reason
        
        return token, "Valid"
    
    def _record_failed_attempt(self, client_ip: str):
        """Record failed token verification - auto-block after threshold"""
        now = time.time()
        
        if client_ip in self._failed_attempts:
            count, first_time = self._failed_attempts[client_ip]
            count += 1
            self._failed_attempts[client_ip] = (count, first_time)
            
            # Auto-block after 5 failed attempts within 10 minutes
            if count >= 5 and (now - first_time) < 600:
                # Progressive blocking: 1min, 2min, 3min... up to 1 hour max
                block_duration = min(count * 60, 3600)
                self._blocked_ips[client_ip] = now + block_duration
                logger.warning(
                    f"SECURITY: Auto-blocked IP {client_ip} from terminal "
                    f"for {block_duration}s after {count} failed attempts"
                )
        else:
            self._failed_attempts[client_ip] = (1, now)

    def record_failed_attempt(self, client_ip: str):
        """Public wrapper to record a failed attempt."""
        self._record_failed_attempt(client_ip)
    
    def register_session(self, user_id: int, session_id: str):
        """Register an active terminal session"""
        self._active_sessions[user_id].add(session_id)
        total = sum(len(s) for s in self._active_sessions.values())
        logger.info(
            f"Terminal session registered: user={user_id}, session={session_id}, "
            f"total_active={total}"
        )
    
    def unregister_session(self, user_id: int, session_id: str):
        """Unregister terminal session on disconnect"""
        if user_id in self._active_sessions:
            self._active_sessions[user_id].discard(session_id)
            if not self._active_sessions[user_id]:
                del self._active_sessions[user_id]
        logger.info(f"Terminal session unregistered: user={user_id}, session={session_id}")
    
    def get_active_session_count(self, user_id: int) -> int:
        """Get number of active sessions for user"""
        return len(self._active_sessions.get(user_id, set()))
    
    def get_stats(self) -> dict:
        """Get security statistics for monitoring"""
        return {
            "pending_tokens": len(self._tokens),
            "active_sessions": sum(len(s) for s in self._active_sessions.values()),
            "sessions_by_user": {
                uid: len(sessions) 
                for uid, sessions in self._active_sessions.items()
            },
            "blocked_ips": list(self._blocked_ips.keys()),
            "failed_attempt_ips": list(self._failed_attempts.keys()),
        }
    
    def force_block_ip(self, ip: str, duration_seconds: int = 3600):
        """Manually block an IP from terminal access"""
        self._blocked_ips[ip] = time.time() + duration_seconds
        logger.warning(f"Manually blocked IP {ip} from terminal for {duration_seconds}s")
    
    def unblock_ip(self, ip: str):
        """Manually unblock an IP"""
        if ip in self._blocked_ips:
            del self._blocked_ips[ip]
            logger.info(f"Manually unblocked IP {ip} from terminal")


# Global singleton instance
terminal_security = TerminalSecurityManager()


def check_dangerous_command(command: str) -> Tuple[bool, str]:
    """
    Check if command matches dangerous patterns.
    Returns (is_dangerous, pattern_matched)
    
    Note: This only LOGS, doesn't block. Admin should have full access.
    """
    cmd_lower = command.lower().strip()
    
    for pattern in DANGEROUS_COMMANDS:
        if pattern.lower() in cmd_lower:
            logger.warning("Dangerous terminal command pattern detected: %s", pattern)
            return True, pattern
    
    return False, ""
