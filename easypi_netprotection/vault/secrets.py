from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..config import get_settings


class SecretsVault:
    """Secure storage for sensitive configuration data."""
    
    def __init__(self, key_path: Path | str | None = None):
        settings = get_settings()
        data_dir = settings.vault.db_path.parent
        self.key_path = Path(key_path) if key_path else data_dir / ".vault_key"
        self.secrets_path = data_dir / "secrets.enc"
        self._fernet: Fernet | None = None
        self._ensure_key()
    
    def _ensure_key(self) -> None:
        """Ensure encryption key exists."""
        if not self.key_path.exists():
            self._generate_key()
        self._load_key()
    
    def _generate_key(self) -> None:
        """Generate a new encryption key."""
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        
        # Write with restrictive permissions
        self.key_path.write_bytes(key)
        try:
            os.chmod(self.key_path, 0o600)
        except (OSError, AttributeError):
            # Windows doesn't support chmod the same way
            pass
    
    def _load_key(self) -> None:
        """Load the encryption key."""
        key = self.key_path.read_bytes().strip()
        self._fernet = Fernet(key)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt(self, data: str | bytes) -> bytes:
        """Encrypt data."""
        if self._fernet is None:
            raise RuntimeError("Vault not initialized")
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        return self._fernet.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data."""
        if self._fernet is None:
            raise RuntimeError("Vault not initialized")
        
        try:
            return self._fernet.decrypt(encrypted_data)
        except InvalidToken:
            raise ValueError("Failed to decrypt: invalid key or corrupted data")
    
    def encrypt_json(self, data: dict | list) -> bytes:
        """Encrypt JSON-serializable data."""
        json_str = json.dumps(data, separators=(",", ":"))
        return self.encrypt(json_str)
    
    def decrypt_json(self, encrypted_data: bytes) -> dict | list:
        """Decrypt and parse JSON data."""
        decrypted = self.decrypt(encrypted_data)
        return json.loads(decrypted.decode("utf-8"))
    
    def store_secret(self, key: str, value: Any) -> None:
        """Store a secret in the encrypted secrets file."""
        secrets_data = self._load_secrets()
        secrets_data[key] = value
        self._save_secrets(secrets_data)
    
    def get_secret(self, key: str, default: Any = None) -> Any:
        """Retrieve a secret from the encrypted secrets file."""
        secrets_data = self._load_secrets()
        return secrets_data.get(key, default)
    
    def delete_secret(self, key: str) -> bool:
        """Delete a secret from the encrypted secrets file."""
        secrets_data = self._load_secrets()
        if key in secrets_data:
            del secrets_data[key]
            self._save_secrets(secrets_data)
            return True
        return False
    
    def list_secrets(self) -> list[str]:
        """List all secret keys (not values)."""
        secrets_data = self._load_secrets()
        return list(secrets_data.keys())
    
    def _load_secrets(self) -> dict:
        """Load all secrets from encrypted file."""
        if not self.secrets_path.exists():
            return {}
        
        try:
            encrypted = self.secrets_path.read_bytes()
            return self.decrypt_json(encrypted)
        except (ValueError, json.JSONDecodeError):
            return {}
    
    def _save_secrets(self, data: dict) -> None:
        """Save secrets to encrypted file."""
        encrypted = self.encrypt_json(data)
        self.secrets_path.parent.mkdir(parents=True, exist_ok=True)
        self.secrets_path.write_bytes(encrypted)
        try:
            os.chmod(self.secrets_path, 0o600)
        except (OSError, AttributeError):
            pass
    
    def rotate_key(self) -> None:
        """Rotate the encryption key while preserving secrets."""
        # Load existing secrets with old key
        secrets_data = self._load_secrets()
        
        # Generate new key
        self._generate_key()
        self._load_key()
        
        # Re-encrypt secrets with new key
        if secrets_data:
            self._save_secrets(secrets_data)


class IPAnonymizer:
    """Utility for anonymizing IP addresses."""
    
    def __init__(self, salt: str | None = None):
        settings = get_settings()
        self.salt = (salt or settings.chronicle.hash_salt).encode("utf-8")
        self.ipv6_prefix_length = settings.chronicle.anonymize_ipv6_prefix
    
    def hash_ipv4(self, ip: str) -> str:
        """Hash an IPv4 address with salt."""
        data = self.salt + ip.encode("utf-8")
        hash_bytes = hashlib.sha256(data).digest()
        return base64.urlsafe_b64encode(hash_bytes[:12]).decode("ascii")
    
    def anonymize_ipv6(self, ip: str) -> str:
        """Anonymize IPv6 by truncating to configured prefix."""
        import ipaddress
        
        try:
            addr = ipaddress.IPv6Address(ip)
            # Create network with configured prefix length
            network = ipaddress.IPv6Network(
                (addr, self.ipv6_prefix_length),
                strict=False,
            )
            # Return network address (zeroed suffix)
            return str(network.network_address)
        except ipaddress.AddressValueError:
            return self.hash_ipv4(ip)  # Fallback to hash
    
    def anonymize(self, ip: str) -> str:
        """Anonymize any IP address."""
        if ":" in ip:
            return self.anonymize_ipv6(ip)
        else:
            return self.hash_ipv4(ip)


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate an API key for external access."""
    return f"np_{secrets.token_urlsafe(32)}"


def hash_password(password: str) -> str:
    """Hash a password using SHA256 with salt."""
    salt = secrets.token_bytes(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=480000,
    )
    return base64.b64encode(salt + hash_bytes).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    try:
        decoded = base64.b64decode(hashed.encode("ascii"))
        salt = decoded[:16]
        stored_hash = decoded[16:]
        
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=480000,
        )
        return secrets.compare_digest(stored_hash, computed_hash)
    except Exception:
        return False


# Singleton instance
_vault: SecretsVault | None = None


def get_vault() -> SecretsVault:
    """Get cached vault instance."""
    global _vault
    if _vault is None:
        _vault = SecretsVault()
    return _vault


def get_anonymizer() -> IPAnonymizer:
    """Get a new IP anonymizer instance."""
    return IPAnonymizer()
