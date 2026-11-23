"""Encryption utilities for sensitive data like camera passwords."""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from config import get_settings

settings = get_settings()


def _get_encryption_key() -> bytes:
    """Derive encryption key from SECRET_KEY."""
    # Use SHA256 to derive a 32-byte key from SECRET_KEY
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    # Fernet requires base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key)


def _get_fernet() -> Fernet:
    """Get Fernet instance for encryption/decryption."""
    return Fernet(_get_encryption_key())


def encrypt_password(plain_password: str) -> str:
    """
    Encrypt a password for storage.
    
    Args:
        plain_password: The plain text password
        
    Returns:
        Base64-encoded encrypted password with 'enc:' prefix
    """
    if not plain_password:
        return ""
    
    # Already encrypted
    if plain_password.startswith("enc:"):
        return plain_password
    
    fernet = _get_fernet()
    encrypted = fernet.encrypt(plain_password.encode())
    return f"enc:{encrypted.decode()}"


def decrypt_password(encrypted_password: str) -> str:
    """
    Decrypt a stored password.
    
    Args:
        encrypted_password: The encrypted password (with 'enc:' prefix)
        
    Returns:
        The plain text password
    """
    if not encrypted_password:
        return ""
    
    # Not encrypted (legacy data)
    if not encrypted_password.startswith("enc:"):
        return encrypted_password
    
    try:
        fernet = _get_fernet()
        encrypted_data = encrypted_password[4:]  # Remove 'enc:' prefix
        decrypted = fernet.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except InvalidToken:
        # If decryption fails, return empty (password corrupted)
        return ""
    except Exception:
        return ""


def is_encrypted(password: str) -> bool:
    """Check if password is already encrypted."""
    return password.startswith("enc:") if password else False


def mask_password(password: str) -> str:
    """Return masked password for display."""
    if not password:
        return ""
    return "••••••••"
