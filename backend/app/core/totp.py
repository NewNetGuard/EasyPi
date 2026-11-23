"""Two-Factor Authentication (TOTP) utilities."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import secrets
import struct
import time
from typing import List, Tuple

import qrcode
from passlib.context import CryptContext

# For hashing backup codes
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate_totp_secret() -> str:
    """Generate a random TOTP secret (base32 encoded)."""
    # Generate 20 random bytes and encode as base32
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')


def get_totp_uri(secret: str, username: str, issuer: str = "EasyPi") -> str:
    """Generate TOTP URI for QR code."""
    # Pad secret to proper base32 length
    padded_secret = secret + '=' * ((8 - len(secret) % 8) % 8)
    return f"otpauth://totp/{issuer}:{username}?secret={padded_secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def generate_qr_code(uri: str) -> str:
    """Generate QR code as base64 PNG."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode('utf-8')


def _hotp(secret: str, counter: int) -> str:
    """Generate HOTP code."""
    # Pad secret
    padded_secret = secret + '=' * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret.upper())
    
    # Pack counter as big-endian 8-byte integer
    msg = struct.pack('>Q', counter)
    
    # HMAC-SHA1
    h = hmac.new(key, msg, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset + 4])[0]
    code = (code & 0x7FFFFFFF) % 1000000
    
    return str(code).zfill(6)


def generate_totp(secret: str, time_step: int = 30) -> str:
    """Generate current TOTP code."""
    counter = int(time.time()) // time_step
    return _hotp(secret, counter)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance.
    
    Args:
        secret: TOTP secret
        code: 6-digit code to verify
        window: Number of time steps to check before/after current
        
    Returns:
        True if code is valid
    """
    if not code or len(code) != 6 or not code.isdigit():
        return False
    
    current_counter = int(time.time()) // 30
    
    # Check current and adjacent time windows
    for i in range(-window, window + 1):
        if _hotp(secret, current_counter + i) == code:
            return True
    
    return False


def generate_backup_codes(count: int = 10) -> Tuple[List[str], List[str]]:
    """
    Generate backup codes for 2FA recovery.
    
    Returns:
        Tuple of (plain_codes for user, hashed_codes for storage)
    """
    plain_codes = []
    hashed_codes = []
    
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        formatted = f"{code[:4]}-{code[4:]}"
        plain_codes.append(formatted)
        hashed_codes.append(pwd_context.hash(formatted))
    
    return plain_codes, hashed_codes


def verify_backup_code(code: str, hashed_codes_json: str) -> Tuple[bool, str]:
    """
    Verify a backup code and return updated hashed codes (with used code removed).
    
    Returns:
        Tuple of (is_valid, updated_hashed_codes_json)
    """
    if not hashed_codes_json:
        return False, hashed_codes_json
    
    try:
        hashed_codes = json.loads(hashed_codes_json)
    except json.JSONDecodeError:
        return False, hashed_codes_json
    
    # Normalize code format
    code = code.upper().replace(' ', '').replace('-', '')
    if len(code) == 8:
        code = f"{code[:4]}-{code[4:]}"
    
    for i, hashed in enumerate(hashed_codes):
        if pwd_context.verify(code, hashed):
            # Remove used code
            hashed_codes.pop(i)
            return True, json.dumps(hashed_codes)
    
    return False, hashed_codes_json


def hash_backup_codes(codes: List[str]) -> str:
    """Hash backup codes and return as JSON string."""
    hashed = [pwd_context.hash(code) for code in codes]
    return json.dumps(hashed)
