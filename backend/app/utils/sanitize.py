"""
Sanitization utilities for safe data handling.

These functions should be used throughout the application to sanitize
any data that comes from external sources (user input, database, files, network).

Security principle: Never trust external data.
"""

import re
import ipaddress
from typing import Optional


def sanitize_domain(domain: Optional[str], max_length: int = 253) -> str:
    """
    Sanitize domain name for safe display.
    
    Only allows: a-z, A-Z, 0-9, dots, hyphens, underscores
    Max length: 253 characters (DNS limit)
    """
    if not domain or not isinstance(domain, str):
        return "unknown"
    # Only allow valid domain characters
    return ''.join(c for c in domain if c.isalnum() or c in '.-_')[:max_length]


def sanitize_ip(ip: Optional[str]) -> str:
    """
    Sanitize and validate IP address (IPv4 or IPv6).
    
    Returns canonical form or "unknown" if invalid.
    """
    if not ip or not isinstance(ip, str):
        return "unknown"
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return "unknown"


def validate_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def sanitize_hostname(hostname: Optional[str], max_length: int = 253) -> str:
    """
    Sanitize hostname for safe display.
    
    Only allows: a-z, A-Z, 0-9, dots, hyphens
    """
    if not hostname or not isinstance(hostname, str):
        return ""
    return ''.join(c for c in hostname if c.isalnum() or c in '.-')[:max_length]


def sanitize_name(name: Optional[str], max_length: int = 64) -> str:
    """
    Sanitize device/client/user name for safe display.
    
    Only allows: a-z, A-Z, 0-9, spaces, hyphens, underscores, dots
    """
    if not name or not isinstance(name, str):
        return ""
    return ''.join(c for c in name if c.isalnum() or c in ' -_.')[:max_length]


def sanitize_query_type(qtype: Optional[str]) -> str:
    """
    Sanitize DNS query type.
    
    Only allows known DNS record types.
    """
    if not qtype or not isinstance(qtype, str):
        return "A"
    
    valid_types = {
        'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT',
        'CAA', 'DNSKEY', 'DS', 'HTTPS', 'SVCB', 'NAPTR', 'SPF', 'TLSA'
    }
    qtype_upper = qtype.upper().strip()[:10]
    return qtype_upper if qtype_upper in valid_types else "A"


def sanitize_reason(reason: Optional[str], max_length: int = 100) -> str:
    """
    Sanitize block/filter reason for safe display.
    
    Only allows: a-z, A-Z, 0-9, spaces, hyphens, underscores, dots
    """
    if not reason or not isinstance(reason, str):
        return ""
    return ''.join(c for c in reason if c.isalnum() or c in ' -_.')[:max_length]


def sanitize_email(email: Optional[str], max_length: int = 254) -> str:
    """
    Sanitize email address.
    
    Only allows: a-z, A-Z, 0-9, @, dots, hyphens, underscores, plus
    """
    if not email or not isinstance(email, str):
        return ""
    # Basic email character whitelist
    sanitized = ''.join(c for c in email if c.isalnum() or c in '@.-_+')[:max_length]
    # Basic format check
    if '@' not in sanitized or '.' not in sanitized.split('@')[-1]:
        return ""
    return sanitized


def sanitize_path(path: Optional[str], max_length: int = 500) -> str:
    """
    Sanitize file path - prevent directory traversal.
    
    Removes: .., //, backslashes, null bytes
    """
    if not path or not isinstance(path, str):
        return ""
    # Remove dangerous patterns
    sanitized = path.replace('..', '').replace('//', '/').replace('\\', '/').replace('\x00', '')
    # Only allow safe characters
    return ''.join(c for c in sanitized if c.isalnum() or c in '/-_.')[:max_length]


def sanitize_url(url: Optional[str], max_length: int = 2048) -> str:
    """
    Sanitize URL for safe use.
    
    Only allows http/https schemes, standard URL characters.
    """
    if not url or not isinstance(url, str):
        return ""
    
    url = url.strip()[:max_length]
    
    # Must start with http:// or https://
    if not url.startswith(('http://', 'https://')):
        return ""
    
    # Check for dangerous patterns
    dangerous = ['javascript:', 'data:', 'vbscript:', '<', '>', '"', "'"]
    for pattern in dangerous:
        if pattern in url.lower():
            return ""
    
    return url


def sanitize_mac(mac: Optional[str]) -> str:
    """
    Sanitize and normalize MAC address.
    
    Returns format: AA:BB:CC:DD:EE:FF or empty string if invalid.
    """
    if not mac or not isinstance(mac, str):
        return ""
    
    # Remove common separators and convert to uppercase
    clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    
    # Must be exactly 12 hex characters
    if len(clean) != 12 or not all(c in '0123456789ABCDEF' for c in clean):
        return ""
    
    # Format as AA:BB:CC:DD:EE:FF
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def sanitize_integer(value: any, min_val: int = 0, max_val: int = 2147483647, default: int = 0) -> int:
    """
    Sanitize integer value within bounds.
    """
    try:
        val = int(value)
        return max(min_val, min(val, max_val))
    except (ValueError, TypeError):
        return default


def sanitize_html(text: Optional[str], max_length: int = 10000) -> str:
    """
    Remove HTML tags from text.
    
    For displaying user-provided text safely.
    """
    if not text or not isinstance(text, str):
        return ""
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', '', text)
    return clean[:max_length]


def escape_html(text: Optional[str]) -> str:
    """
    Escape HTML special characters.
    
    Converts < > & " ' to HTML entities.
    """
    if not text or not isinstance(text, str):
        return ""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#x27;'))
