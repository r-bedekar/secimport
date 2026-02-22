"""
Hostname, IP address, and MAC address normalization.

Ensures consistent formatting for correlation and deduplication
across multiple security sources.
"""

import ipaddress
import re
from typing import Optional

# Domain suffixes commonly appended by internal DNS
_INTERNAL_SUFFIXES = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".home",
    ".localdomain",
    ".ad",
    ".domain",
)


def normalize_hostname(value: Optional[str], strip_domain: bool = True) -> Optional[str]:
    """
    Normalize a hostname for consistent matching.

    - Lowercases
    - Strips leading/trailing whitespace
    - Optionally strips common internal domain suffixes

    Args:
        value: Raw hostname string.
        strip_domain: If True, remove known internal suffixes.

    Returns:
        Normalized hostname, or None if input is empty.

    Examples:
        >>> normalize_hostname("WEB01.Corp.LOCAL")
        'web01'
        >>> normalize_hostname("  DB-Server.internal  ")
        'db-server'
        >>> normalize_hostname("app01.prod.example.com", strip_domain=False)
        'app01.prod.example.com'
    """
    if not value or not value.strip():
        return None

    result = value.strip().lower()

    if strip_domain:
        for suffix in _INTERNAL_SUFFIXES:
            if result.endswith(suffix):
                result = result[: -len(suffix)]
                break

    return result or None


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """
    Normalize an IP address.

    - Strips whitespace
    - Validates IPv4/IPv6 format
    - Returns the compact string representation

    Args:
        value: Raw IP address string.

    Returns:
        Normalized IP string, or None if invalid/empty.

    Examples:
        >>> normalize_ip("  10.0.0.1  ")
        '10.0.0.1'
        >>> normalize_ip("::ffff:192.168.1.1")
        '::ffff:c0a8:101'
        >>> normalize_ip("not-an-ip")
    """
    if not value or not value.strip():
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_mac(value: Optional[str]) -> Optional[str]:
    """
    Normalize a MAC address to lowercase colon-separated format.

    Accepts common formats:
    - ``AA:BB:CC:DD:EE:FF``
    - ``AA-BB-CC-DD-EE-FF``
    - ``AABB.CCDD.EEFF`` (Cisco)
    - ``AABBCCDDEEFF``

    Args:
        value: Raw MAC address string.

    Returns:
        Normalized MAC in ``aa:bb:cc:dd:ee:ff`` format, or None if invalid.

    Examples:
        >>> normalize_mac("AA-BB-CC-DD-EE-FF")
        'aa:bb:cc:dd:ee:ff'
        >>> normalize_mac("AABB.CCDD.EEFF")
        'aa:bb:cc:dd:ee:ff'
    """
    if not value or not value.strip():
        return None

    # Remove all separators to get raw hex
    raw = re.sub(r"[:\-.]", "", value.strip().lower())

    if len(raw) != 12 or not re.fullmatch(r"[0-9a-f]{12}", raw):
        return None

    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))
