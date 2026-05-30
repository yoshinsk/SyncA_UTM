"""Strict input validators. Reject anything that doesn't conform."""
from __future__ import annotations

import ipaddress
import re

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
INTERFACE_RE = re.compile(r"^[a-z0-9][a-z0-9\-_.@]{0,14}$", re.IGNORECASE)
IDENTIFIER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$")
COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
SIZE_RE = re.compile(r"^\d+[kKmMgG]?$")


class ValidationError(ValueError):
    pass


def validate_ipv4(value: str) -> str:
    try:
        ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError) as e:
        raise ValidationError(f"invalid IPv4: {value!r}") from e
    return value


def validate_ipv4_cidr(value: str) -> str:
    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError as e:
        raise ValidationError(f"invalid IPv4 CIDR: {value!r}") from e
    return value


def validate_hostname(value: str) -> str:
    if not isinstance(value, str) or not HOSTNAME_RE.match(value):
        raise ValidationError(f"invalid hostname: {value!r}")
    return value.lower()


def validate_hostname_or_ip(value: str) -> str:
    try:
        return validate_hostname(value)
    except ValidationError:
        return validate_ipv4(value)


def validate_mac(value: str) -> str:
    if not isinstance(value, str) or not MAC_RE.match(value):
        raise ValidationError(f"invalid MAC: {value!r}")
    return value.lower()


def validate_port(value) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError) as e:
        raise ValidationError(f"invalid port: {value!r}") from e
    if not (1 <= p <= 65535):
        raise ValidationError(f"port out of range: {p}")
    return p


def validate_identifier(value: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.match(value):
        raise ValidationError(f"invalid identifier: {value!r}")
    return value


def validate_country_code(value: str) -> str:
    if not isinstance(value, str) or not COUNTRY_CODE_RE.match(value):
        raise ValidationError(f"invalid country code: {value!r} (expected ISO-3166 alpha-2 uppercase)")
    return value


def validate_interface(value: str) -> str:
    if not isinstance(value, str) or not INTERFACE_RE.match(value):
        raise ValidationError(f"invalid interface name: {value!r}")
    return value


def validate_size(value: str) -> str:
    if not isinstance(value, str) or not SIZE_RE.match(value):
        raise ValidationError(f"invalid size value: {value!r} (e.g. 10m, 1g, 512k)")
    return value
