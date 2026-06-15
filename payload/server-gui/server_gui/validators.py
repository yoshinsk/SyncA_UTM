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
        raise ValidationError(f"IPv4アドレスが不正です: {value!r}") from e
    return value


def validate_ipv4_cidr(value: str) -> str:
    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError as e:
        raise ValidationError(f"IPv4 CIDRが不正です: {value!r}") from e
    return value


def validate_hostname(value: str) -> str:
    if not isinstance(value, str) or not HOSTNAME_RE.match(value):
        raise ValidationError(f"ホスト名が不正です: {value!r}")
    return value.lower()


def validate_hostname_or_ip(value: str) -> str:
    try:
        return validate_hostname(value)
    except ValidationError:
        return validate_ipv4(value)


def validate_mac(value: str) -> str:
    if not isinstance(value, str) or not MAC_RE.match(value):
        raise ValidationError(f"MACアドレスが不正です: {value!r}")
    return value.lower()


def validate_port(value) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError) as e:
        raise ValidationError(f"ポート番号が不正です: {value!r}") from e
    if not (1 <= p <= 65535):
        raise ValidationError(f"ポート番号は1から65535の範囲で指定してください: {p}")
    return p


def validate_identifier(value: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.match(value):
        raise ValidationError(f"識別子が不正です: {value!r}")
    return value


def validate_country_code(value: str) -> str:
    if not isinstance(value, str) or not COUNTRY_CODE_RE.match(value):
        raise ValidationError(f"国コードが不正です: {value!r} (ISO-3166 alpha-2の大文字2文字で指定してください)")
    return value


def validate_interface(value: str) -> str:
    if not isinstance(value, str) or not INTERFACE_RE.match(value):
        raise ValidationError(f"インターフェース名が不正です: {value!r}")
    return value


def validate_size(value: str) -> str:
    if not isinstance(value, str) or not SIZE_RE.match(value):
        raise ValidationError(f"サイズ指定が不正です: {value!r} (例: 10m, 1g, 512k)")
    return value
