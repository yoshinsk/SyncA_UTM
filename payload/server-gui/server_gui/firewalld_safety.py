"""payload/server-gui/server_gui/firewalld_safety.py

Firewalld reload guard for SyncA UTM management access.

The server-gui exposes the management UI on 4444/tcp and commonly uses a
Japan-source allow zone with jp-ipv4. If a later GeoIP refresh or GUI action
reloads firewalld after the allow zone lost its source or management openings,
WAN access can disappear even though the daemon itself reloads successfully.
"""
from __future__ import annotations

from dataclasses import dataclass
import shlex
import subprocess
from typing import Sequence


MANAGEMENT_ZONE = "japan"
MANAGEMENT_IPSET = "jp-ipv4"
MANAGEMENT_SOURCE = f"ipset:{MANAGEMENT_IPSET}"
GUI_PORT = "4444/tcp"
WIREGUARD_PORT = "51820/udp"
MONITOR_SOURCES = ("121.80.1.65/32",)


@dataclass
class FirewalldSafetyResult:
    ok: bool
    output: str = ""


def ensure_before_firewalld_reload() -> FirewalldSafetyResult:
    """Repair the JP management allow zone before a firewalld reload.

    The guard is intentionally narrow: it only acts when the appliance already
    has the jp-ipv4 ipset and a restrictive public zone. It does not loosen a
    normal non-DROP public zone, and it preserves existing public source/rich
    rules such as site-specific IPsec peers.
    """
    state = _run_firewall_cmd(["--state"], timeout=10)
    if state.returncode != 0:
        return FirewalldSafetyResult(True, "firewalld is not running")

    zones = set(_words(["--permanent", "--get-zones"]))
    ipsets = set(_words(["--permanent", "--get-ipsets"]))
    if MANAGEMENT_IPSET not in ipsets:
        return FirewalldSafetyResult(True, f"{MANAGEMENT_IPSET} is not configured")

    public = _zone_details("public")
    public_is_restrictive = public.get("target") == "DROP"
    if not public_is_restrictive:
        return FirewalldSafetyResult(True, "public zone is not DROP")

    changed: list[str] = []
    errors: list[str] = []

    if MANAGEMENT_ZONE not in zones:
        _collect_change(["--permanent", "--new-zone", MANAGEMENT_ZONE], changed, errors)

    _collect_change(["--permanent", "--zone", MANAGEMENT_ZONE, "--set-target=default"], changed, errors)
    _move_source_to_management_zone(changed, errors)

    services = set(_words(["--get-services"]))
    for service in ("ssh", "ipsec", "wireguard"):
        if service in services:
            _collect_change(
                ["--permanent", "--zone", MANAGEMENT_ZONE, "--add-service", service],
                changed,
                errors,
            )

    for port in (GUI_PORT, WIREGUARD_PORT):
        _collect_change(["--permanent", "--zone", MANAGEMENT_ZONE, "--add-port", port], changed, errors)

    for source in MONITOR_SOURCES:
        _collect_change(
            [
                "--permanent",
                "--zone",
                MANAGEMENT_ZONE,
                "--add-rich-rule",
                f'rule family="ipv4" source address="{source}" protocol value="icmp" accept',
            ],
            changed,
            errors,
        )

    if errors:
        return FirewalldSafetyResult(False, "\n".join(errors))
    return FirewalldSafetyResult(True, "\n".join(changed))


def _move_source_to_management_zone(changed: list[str], errors: list[str]) -> None:
    """Ensure ipset:jp-ipv4 is not assigned to a conflicting zone."""
    for zone in _words(["--permanent", "--get-zones"]):
        if zone == MANAGEMENT_ZONE:
            continue
        sources = set(_words(["--permanent", "--zone", zone, "--list-sources"]))
        if MANAGEMENT_SOURCE not in sources:
            continue
        _collect_change(
            ["--permanent", "--zone", zone, "--remove-source", MANAGEMENT_SOURCE],
            changed,
            errors,
            ignore_missing=True,
        )
    _collect_change(
        ["--permanent", "--zone", MANAGEMENT_ZONE, "--add-source", MANAGEMENT_SOURCE],
        changed,
        errors,
    )


def _zone_details(zone: str) -> dict[str, object]:
    """Parse the stable fields from firewall-cmd --list-all output."""
    res = _run_firewall_cmd(["--permanent", "--zone", zone, "--list-all"])
    if res.returncode != 0:
        return {}
    details: dict[str, object] = {}
    for raw in res.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(zone + " "):
            if "(active)" in line:
                details["active"] = True
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if key in {"services", "ports", "sources"}:
            details[key] = value.split() if value else []
        else:
            details[key] = value
    return details


def _words(args: Sequence[str]) -> list[str]:
    res = _run_firewall_cmd(args)
    return res.stdout.split() if res.returncode == 0 else []


def _collect_change(
    args: Sequence[str],
    changed: list[str],
    errors: list[str],
    *,
    ignore_missing: bool = False,
) -> None:
    res = _run_firewall_cmd(args)
    output = (res.stderr or res.stdout).strip()
    if res.returncode == 0:
        changed.append("firewall-cmd " + " ".join(shlex.quote(part) for part in args))
        return
    if any(token in output for token in ("ALREADY_ENABLED", "ZONE_ALREADY_SET", "NAME_CONFLICT")):
        return
    if ignore_missing and any(token in output for token in ("NOT_ENABLED", "INVALID_ENTRY")):
        return
    errors.append(output or "failed: firewall-cmd " + " ".join(args))


def _run_firewall_cmd(args: Sequence[str], *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    argv = ["sudo", "-n", "firewall-cmd", *args]
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        return subprocess.CompletedProcess(argv, 124, stdout, (stderr + "\n[timeout]").strip())
    except FileNotFoundError as e:
        return subprocess.CompletedProcess(argv, 127, "", str(e))
