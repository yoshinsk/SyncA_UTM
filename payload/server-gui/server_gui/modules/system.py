"""Dashboard / system status module."""
from __future__ import annotations

import platform
import json
from pathlib import Path

from flask import Blueprint, Flask, jsonify, render_template

from ..auth import login_required
from ..shell import run

bp = Blueprint("system", __name__, url_prefix="/system")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", active_tab="dashboard")


@bp.route("/api/status")
@login_required
def status():
    return jsonify({
        "hostname": _read_text(Path("/etc/hostname")).strip() or platform.node(),
        "os": _read_os_release(),
        "uptime": run(["uptime"]).stdout.strip(),
        "memory": run(["free", "-h"]).stdout,
        "disk": run(["df", "-h", "/"]).stdout,
        "kernel": platform.release(),
        "network_links": _network_links(),
        "lan_link_warnings": _lan_link_warnings(),
    })


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def _read_os_release() -> str:
    text = _read_text(Path("/etc/os-release"))
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "Unknown"


def _network_links() -> list[dict]:
    """Return kernel link state for dashboard health checks."""
    links: list[dict] = []
    root = Path("/sys/class/net")
    try:
        names = sorted(p.name for p in root.iterdir())
    except OSError:
        return links
    for name in names:
        base = root / name
        item = {"name": name, "carrier": None, "operstate": "", "address": ""}
        try:
            carrier = (base / "carrier").read_text(encoding="ascii").strip()
            if carrier in {"0", "1"}:
                item["carrier"] = carrier == "1"
        except OSError:
            pass
        for key in ("operstate", "address"):
            try:
                item[key] = (base / key).read_text(encoding="ascii").strip()
            except OSError:
                pass
        links.append(item)
    return links


def _lan_link_warnings() -> list[dict]:
    """Warn when an interface referenced by LAN services has no carrier."""
    links = {item["name"]: item for item in _network_links()}
    warnings: list[dict] = []
    for iface in sorted(_configured_lan_interfaces()):
        link = links.get(iface)
        if not link:
            warnings.append({"interface": iface, "reason": "missing"})
            continue
        if link.get("carrier") is False:
            warnings.append({
                "interface": iface,
                "reason": "no_carrier",
                "operstate": link.get("operstate", ""),
            })
    return warnings


def _configured_lan_interfaces() -> set[str]:
    interfaces: set[str] = set()
    data = _read_json(Path("/etc/server-gui/dnsmasq.json"), {})
    for rng in _dnsmasq_ranges(data):
        if not isinstance(rng, dict):
            continue
        iface = str(rng.get("interface") or "").strip()
        if iface:
            interfaces.add(iface)
    upnp = _read_json(Path("/etc/server-gui/upnp.json"), {})
    for iface in upnp.get("lan_interfaces", []) if isinstance(upnp, dict) else []:
        iface = str(iface).strip()
        if iface:
            interfaces.add(iface)
    text = _read_text(Path("/etc/dnsmasq.d/server-gui.conf"))
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface="):
            iface = stripped.split("=", 1)[1].strip()
            if iface:
                interfaces.add(iface)
    return interfaces


def _dnsmasq_ranges(data: dict) -> list:
    if not isinstance(data, dict):
        return []
    ranges = list(data.get("ranges", []))
    dhcp = data.get("dhcp")
    if isinstance(dhcp, dict):
        ranges.extend(dhcp.get("ranges", []))
    return ranges


def _read_json(path: Path, default: dict) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return default
