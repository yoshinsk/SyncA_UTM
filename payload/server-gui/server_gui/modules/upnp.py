"""payload/server-gui/server_gui/modules/upnp.py - Manage disabled-by-default UPnP/NAT-PMP.

The GUI controls SyncA's bundled `synca-upnpd` daemon. The daemon is disabled
by default, reads `/etc/server-gui/upnp.json`, listens only through selected
LAN interfaces, and creates temporary firewalld direct rules for requested WAN
port mappings.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shlex
import socket
import uuid
from pathlib import Path

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run, sudo_run
from ..validators import ValidationError, validate_interface, validate_ipv4_cidr, validate_port

bp = Blueprint("upnp", __name__, url_prefix="/upnp")

CONFIG_NAME = "upnp"
SYNCA_UPNPD_BIN = Path("/opt/server-gui/bin/synca-upnpd")
SYNCA_UPNP_SERVICE = Path("/etc/systemd/system/synca-upnp.service")
SYNCA_UPNP_UNIT = "synca-upnp.service"
MANAGED_RULE_COMMENT = "synca-upnp-control"
DEFAULT_CONTROL_PORT = 5000


def register(app: Flask) -> None:
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def page():
    return render_template("upnp.html", active_tab="upnp")


@bp.route("/api/status", methods=["GET"])
@login_required
def status():
    settings = _load_settings()
    interfaces = _interface_rows()
    detected_wan = _default_wan_interfaces()
    detected_lan = _default_lan_interfaces(interfaces, detected_wan)
    return jsonify({
        "settings": settings,
        "interfaces": interfaces,
        "detected_wan_interfaces": detected_wan,
        "detected_lan_interfaces": detected_lan,
        "service": _service_state(SYNCA_UPNP_UNIT),
        "daemon": _daemon_status(),
        "firewalld": _firewalld_state(),
        "managed_firewall_rules": sorted(_managed_firewalld_rules()),
        "config_path": str(_store().path(CONFIG_NAME)),
    })


@bp.route("/api/config", methods=["POST"])
@login_required
@csrf_protect
def save_config():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        settings = _normalize_settings(payload)
    except ValidationError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    _save_settings(settings)
    result = _apply_runtime(settings)
    return jsonify(result), (200 if result.get("ok") else 500)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default_settings() -> dict:
    return {
        "enabled": False,
        "wan_interface": "",
        "lan_interfaces": [],
        "allowed_cidrs": [],
        "control_port": DEFAULT_CONTROL_PORT,
        "enable_upnp": True,
        "enable_natpmp": True,
        "secure_mode": True,
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname() + ".synca-upnp")),
    }


def _load_settings() -> dict:
    data = _store().load(CONFIG_NAME, _default_settings())
    default = _default_settings()
    if not isinstance(data, dict):
        return default
    merged = {**default, **data}
    merged["lan_interfaces"] = _string_list(merged.get("lan_interfaces"))
    merged["allowed_cidrs"] = _normalize_cidr_list(merged.get("allowed_cidrs"), allow_empty=True)
    return merged


def _save_settings(settings: dict) -> None:
    _store().save(CONFIG_NAME, settings)


def _normalize_settings(payload: dict) -> dict:
    current = _load_settings()
    enabled = bool(payload.get("enabled", current.get("enabled", False)))
    wan_interface = str(payload.get("wan_interface", current.get("wan_interface", ""))).strip()
    lan_interfaces = _string_list(payload.get("lan_interfaces", current.get("lan_interfaces", [])))
    allowed_cidrs = _normalize_cidr_list(payload.get("allowed_cidrs", current.get("allowed_cidrs", [])))
    control_port = validate_port(payload.get("control_port", current.get("control_port", DEFAULT_CONTROL_PORT)))
    if control_port < 1024:
        raise ValidationError("UPnP制御ポートは1024以上を指定してください")

    if wan_interface:
        wan_interface = validate_interface(wan_interface)
    lan_interfaces = [validate_interface(iface) for iface in lan_interfaces]

    if enabled:
        if not wan_interface:
            raise ValidationError("UPnPを有効にする場合はWANインターフェースが必要です")
        if not lan_interfaces:
            raise ValidationError("UPnPを有効にする場合はLAN待受インターフェースを1つ以上指定してください")
        if wan_interface in lan_interfaces:
            raise ValidationError("WANインターフェースをLAN待受インターフェースには指定できません")
        if not allowed_cidrs:
            allowed_cidrs = _cidrs_for_interfaces(lan_interfaces)
        if not allowed_cidrs:
            raise ValidationError("UPnPを有効にする場合は許可するLAN CIDRを1つ以上指定してください")

    enable_upnp = bool(payload.get("enable_upnp", current.get("enable_upnp", True)))
    enable_natpmp = bool(payload.get("enable_natpmp", current.get("enable_natpmp", True)))
    if enabled and not (enable_upnp or enable_natpmp):
        raise ValidationError("UPnP IGDまたはNAT-PMPの少なくとも一方を有効にしてください")

    return {
        "enabled": enabled,
        "wan_interface": wan_interface,
        "lan_interfaces": _dedupe(lan_interfaces),
        "allowed_cidrs": allowed_cidrs,
        "control_port": control_port,
        "enable_upnp": enable_upnp,
        "enable_natpmp": enable_natpmp,
        "secure_mode": bool(payload.get("secure_mode", current.get("secure_mode", True))),
        "uuid": str(current.get("uuid") or _default_settings()["uuid"]),
    }


def _apply_runtime(settings: dict) -> dict:
    changed: list[str] = []
    errors: list[str] = []

    _write_systemd_unit()
    changed.append(str(SYNCA_UPNP_SERVICE))

    if settings["enabled"]:
        if not SYNCA_UPNPD_BIN.exists():
            return {"ok": False, "error": f"UPnPデーモンが見つかりません: {SYNCA_UPNPD_BIN}"}
        _apply_firewalld_rules(settings, changed, errors)
        for cmd in (
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "--now", SYNCA_UPNP_UNIT],
            ["systemctl", "restart", SYNCA_UPNP_UNIT],
        ):
            _collect_system_change(cmd, changed, errors)
    else:
        for cmd in (
            ["systemctl", "disable", "--now", SYNCA_UPNP_UNIT],
            ["systemctl", "daemon-reload"],
        ):
            _collect_system_change(cmd, changed, errors, ignore_missing=True)
        _remove_managed_firewalld_rules(changed, errors)
        _reload_firewalld(changed, errors)

    return {
        "ok": not errors,
        "changed": changed,
        "errors": errors,
        "settings": settings,
        "service": _service_state(SYNCA_UPNP_UNIT),
    }


def _write_systemd_unit() -> None:
    text = f"""[Unit]
Description=SyncA UTM UPnP/NAT-PMP gateway
After=network-online.target firewalld.service
Wants=network-online.target
ConditionPathExists={_store().path(CONFIG_NAME)}

[Service]
Type=simple
ExecStart={SYNCA_UPNPD_BIN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    SYNCA_UPNP_SERVICE.write_text(text, encoding="utf-8")
    os.chmod(SYNCA_UPNP_SERVICE, 0o644)


def _apply_firewalld_rules(settings: dict, changed: list[str], errors: list[str]) -> None:
    _remove_managed_firewalld_rules(changed, errors)
    if not _firewalld_active():
        return
    for iface in settings["lan_interfaces"]:
        ports = [("tcp", settings["control_port"])]
        if settings["enable_upnp"]:
            ports.append(("udp", 1900))
        if settings["enable_natpmp"]:
            ports.append(("udp", 5351))
        for proto, port in ports:
            cmd = [
                "firewall-cmd", "--permanent", "--direct", "--add-rule",
                "ipv4", "filter", "INPUT", "0",
                "-i", iface, "-p", proto, "--dport", str(port),
                "-m", "comment", "--comment", MANAGED_RULE_COMMENT,
                "-j", "ACCEPT",
            ]
            _collect_firewall_change(cmd, changed, errors)
    _reload_firewalld(changed, errors)


def _remove_managed_firewalld_rules(changed: list[str], errors: list[str]) -> None:
    if not _firewalld_active():
        return
    for raw in sorted(_managed_firewalld_rules(permanent=True)):
        try:
            parts = shlex.split(raw)
        except ValueError as e:
            errors.append(f"管理対象firewalldルールの解析に失敗しました: {e}")
            continue
        res = sudo_run(["firewall-cmd", "--permanent", "--direct", "--remove-rule", *parts])
        output = (res.stderr or res.stdout).strip()
        if res.ok or "not in list" in output:
            changed.append("removed firewalld direct " + raw)
        else:
            errors.append(output or "管理対象firewalldルールの削除に失敗しました")


def _collect_firewall_change(cmd: list[str], changed: list[str], errors: list[str]) -> None:
    res = sudo_run(cmd)
    output = (res.stderr or res.stdout).strip()
    if res.ok:
        changed.append(" ".join(shlex.quote(part) for part in cmd))
        return
    if "ALREADY_ENABLED" in output:
        return
    errors.append(output or "コマンドに失敗しました: " + " ".join(cmd))


def _collect_system_change(
    cmd: list[str],
    changed: list[str],
    errors: list[str],
    *,
    ignore_missing: bool = False,
) -> None:
    res = sudo_run(cmd, timeout=60)
    output = (res.stderr or res.stdout).strip()
    if res.ok:
        changed.append(" ".join(shlex.quote(part) for part in cmd))
        return
    if ignore_missing and any(token in output for token in ("not loaded", "not-found", "does not exist")):
        return
    errors.append(output or "コマンドに失敗しました: " + " ".join(cmd))


def _reload_firewalld(changed: list[str], errors: list[str]) -> None:
    if not _firewalld_active():
        return
    res = sudo_run(["firewall-cmd", "--reload"])
    output = (res.stderr or res.stdout).strip()
    if res.ok:
        changed.append("firewall-cmd --reload")
    else:
        errors.append(output or "firewalldの再読み込みに失敗しました")


def _managed_firewalld_rules(permanent: bool = False) -> set[str]:
    if not _firewalld_active():
        return set()
    cmd = ["firewall-cmd"]
    if permanent:
        cmd.append("--permanent")
    cmd.extend(["--direct", "--get-all-rules"])
    res = sudo_run(cmd)
    if not res.ok:
        return set()
    return {line.strip() for line in res.stdout.splitlines() if MANAGED_RULE_COMMENT in line}


def _firewalld_active() -> bool:
    res = sudo_run(["systemctl", "is-active", "firewalld"], timeout=10)
    return res.stdout.strip() == "active"


def _firewalld_state() -> dict:
    active = _firewalld_active()
    zones = sudo_run(["firewall-cmd", "--get-active-zones"], timeout=10) if active else None
    return {
        "active": active,
        "active_zones": zones.stdout.strip() if zones and zones.ok else "",
    }


def _service_state(unit: str) -> dict:
    active = sudo_run(["systemctl", "is-active", unit], timeout=10)
    enabled = sudo_run(["systemctl", "is-enabled", unit], timeout=10)
    return {
        "unit": unit,
        "active": active.stdout.strip() if active.stdout else "unknown",
        "enabled": enabled.stdout.strip() if enabled.stdout else "unknown",
    }


def _daemon_status() -> dict:
    return {
        "installed": SYNCA_UPNPD_BIN.exists(),
        "path": str(SYNCA_UPNPD_BIN),
    }


def _default_wan_interfaces() -> list[str]:
    routes = _json_command(["ip", "-j", "-4", "route", "show", "default"])
    out: list[str] = []
    if isinstance(routes, list):
        for route in routes:
            dev = str(route.get("dev", "")).strip()
            if dev and dev not in out:
                out.append(dev)
    return out


def _default_lan_interfaces(interfaces: list[dict], wan_interfaces: list[str]) -> list[str]:
    out: list[str] = []
    wan = set(wan_interfaces)
    for item in interfaces:
        name = item["name"]
        if name in wan or name == "lo":
            continue
        if item.get("private_ipv4") and name not in out:
            out.append(name)
    return out


def _interface_rows() -> list[dict]:
    data = _json_command(["ip", "-j", "-4", "addr", "show"])
    if not isinstance(data, list):
        return []
    wan = set(_default_wan_interfaces())
    rows: list[dict] = []
    for item in data:
        name = str(item.get("ifname", "")).strip()
        if not name:
            continue
        cidrs: list[str] = []
        networks: list[str] = []
        private_ipv4 = False
        for addr in item.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            local = str(addr.get("local", "")).strip()
            prefix = addr.get("prefixlen")
            if not local or prefix is None:
                continue
            cidr = f"{local}/{prefix}"
            cidrs.append(cidr)
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                continue
            networks.append(str(network))
            private_ipv4 = private_ipv4 or network.network_address.is_private
        rows.append({
            "name": name,
            "operstate": item.get("operstate", ""),
            "cidrs": cidrs,
            "networks": _dedupe(networks),
            "is_wan_default": name in wan,
            "private_ipv4": private_ipv4,
        })
    return rows


def _cidrs_for_interfaces(names: list[str]) -> list[str]:
    selected = set(names)
    networks: list[str] = []
    for item in _interface_rows():
        if item["name"] not in selected:
            continue
        networks.extend(item.get("networks", []))
    return _normalize_cidr_list(networks, allow_empty=True)


def _json_command(argv: list[str]):
    res = run(argv, timeout=10)
    if not res.ok or not res.stdout.strip():
        return None
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return None


def _string_list(value) -> list[str]:
    if isinstance(value, str):
        raw = value.replace(",", "\n").splitlines()
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    return _dedupe([str(item).strip() for item in raw if str(item).strip()])


def _normalize_cidr_list(value, allow_empty: bool = False) -> list[str]:
    out: list[str] = []
    for item in _string_list(value):
        cidr = validate_ipv4_cidr(item)
        network = str(ipaddress.IPv4Network(cidr, strict=False))
        if network not in out:
            out.append(network)
    if not out and not allow_empty:
        return []
    return out


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out
