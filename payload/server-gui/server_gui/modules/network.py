"""payload/server-gui/server_gui/modules/network.py - Manage NetworkManager profiles and WAN state.

Phase 1 scope:
  - List physical/virtual interfaces (device level)
  - List nmcli connection profiles
  - Show detailed connection config
  - Edit static IPv4 (address, gateway, DNS) on a connection
  - Switch a connection between manual / auto (DHCP)
  - Bring connections up/down

WARNING: misconfiguring the management-path interface can lock you out.
The UI shows a banner; no programmatic safeguard yet (Phase 2).
"""
from __future__ import annotations

import copy
import ipaddress
import json
import shlex
from pathlib import Path
from typing import Optional

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

import re

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..dnsmasq_apply import (
    LEGACY_FIRSTBOOT_CONFIG_PATH,
    apply as apply_dnsmasq,
    default as default_dnsmasq_config,
)
from ..shell import run, sudo_run
from ..validators import ValidationError, validate_interface, validate_ipv4, validate_ipv4_cidr

_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{0,63}$")
_SYNCA_DIR = Path("/etc/synca")
_PPPOE_PARENT_IP_CONFIG = _SYNCA_DIR / "pppoe-parent-ip.json"
_PPPOE_PARENT_IP_DISPATCHER = Path("/etc/NetworkManager/dispatcher.d/90-synca-pppoe-parent-ip")
_UPNP_MODULE_NAME = "upnp"
_SYNCA_UPNP_UNIT = "synca-upnp.service"

bp = Blueprint("network", __name__, url_prefix="/network")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("network.html", active_tab="network")


@bp.route("/api/devices", methods=["GET"])
@login_required
def list_devices():
    connections = _list_connections()
    _mark_lan_bridge_connections(connections)
    return jsonify({"devices": _list_devices(), "connections": connections})


@bp.route("/api/connections/<name>", methods=["GET"])
@login_required
def get_connection(name: str):
    return jsonify(_describe_connection(name))


@bp.route("/api/connections/<name>", methods=["PUT"])
@login_required
@csrf_protect
def update_connection(name: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        result = _apply_ipv4(name, payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    if not result["ok"]:
        return jsonify(result), 500
    return jsonify(result)


@bp.route("/api/connections/<name>/up", methods=["POST"])
@login_required
@csrf_protect
def up_connection(name: str):
    res = sudo_run(["nmcli", "connection", "up", name])
    return jsonify({"ok": res.ok, "output": res.stdout or res.stderr})


@bp.route("/api/connections/<name>/down", methods=["POST"])
@login_required
@csrf_protect
def down_connection(name: str):
    res = sudo_run(["nmcli", "connection", "down", name])
    return jsonify({"ok": res.ok, "output": res.stdout or res.stderr})


@bp.route("/api/connections/<name>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_connection(name: str):
    """Delete a connection profile (nmcli connection delete)."""
    res = sudo_run(["nmcli", "connection", "delete", name])
    return jsonify({"ok": res.ok, "output": (res.stdout + res.stderr).strip()})


def _ensure_pppoe_mss_clamp() -> dict:
    """Ensure firewalld direct rules are in place to TCP-MSS-clamp ppp+ traffic.

    PPPoE links have an MTU of ~1492 (or 1454 on Flets) which is smaller than
    the typical ethernet 1500. Without MSS clamping, large TCP packets get
    silently black-holed when ICMP "fragmentation needed" is dropped on the
    return path (extremely common). Clamping the SYN's MSS to the path MTU
    is the standard fix and is idempotent — adding the same rule twice is a
    no-op in firewalld.

    Returns a dict {ok, output} for the caller to surface in the UI.
    """
    rules = [
        ("ipv4", "mangle", "FORWARD", "0",
         "-o", "ppp+", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--clamp-mss-to-pmtu"),
        ("ipv4", "mangle", "FORWARD", "0",
         "-i", "ppp+", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--clamp-mss-to-pmtu"),
    ]
    out: list[str] = []
    for r in rules:
        res = sudo_run(["firewall-cmd", "--permanent", "--direct", "--add-rule", *r])
        out.append((res.stdout + res.stderr).strip())
    reload_res = sudo_run(["firewall-cmd", "--reload"])
    out.append((reload_res.stdout + reload_res.stderr).strip())
    return {"ok": reload_res.ok, "output": "\n".join(out)}


@bp.route("/api/pppoe/mss-clamp/status", methods=["GET"])
@login_required
def pppoe_mss_clamp_status():
    """Report whether the MSS clamp direct rules are present."""
    res = sudo_run(["firewall-cmd", "--permanent", "--direct", "--get-all-rules"])
    if not res.ok:
        return jsonify({"installed": False, "error": res.stderr.strip()})
    has_out = any("-o ppp+" in line and "TCPMSS" in line for line in res.stdout.splitlines())
    has_in = any("-i ppp+" in line and "TCPMSS" in line for line in res.stdout.splitlines())
    return jsonify({"installed": has_out and has_in, "outbound": has_out, "inbound": has_in})


@bp.route("/api/pppoe/mss-clamp", methods=["POST"])
@login_required
@csrf_protect
def pppoe_mss_clamp_install():
    """Manually install the MSS clamp rules (called from PPPoE settings UI)."""
    return jsonify(_ensure_pppoe_mss_clamp())


@bp.route("/api/connections/bridge/lan-migration-preview", methods=["POST"])
@login_required
@csrf_protect
def bridge_lan_migration_preview():
    """Preview which LAN services would move from selected members to a bridge."""
    payload = request.get_json(force=True, silent=True) or {}
    bridge_name = (payload.get("name") or "").strip()
    bridge_ifname = (payload.get("ifname") or bridge_name).strip()
    try:
        bridge_ifname = validate_interface(bridge_ifname)
        members = _validate_bridge_members(payload.get("members") or [])
        addresses = _normalize_ipv4_addresses(
            (payload.get("address") or "").strip(),
            payload.get("secondary_addresses"),
            payload.get("addresses"),
        )
    except ValidationError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({
        "ok": True,
        "plan": _build_lan_bridge_migration_plan(bridge_ifname, members, addresses),
    })


@bp.route("/api/connections/bridge", methods=["POST"])
@login_required
@csrf_protect
def create_bridge():
    """Create a bridge connection (switching-hub style with optional STP).

    Body:
      {
        "name":          "br-lan",       # nmcli connection profile name
        "ifname":        "br-lan",       # bridge interface name (defaults to name)
        "members":       ["ens4","ens5"],# enslaved ethernet interfaces
        "address":       "192.168.1.1/24",  # optional primary LAN IP (manual)
        "secondary_addresses": ["192.168.2.1/24"], # optional extra LAN IPs
        "gateway":       "",                 # optional, usually empty for LAN
        "dns":           ["8.8.8.8"],        # optional, list of IPs
        "stp":           true,
        "stp_priority":  32768,              # 0-65535
        "forward_delay": 4,                  # seconds, 2-30
        "hello_time":    2,                  # seconds, 1-10
        "autoconnect":   true,
        "activate":      true,
        "use_as_lan":    true                # migrate LAN services to bridge
      }

    Rolls back (deletes bridge + slaves) on any partial failure.
    """
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip()
    ifname = (payload.get("ifname") or name).strip()
    members_raw = payload.get("members") or []
    address = (payload.get("address") or "").strip()
    secondary_addresses_raw = payload.get("secondary_addresses")
    addresses_raw = payload.get("addresses")
    gateway = (payload.get("gateway") or "").strip()
    dns_raw = payload.get("dns") or []
    stp = bool(payload.get("stp", True))
    stp_priority = int(payload.get("stp_priority", 32768))
    forward_delay = int(payload.get("forward_delay", 4))
    hello_time = int(payload.get("hello_time", 2))
    autoconnect = bool(payload.get("autoconnect", True))
    activate = bool(payload.get("activate", True))
    use_as_lan = bool(payload.get("use_as_lan", False))

    # Validate
    if not _IDENT_RE.match(name):
        return jsonify({"error": "name required (alnum, '_', '-')"}), 400
    try:
        ifname = validate_interface(ifname)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    if not isinstance(members_raw, list) or not members_raw:
        return jsonify({"error": "at least one member interface required"}), 400
    members = []
    for m in members_raw:
        if not isinstance(m, str):
            return jsonify({"error": "invalid member"}), 400
        try:
            members.append(validate_interface(m.strip()))
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400
    try:
        addresses = _normalize_ipv4_addresses(address, secondary_addresses_raw, addresses_raw)
    except ValidationError as e:
        return jsonify({"error": f"invalid address: {e}"}), 400
    if gateway:
        try:
            validate_ipv4(gateway)
        except ValidationError as e:
            return jsonify({"error": f"invalid gateway: {e}"}), 400
    dns_list: list[str] = []
    if isinstance(dns_raw, list):
        for d in dns_raw:
            if str(d).strip():
                try:
                    dns_list.append(validate_ipv4(str(d).strip()))
                except ValidationError as e:
                    return jsonify({"error": str(e)}), 400
    if not (0 <= stp_priority <= 65535):
        return jsonify({"error": "stp_priority out of range (0-65535)"}), 400
    if not (2 <= forward_delay <= 30):
        return jsonify({"error": "forward_delay out of range (2-30)"}), 400
    if not (1 <= hello_time <= 10):
        return jsonify({"error": "hello_time out of range (1-10)"}), 400

    # Refuse to enslave the interface currently carrying the default route —
    # otherwise we'd take down the WAN unintentionally.
    route = run(["ip", "-o", "route", "show", "default"])
    wan_dev = ""
    if route.ok:
        for line in route.stdout.splitlines():
            tokens = line.split()
            if "dev" in tokens:
                wan_dev = tokens[tokens.index("dev") + 1]
                break
    if wan_dev in members:
        return jsonify({
            "error": f"refusing to enslave WAN interface {wan_dev!r} into the bridge. "
                     "Move the default route first or pick different members."
        }), 400
    blocked_members = sorted(set(members) & _blocked_bridge_members())
    if blocked_members:
        return jsonify({
            "error": "refusing to enslave WAN/PPPoE interface(s) into the bridge: "
                     + ", ".join(blocked_members)
        }), 400
    lan_migration_plan = None
    if use_as_lan:
        lan_migration_plan = _build_lan_bridge_migration_plan(ifname, members, addresses)
        if not lan_migration_plan.get("old_lan_interfaces") and not lan_migration_plan.get("already_lan_bridge"):
            return jsonify({
                "error": "旧LANインターフェースを検出できないため、Bridge作成前に中止しました。",
                "lan_migration_preview": lan_migration_plan,
            }), 400
        if not _firewalld_running():
            return jsonify({
                "error": "firewalldが動作していないため、Bridge作成前にLANサービス移行を中止しました。",
                "lan_migration_preview": lan_migration_plan,
            }), 400
        addresses = _merge_lan_bridge_addresses(addresses, lan_migration_plan.get("moved_addresses", []))

    # ---- create bridge ----
    add_cmd = [
        "nmcli", "connection", "add", "type", "bridge",
        "con-name", name, "ifname", ifname,
        "connection.autoconnect", "yes" if autoconnect else "no",
        "connection.zone", "trusted",
    ]
    res = sudo_run(add_cmd, timeout=30)
    if not res.ok:
        return jsonify({"ok": False, "error": (res.stderr or res.stdout).strip()}), 500

    def _rollback():
        # Delete bridge + any slaves we managed to create
        for sn in [f"{name}-port-{m}" for m in members]:
            sudo_run(["nmcli", "connection", "delete", sn])
        sudo_run(["nmcli", "connection", "delete", name])

    # STP settings
    stp_res = sudo_run([
        "nmcli", "connection", "modify", name,
        "bridge.stp", "yes" if stp else "no",
        "bridge.priority", str(stp_priority),
        "bridge.forward-delay", str(forward_delay),
        "bridge.hello-time", str(hello_time),
    ])
    if not stp_res.ok:
        _rollback()
        return jsonify({"ok": False, "error": "STP config failed: " + stp_res.stderr.strip()}), 500

    # IPv4
    if addresses:
        ipv4_cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.method", "manual",
            "ipv4.addresses", ",".join(addresses),
        ]
        if gateway:
            ipv4_cmd.extend(["ipv4.gateway", gateway])
        if dns_list:
            ipv4_cmd.extend(["ipv4.dns", ",".join(dns_list)])
        ip_res = sudo_run(ipv4_cmd)
        if not ip_res.ok:
            _rollback()
            return jsonify({"ok": False, "error": "IPv4 config failed: " + ip_res.stderr.strip()}), 500
    else:
        sudo_run(["nmcli", "connection", "modify", name, "ipv4.method", "disabled"])

    # Add member ports (bridge-slaves)
    slave_failures = []
    for m in members:
        slave_name = f"{name}-port-{m}"
        prep_result = _prepare_bridge_member(m, {name, slave_name})
        if not prep_result["ok"]:
            slave_failures.append({"member": m, "error": prep_result["error"]})
            continue
        slave_res = sudo_run([
            "nmcli", "connection", "add", "type", "bridge-slave",
            "con-name", slave_name, "ifname", m, "master", name,
            "connection.zone", "trusted",
        ])
        if not slave_res.ok:
            slave_failures.append({"member": m, "error": slave_res.stderr.strip()})
    if slave_failures:
        _rollback()
        return jsonify({"ok": False, "slave_failures": slave_failures,
                        "error": "failed to add bridge slaves"}), 500

    output = ""
    if activate:
        up = sudo_run(["nmcli", "connection", "up", name], timeout=60)
        output = (up.stdout + up.stderr).strip()
        if not up.ok:
            return jsonify({
                "ok": False, "created": True, "activated": False,
                "error": "created but failed to activate", "output": output,
            }), 500
        for m in members:
            port_name = f"{name}-port-{m}"
            port_up = sudo_run(["nmcli", "connection", "up", port_name], timeout=60)
            port_output = (port_up.stdout + port_up.stderr).strip()
            if port_output:
                output = "\n".join(part for part in [output, port_output] if part)
            if not port_up.ok:
                return jsonify({
                    "ok": False, "created": True, "activated": False,
                    "error": f"created but failed to activate {port_name}",
                    "output": output,
                }), 500

    lan_migration = None
    if use_as_lan:
        lan_migration = _apply_bridge_lan_migration(
            ifname, members, addresses, lan_migration_plan
        )
        if not lan_migration.get("ok"):
            return jsonify({
                "ok": False, "created": True, "activated": activate,
                "error": lan_migration.get("error") or "LANサービス移行に失敗しました",
                "lan_migration": lan_migration,
                "output": output,
            }), 500

    return jsonify({
        "ok": True, "name": name, "ifname": ifname,
        "members": members, "stp": stp, "address": addresses[0] if addresses else "",
        "addresses": addresses,
        "lan_migration": lan_migration,
        "output": output,
    }), 201


@bp.route("/api/connections/<name>/bridge", methods=["GET"])
@login_required
def get_bridge(name: str):
    """Return editable bridge settings and current member interfaces."""
    detail = _describe_connection(name)
    if detail.get("error"):
        return jsonify(detail), 404
    if detail.get("type") != "bridge":
        return jsonify({"error": "connection is not a bridge"}), 400
    member_profiles = _bridge_member_profiles(name)
    return jsonify({
        **detail,
        "members": sorted(member_profiles),
        "member_profiles": member_profiles,
        "is_lan_bridge": _is_bridge_lan_interface(detail.get("interface") or name),
    })


@bp.route("/api/connections/<name>/bridge", methods=["PUT"])
@login_required
@csrf_protect
def update_bridge(name: str):
    """Update an existing bridge and reconcile its member interfaces."""
    detail = _describe_connection(name)
    if detail.get("error"):
        return jsonify(detail), 404
    if detail.get("type") != "bridge":
        return jsonify({"error": "connection is not a bridge"}), 400

    payload = request.get_json(force=True, silent=True) or {}
    members_raw = payload.get("members") or []
    address = (payload.get("address") or "").strip()
    secondary_addresses_raw = payload.get("secondary_addresses")
    addresses_raw = payload.get("addresses")
    gateway = (payload.get("gateway") or "").strip()
    dns_raw = payload.get("dns") or []
    stp = bool(payload.get("stp", True))
    stp_priority = int(payload.get("stp_priority", 32768))
    forward_delay = int(payload.get("forward_delay", 4))
    hello_time = int(payload.get("hello_time", 2))
    autoconnect = bool(payload.get("autoconnect", True))
    activate = bool(payload.get("activate", True))
    use_as_lan = bool(payload.get("use_as_lan", False))

    try:
        members = _validate_bridge_members(members_raw)
        addresses = _normalize_ipv4_addresses(address, secondary_addresses_raw, addresses_raw)
        dns_list = _validate_bridge_ipv4(addresses, gateway, dns_raw)
        _validate_bridge_timers(stp_priority, forward_delay, hello_time)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    blocked_members = sorted(set(members) & _blocked_bridge_members())
    if blocked_members:
        return jsonify({
            "error": "refusing to enslave WAN/PPPoE interface(s) into the bridge: "
                     + ", ".join(blocked_members)
        }), 400
    bridge_ifname = detail.get("interface") or name
    lan_migration_plan = None
    if use_as_lan:
        lan_migration_plan = _build_lan_bridge_migration_plan(bridge_ifname, members, addresses)
        if not lan_migration_plan.get("old_lan_interfaces") and not lan_migration_plan.get("already_lan_bridge"):
            return jsonify({
                "error": "旧LANインターフェースを検出できないため、Bridge更新前に中止しました。",
                "lan_migration_preview": lan_migration_plan,
            }), 400
        if not _firewalld_running():
            return jsonify({
                "error": "firewalldが動作していないため、Bridge更新前にLANサービス移行を中止しました。",
                "lan_migration_preview": lan_migration_plan,
            }), 400
        addresses = _merge_lan_bridge_addresses(addresses, lan_migration_plan.get("moved_addresses", []))

    stp_result = _apply_bridge_stp(name, stp, stp_priority, forward_delay, hello_time)
    if not stp_result["ok"]:
        return jsonify({"ok": False, "error": "STP config failed: " + stp_result["error"]}), 500

    ipv4_result = _apply_bridge_ipv4(name, addresses, gateway, dns_list)
    if not ipv4_result["ok"]:
        return jsonify({"ok": False, "error": "IPv4 config failed: " + ipv4_result["error"]}), 500

    auto_res = sudo_run([
        "nmcli", "connection", "modify", name,
        "connection.autoconnect", "yes" if autoconnect else "no",
        "connection.zone", "trusted",
    ])
    if not auto_res.ok:
        return jsonify({"ok": False, "error": auto_res.stderr.strip()}), 500

    reconcile = _reconcile_bridge_members(name, members, activate)
    if not reconcile["ok"]:
        return jsonify(reconcile), 500

    output = list(reconcile.get("output", []))
    if activate:
        up = sudo_run(["nmcli", "connection", "up", name], timeout=60)
        text = (up.stdout + up.stderr).strip()
        if text:
            output.append(text)
        if not up.ok:
            return jsonify({
                "ok": False, "activated": False,
                "error": "updated but failed to activate",
                "output": "\n".join(output),
            }), 500

    lan_migration = None
    if use_as_lan:
        lan_migration = _apply_bridge_lan_migration(
            bridge_ifname, members, addresses, lan_migration_plan
        )
        if not lan_migration.get("ok"):
            return jsonify({
                "ok": False, "updated": True, "activated": activate,
                "error": lan_migration.get("error") or "LANサービス移行に失敗しました",
                "lan_migration": lan_migration,
                "output": "\n".join(output),
            }), 500

    return jsonify({
        "ok": True,
        "name": name,
        "members": members,
        "address": addresses[0] if addresses else "",
        "addresses": addresses,
        "lan_migration": lan_migration,
        "output": "\n".join(output),
    })


@bp.route("/api/connections/vlan", methods=["POST"])
@login_required
@csrf_protect
def create_vlan():
    """Create a VLAN-tagged NetworkManager connection on a parent interface."""
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip()
    parent = (payload.get("parent") or "").strip()
    ifname = (payload.get("ifname") or "").strip()
    vlan_id_raw = payload.get("vlan_id")
    address = (payload.get("address") or "").strip()
    gateway = (payload.get("gateway") or "").strip()
    dns_raw = payload.get("dns") or []
    autoconnect = bool(payload.get("autoconnect", True))
    activate = bool(payload.get("activate", True))

    if not _IDENT_RE.match(name):
        return jsonify({"error": "name required (alnum, '_', '-')"}), 400
    try:
        parent = validate_interface(parent)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    try:
        vlan_id = int(vlan_id_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid VLAN ID"}), 400
    if not (1 <= vlan_id <= 4094):
        return jsonify({"error": "VLAN ID out of range (1-4094)"}), 400
    if not ifname:
        ifname = f"{parent}.{vlan_id}"
    try:
        ifname = validate_interface(ifname)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    if address:
        try:
            validate_ipv4_cidr(address)
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400
    if gateway:
        try:
            validate_ipv4(gateway)
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400
    dns_list: list[str] = []
    if isinstance(dns_raw, list):
        for d in dns_raw:
            if str(d).strip():
                try:
                    dns_list.append(validate_ipv4(str(d).strip()))
                except ValidationError as e:
                    return jsonify({"error": str(e)}), 400

    res = sudo_run([
        "nmcli", "connection", "add",
        "type", "vlan",
        "con-name", name,
        "ifname", ifname,
        "dev", parent,
        "id", str(vlan_id),
        "connection.autoconnect", "yes" if autoconnect else "no",
    ], timeout=30)
    if not res.ok:
        return jsonify({"ok": False, "error": (res.stderr or res.stdout).strip()}), 500

    if address:
        cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.method", "manual",
            "ipv4.addresses", address,
            "ipv4.never-default", "no" if gateway else "yes",
            "ipv6.method", "ignore",
        ]
        if gateway:
            cmd.extend(["ipv4.gateway", gateway])
        if dns_list:
            cmd.extend(["ipv4.dns", ",".join(dns_list)])
        ip_res = sudo_run(cmd)
        if not ip_res.ok:
            sudo_run(["nmcli", "connection", "delete", name])
            return jsonify({"ok": False, "error": ip_res.stderr.strip()}), 500
    else:
        # A VLAN with no configured address is still useful as a bridge member
        # or L2 test interface. NetworkManager may refuse to activate a profile
        # with all address families disabled, so use IPv4 link-local and forbid
        # default-route contribution.
        ip_res = sudo_run([
            "nmcli", "connection", "modify", name,
            "ipv4.method", "link-local",
            "ipv4.never-default", "yes",
            "ipv6.method", "ignore",
        ])
        if not ip_res.ok:
            sudo_run(["nmcli", "connection", "delete", name])
            return jsonify({"ok": False, "error": ip_res.stderr.strip()}), 500

    output = res.stdout + res.stderr
    if activate:
        up = sudo_run(["nmcli", "connection", "up", name], timeout=60)
        output += "\n--- up ---\n" + (up.stdout + up.stderr)
        if not up.ok:
            return jsonify({
                "ok": False, "created": True, "activated": False,
                "error": "created but failed to activate",
                "output": output.strip(),
            })

    return jsonify({
        "ok": True,
        "name": name,
        "ifname": ifname,
        "parent": parent,
        "vlan_id": vlan_id,
        "output": output.strip(),
    }), 201


@bp.route("/api/connections/pppoe", methods=["POST"])
@login_required
@csrf_protect
def create_pppoe():
    """Create a PPPoE connection profile.

    Body:
      {
        "name": "wan-pppoe",          # connection profile name
        "ifname": "ens3",             # parent ethernet interface
        "username": "user@isp.example",
        "password": "...",
        "service": "",                # optional service name (rare)
        "mtu": 1454,                  # optional, MUST be set for many JP ISPs
        "autoconnect": true,
        "activate": true
      }
    """
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip()
    ifname = (payload.get("ifname") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    service = (payload.get("service") or "").strip()
    mtu = payload.get("mtu")
    autoconnect = bool(payload.get("autoconnect", True))
    activate = bool(payload.get("activate", True))
    mss_clamp = bool(payload.get("mss_clamp", True))

    if not _IDENT_RE.match(name):
        return jsonify({"error": "name required (alnum, '_', '-')"}), 400
    try:
        ifname = validate_interface(ifname)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    if not username or "\n" in username or len(username) > 128:
        return jsonify({"error": "invalid username"}), 400
    if not password or "\n" in password or len(password) > 256:
        return jsonify({"error": "invalid password"}), 400
    if mtu is not None and mtu != "":
        try:
            mtu = int(mtu)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid MTU"}), 400
        if not (576 <= mtu <= 1500):
            return jsonify({"error": "MTU out of range (576-1500)"}), 400
    else:
        mtu = None

    # 1. Create the connection (without secrets in argv if possible)
    add_cmd = [
        "nmcli", "connection", "add",
        "type", "pppoe",
        "con-name", name,
        "ifname", ifname,
        "username", username,
        "connection.autoconnect", "yes" if autoconnect else "no",
    ]
    if service:
        add_cmd.extend(["service", service])
    res = sudo_run(add_cmd, timeout=30)
    if not res.ok:
        return jsonify({"ok": False, "error": (res.stderr or res.stdout).strip()}), 500

    # 2. Set password via stdin to keep it out of process args
    pw_res = sudo_run(["nmcli", "connection", "modify", name, "pppoe.password", password], timeout=15)
    if not pw_res.ok:
        sudo_run(["nmcli", "connection", "delete", name])
        return jsonify({"ok": False, "error": "password set failed: " + pw_res.stderr.strip()}), 500

    if mtu is not None:
        sudo_run(["nmcli", "connection", "modify", name, "ppp.mtu", str(mtu), "ppp.mru", str(mtu)])

    output = res.stdout + res.stderr

    # MSS clamping for PPPoE (prevents MTU black-hole, see _ensure_pppoe_mss_clamp)
    if mss_clamp:
        clamp_res = _ensure_pppoe_mss_clamp()
        output += "\n--- mss-clamp ---\n" + clamp_res["output"]

    if activate:
        up = sudo_run(["nmcli", "connection", "up", name], timeout=60)
        output += "\n--- up ---\n" + (up.stdout + up.stderr)
        if not up.ok:
            return jsonify({
                "ok": False, "created": True, "activated": False,
                "error": "created but failed to activate", "output": output,
            }), 500

    return jsonify({"ok": True, "name": name, "output": output.strip(), "mss_clamp": mss_clamp}), 201


@bp.route("/api/connections/<name>/pppoe", methods=["PUT"])
@login_required
@csrf_protect
def update_pppoe(name: str):
    """Update PPPoE-specific fields of an existing connection profile."""
    payload = request.get_json(force=True, silent=True) or {}
    changed: list[str] = []
    if "username" in payload:
        u = (payload["username"] or "").strip()
        if not u or "\n" in u or len(u) > 128:
            return jsonify({"error": "invalid username"}), 400
        r = sudo_run(["nmcli", "connection", "modify", name, "pppoe.username", u])
        if not r.ok:
            return jsonify({"ok": False, "error": r.stderr.strip()}), 500
        changed.append("username")
    if "password" in payload and payload["password"]:
        pw = payload["password"]
        if "\n" in pw or len(pw) > 256:
            return jsonify({"error": "invalid password"}), 400
        r = sudo_run(["nmcli", "connection", "modify", name, "pppoe.password", pw])
        if not r.ok:
            return jsonify({"ok": False, "error": r.stderr.strip()}), 500
        changed.append("password")
    if "mtu" in payload and payload["mtu"] not in (None, ""):
        try:
            mtu = int(payload["mtu"])
        except (TypeError, ValueError):
            return jsonify({"error": "invalid MTU"}), 400
        if not (576 <= mtu <= 1500):
            return jsonify({"error": "MTU out of range (576-1500)"}), 400
        r = sudo_run(["nmcli", "connection", "modify", name, "ppp.mtu", str(mtu), "ppp.mru", str(mtu)])
        if not r.ok:
            return jsonify({"ok": False, "error": r.stderr.strip()}), 500
        changed.append("mtu")
    clamp_result = None
    if bool(payload.get("mss_clamp", True)):
        clamp_result = _ensure_pppoe_mss_clamp()
        changed.append("mss_clamp")
    return jsonify({"ok": True, "changed": changed, "mss_clamp": clamp_result})


@bp.route("/api/pppoe/parent-ip", methods=["PUT"])
@login_required
@csrf_protect
def update_pppoe_parent_ip():
    """Persist and apply auxiliary IPv4 addresses on the PPPoE parent NIC."""
    payload = request.get_json(force=True, silent=True) or {}
    parent = (payload.get("ifname") or "").strip()
    if not parent:
        parent = _pppoe_parent(_active_pppoe_connection())
    try:
        parent = validate_interface(parent)
        result = _set_pppoe_parent_ip(parent, payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    if not result.get("ok"):
        return jsonify(result), 500
    return jsonify(result)


# ---- nmcli helpers -----------------------------------------------------

def _nmcli_terse(args: list[str]) -> list[list[str]]:
    """Run `nmcli -t -e no <args>` and split each non-empty line by unescaped ':'."""
    res = run(["nmcli", "-t", "-e", "no", *args])
    if not res.ok:
        return []
    rows = []
    for line in res.stdout.splitlines():
        if not line:
            continue
        # `nmcli -t -e no` already disables escaping; safe to split on ':'
        rows.append(line.split(":"))
    return rows


def _list_devices() -> list[dict]:
    rows = _nmcli_terse(["-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
    ip_map = _device_ip_map()
    default_dev = _default_route_device()
    pppoe_conn = _active_pppoe_connection()
    pppoe_parent = _pppoe_parent(pppoe_conn)
    devices = []
    for r in rows:
        if len(r) < 4:
            continue
        name = r[0]
        info = ip_map.get(name, {})
        state = r[2]
        connection = r[3] or None
        if name == default_dev and r[1] == "ppp" and info.get("ipv4"):
            # NetworkManager may report the kernel ppp device as disconnected
            # while the owning PPPoE profile is activated on the parent NIC.
            state = "connected"
            connection = (pppoe_conn or {}).get("name") or connection
        if pppoe_parent and name == pppoe_parent:
            state = "connected"
            connection = (pppoe_conn or {}).get("name") or connection
        devices.append({
            "device": name,
            "type": r[1],
            "state": state,
            "connection": connection,
            "pppoe_parent": bool(pppoe_parent and name == pppoe_parent),
            "bridge_eligible": r[1] == "ethernet" and not (pppoe_parent and name == pppoe_parent),
            "ipv4": info.get("ipv4", []),
            "ipv6": info.get("ipv6", []),
            "mac": info.get("mac"),
            "mtu": info.get("mtu"),
        })
    return devices


def _default_route_device() -> str:
    """Return the device currently carrying the IPv4 default route."""
    route = run(["ip", "-j", "route", "show", "default"])
    if not route.ok:
        return ""
    try:
        routes = json.loads(route.stdout)
    except json.JSONDecodeError:
        return ""
    if not routes:
        return ""
    return routes[0].get("dev", "") or ""


def _active_pppoe_connection() -> Optional[dict]:
    """Return the active PPPoE profile, if NetworkManager exposes one."""
    for conn in _list_connections():
        if conn.get("type") == "pppoe" and conn.get("device"):
            return conn
    return None


def _pppoe_parent(conn: Optional[dict]) -> str:
    """Return the ethernet parent interface used by an active PPPoE profile."""
    if not conn or not conn.get("name"):
        return ""
    detail = _describe_connection(conn["name"])
    pppoe = detail.get("pppoe") or {}
    return pppoe.get("parent") or detail.get("interface") or conn.get("device") or ""


def _read_pppoe_parent_ip_config() -> dict:
    """Read persisted auxiliary IPv4 addresses for PPPoE parent interfaces."""
    if not _PPPOE_PARENT_IP_CONFIG.exists():
        return {"interfaces": {}}
    try:
        data = json.loads(_PPPOE_PARENT_IP_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"interfaces": {}}
    if not isinstance(data, dict):
        return {"interfaces": {}}
    interfaces = data.get("interfaces")
    if not isinstance(interfaces, dict):
        data["interfaces"] = {}
    return data


def _write_pppoe_parent_ip_config(data: dict) -> None:
    """Persist PPPoE parent auxiliary IPv4 settings under /etc/synca."""
    _SYNCA_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    _PPPOE_PARENT_IP_CONFIG.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _PPPOE_PARENT_IP_CONFIG.chmod(0o600)


def _ensure_pppoe_parent_ip_dispatcher() -> None:
    """Install the NetworkManager dispatcher that reapplies parent NIC IPs."""
    _PPPOE_PARENT_IP_DISPATCHER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _PPPOE_PARENT_IP_DISPATCHER.write_text("""#!/usr/bin/env bash
# /etc/NetworkManager/dispatcher.d/90-synca-pppoe-parent-ip
# Reapply SyncA UTM auxiliary IPv4 addresses on PPPoE parent interfaces.

set -euo pipefail

IFACE="${1:-}"
ACTION="${2:-}"
CONFIG="/etc/synca/pppoe-parent-ip.json"

case "$ACTION" in
    up|dhcp4-change|connectivity-change|reapply) ;;
    *) exit 0 ;;
esac

[[ -n "$IFACE" && -f "$CONFIG" ]] || exit 0

python3 - "$IFACE" "$CONFIG" <<'PY'
import json
import subprocess
import sys

iface, path = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)

entry = (data.get("interfaces") or {}).get(iface) or {}
addresses = [str(addr).strip() for addr in entry.get("addresses", []) if str(addr).strip()]
if not addresses:
    sys.exit(0)

subprocess.run(["ip", "link", "set", iface, "up"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
shown = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
live = shown.stdout
for address in addresses:
    if address in live:
        continue
    subprocess.run(["ip", "addr", "add", address, "dev", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
PY
""", encoding="utf-8")
    _PPPOE_PARENT_IP_DISPATCHER.chmod(0o755)


def _payload_ipv4_addresses(payload: dict) -> list[str]:
    """Extract primary + secondary IPv4 CIDR values from a request payload."""
    addresses_raw = payload.get("addresses")
    if isinstance(addresses_raw, list):
        candidates = [str(a).strip() for a in addresses_raw if str(a).strip()]
    else:
        primary = (payload.get("address") or "").strip()
        secondary_raw = payload.get("secondary_addresses") or []
        candidates = [primary] if primary else []
        if isinstance(secondary_raw, list):
            candidates.extend(str(a).strip() for a in secondary_raw if str(a).strip())
        elif isinstance(secondary_raw, str):
            candidates.extend(part.strip() for part in re.split(r"[\n,;]+", secondary_raw) if part.strip())
    addresses: list[str] = []
    for address in candidates:
        normalized = validate_ipv4_cidr(address)
        if normalized not in addresses:
            addresses.append(normalized)
    return addresses


def _live_ipv4_addresses(ifname: str) -> list[str]:
    """Return live IPv4 CIDR addresses currently assigned to an interface."""
    return (_device_ip_map().get(ifname) or {}).get("ipv4", [])


def _apply_pppoe_parent_ip_live(ifname: str, old_addresses: list[str], new_addresses: list[str]) -> dict:
    """Apply auxiliary IPs directly to the parent NIC without touching PPPoE."""
    if ifname not in _device_ip_map():
        return {"ok": False, "error": f"interface not found: {ifname}"}
    output: list[str] = []
    sudo_run(["ip", "link", "set", ifname, "up"], timeout=10)
    for address in sorted(set(old_addresses) - set(new_addresses)):
        res = sudo_run(["ip", "addr", "del", address, "dev", ifname], timeout=10)
        text = (res.stdout + res.stderr).strip()
        if text:
            output.append(text)
    live = set(_live_ipv4_addresses(ifname))
    for address in new_addresses:
        if address in live:
            continue
        res = sudo_run(["ip", "addr", "add", address, "dev", ifname], timeout=10)
        text = (res.stdout + res.stderr).strip()
        if text:
            output.append(text)
        if not res.ok and "File exists" not in text:
            return {"ok": False, "error": text or f"failed to add {address}"}
    return {"ok": True, "output": "\n".join(output)}


def _set_pppoe_parent_ip(ifname: str, payload: dict) -> dict:
    """Persist and apply auxiliary IPv4 CIDR values for a PPPoE parent NIC."""
    addresses = _payload_ipv4_addresses(payload)
    config = _read_pppoe_parent_ip_config()
    interfaces = config.setdefault("interfaces", {})
    current = interfaces.get(ifname) or {}
    old_addresses = [str(a).strip() for a in current.get("addresses", []) if str(a).strip()]
    live_result = _apply_pppoe_parent_ip_live(ifname, old_addresses, addresses)
    if not live_result.get("ok"):
        return live_result
    if addresses:
        interfaces[ifname] = {"addresses": addresses}
    else:
        interfaces.pop(ifname, None)
    _write_pppoe_parent_ip_config(config)
    _ensure_pppoe_parent_ip_dispatcher()
    return {
        "ok": True,
        "ifname": ifname,
        "addresses": addresses,
        "live_addresses": _live_ipv4_addresses(ifname),
        "output": live_result.get("output", ""),
    }


def _pppoe_parent_ip_status(ifname: str) -> dict:
    """Return persisted and live auxiliary IPv4 information for a parent NIC."""
    if not ifname:
        return {"ifname": "", "addresses": [], "live_addresses": []}
    config = _read_pppoe_parent_ip_config()
    entry = (config.get("interfaces") or {}).get(ifname) or {}
    return {
        "ifname": ifname,
        "addresses": [str(a).strip() for a in entry.get("addresses", []) if str(a).strip()],
        "live_addresses": _live_ipv4_addresses(ifname),
    }


def _validate_bridge_members(members_raw) -> list[str]:
    """Validate and de-duplicate requested bridge member interfaces."""
    if not isinstance(members_raw, list) or not members_raw:
        raise ValidationError("at least one member interface required")
    members: list[str] = []
    for raw_member in members_raw:
        if not isinstance(raw_member, str):
            raise ValidationError("invalid member")
        member = validate_interface(raw_member.strip())
        if member not in members:
            members.append(member)
    return members


def _normalize_ipv4_addresses(primary: str = "", secondary_raw=None, addresses_raw=None) -> list[str]:
    """Normalize primary + secondary IPv4 CIDRs into an nmcli address list."""
    values: list[str] = []
    if isinstance(addresses_raw, list):
        values.extend(str(item).strip() for item in addresses_raw)
    elif isinstance(addresses_raw, str) and addresses_raw.strip():
        values.extend(part.strip() for part in re.split(r"[\s,;]+", addresses_raw))
    else:
        if primary:
            values.append(primary)
        if isinstance(secondary_raw, list):
            values.extend(str(item).strip() for item in secondary_raw)
        elif isinstance(secondary_raw, str):
            values.extend(part.strip() for part in re.split(r"[\r\n,;]+", secondary_raw))

    addresses: list[str] = []
    for value in values:
        if not value:
            continue
        address = validate_ipv4_cidr(value)
        if address not in addresses:
            addresses.append(address)
    return addresses


def _validate_bridge_ipv4(addresses: list[str], gateway: str, dns_raw) -> list[str]:
    """Validate optional bridge IPv4 fields and return normalized DNS IPs."""
    for address in addresses:
        validate_ipv4_cidr(address)
    if gateway:
        validate_ipv4(gateway)
    dns_candidates = dns_raw
    if isinstance(dns_raw, str):
        dns_candidates = [part.strip() for part in dns_raw.split(",")]
    dns_list: list[str] = []
    if isinstance(dns_candidates, list):
        for item in dns_candidates:
            value = str(item).strip()
            if value:
                dns_list.append(validate_ipv4(value))
    elif dns_candidates:
        raise ValidationError("dns must be a list or comma-separated string")
    return dns_list


def _validate_bridge_timers(stp_priority: int, forward_delay: int, hello_time: int) -> None:
    """Validate NetworkManager bridge STP timer ranges."""
    if not (0 <= stp_priority <= 65535):
        raise ValidationError("stp_priority out of range (0-65535)")
    if not (2 <= forward_delay <= 30):
        raise ValidationError("forward_delay out of range (2-30)")
    if not (1 <= hello_time <= 10):
        raise ValidationError("hello_time out of range (1-10)")


def _blocked_bridge_members() -> set[str]:
    """Return interfaces that must never be enslaved into a LAN bridge."""
    blocked = {_default_route_device()}
    pppoe_parent = _pppoe_parent(_active_pppoe_connection())
    if pppoe_parent:
        blocked.add(pppoe_parent)
    return {name for name in blocked if name}


def _connection_profiles_for_interface(ifname: str) -> list[dict]:
    """Return NetworkManager profiles bound to an interface, active or inactive."""
    profiles: list[dict] = []
    for conn in _list_connections():
        name = conn.get("name")
        if not name:
            continue
        detail = _describe_connection(name)
        if detail.get("error"):
            continue
        if detail.get("interface") == ifname or conn.get("device") == ifname:
            profiles.append(detail)
    return profiles


def _bridge_member_profiles(bridge_name: str) -> dict[str, str]:
    """Return {interface: connection_name} for ports enslaved to a bridge."""
    members: dict[str, str] = {}
    for conn in _list_connections():
        name = conn.get("name")
        if not name:
            continue
        detail = _describe_connection(name)
        if detail.get("master") == bridge_name and detail.get("slave_type") == "bridge":
            interface = detail.get("interface")
            if interface:
                members[interface] = name
    return members


def _prepare_bridge_member(ifname: str, keep_connections: set[str]) -> dict:
    """Disable conflicting profiles so the member NIC cannot keep its own IP."""
    output: list[str] = []
    for profile in _connection_profiles_for_interface(ifname):
        conn_name = profile.get("name")
        if not conn_name or conn_name in keep_connections:
            continue
        if profile.get("type") == "pppoe":
            return {"ok": False, "error": f"{ifname} is used by PPPoE profile {conn_name}"}
        master = profile.get("master") or ""
        if master and master not in keep_connections:
            return {"ok": False, "error": f"{ifname} is already enslaved by {master}"}

        auto = sudo_run(["nmcli", "connection", "modify", conn_name, "connection.autoconnect", "no"])
        if not auto.ok:
            return {"ok": False, "error": auto.stderr.strip() or auto.stdout.strip()}
        down = sudo_run(["nmcli", "connection", "down", conn_name], timeout=20)
        text = (down.stdout + down.stderr).strip()
        if text and "not an active connection" not in text and "no active connection provided" not in text:
            output.append(text)

    flush = sudo_run(["ip", "-4", "addr", "flush", "dev", ifname], timeout=10)
    text = (flush.stdout + flush.stderr).strip()
    if text:
        output.append(text)
    return {"ok": True, "output": output}


def _apply_bridge_stp(
    name: str,
    stp: bool,
    stp_priority: int,
    forward_delay: int,
    hello_time: int,
) -> dict:
    """Apply STP settings to a bridge connection."""
    res = sudo_run([
        "nmcli", "connection", "modify", name,
        "bridge.stp", "yes" if stp else "no",
        "bridge.priority", str(stp_priority),
        "bridge.forward-delay", str(forward_delay),
        "bridge.hello-time", str(hello_time),
    ])
    return {"ok": res.ok, "error": (res.stderr or res.stdout).strip()}


def _apply_bridge_ipv4(name: str, addresses: list[str], gateway: str, dns_list: list[str]) -> dict:
    """Apply optional IPv4 settings to a bridge connection."""
    if addresses:
        cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.method", "manual",
            "ipv4.addresses", ",".join(addresses),
            "ipv4.gateway", gateway or "",
            "ipv4.dns", ",".join(dns_list),
            "ipv4.never-default", "no" if gateway else "yes",
            "ipv6.method", "ignore",
        ]
    else:
        cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.method", "disabled",
            "ipv4.addresses", "",
            "ipv4.gateway", "",
            "ipv4.dns", "",
            "ipv6.method", "ignore",
        ]
    res = sudo_run(cmd)
    return {"ok": res.ok, "error": (res.stderr or res.stdout).strip()}


def _reconcile_bridge_members(bridge_name: str, members: list[str], activate: bool) -> dict:
    """Create/delete bridge-slave profiles so the bridge has exactly members."""
    existing = _bridge_member_profiles(bridge_name)
    desired = set(members)
    output: list[str] = []

    for ifname, conn_name in existing.items():
        if ifname in desired:
            continue
        sudo_run(["nmcli", "connection", "down", conn_name], timeout=20)
        deleted = sudo_run(["nmcli", "connection", "delete", conn_name], timeout=20)
        text = (deleted.stdout + deleted.stderr).strip()
        if text:
            output.append(text)

    keep_connections = {bridge_name, *existing.values()}
    for ifname in members:
        slave_name = existing.get(ifname) or f"{bridge_name}-port-{ifname}"
        prep = _prepare_bridge_member(ifname, keep_connections | {slave_name})
        if not prep["ok"]:
            return {"ok": False, "error": prep["error"], "output": output}
        output.extend(prep.get("output", []))
        if ifname not in existing:
            added = sudo_run([
                "nmcli", "connection", "add", "type", "bridge-slave",
                "con-name", slave_name, "ifname", ifname, "master", bridge_name,
                "connection.zone", "trusted",
            ], timeout=30)
            text = (added.stdout + added.stderr).strip()
            if text:
                output.append(text)
            if not added.ok:
                return {"ok": False, "error": text or f"failed to add {ifname}", "output": output}
        else:
            sudo_run([
                "nmcli", "connection", "modify", slave_name,
                "connection.autoconnect", "yes",
                "connection.zone", "trusted",
            ])
        if activate:
            up = sudo_run(["nmcli", "connection", "up", slave_name], timeout=60)
            text = (up.stdout + up.stderr).strip()
            if text:
                output.append(text)
            if not up.ok:
                return {"ok": False, "error": text or f"failed to activate {slave_name}", "output": output}
    return {"ok": True, "output": output}


def _config_store() -> ConfigStore:
    """Return the persisted server-gui config store."""
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _mark_lan_bridge_connections(connections: list[dict]) -> None:
    """Annotate bridge rows that are currently referenced by LAN services."""
    lan_ifaces = _configured_lan_service_interfaces(include_firewalld=False)
    for conn in connections:
        if conn.get("type") != "bridge":
            continue
        names = {str(conn.get("name") or ""), str(conn.get("device") or "")}
        conn["is_lan_bridge"] = bool(lan_ifaces & {name for name in names if name})


def _is_bridge_lan_interface(ifname: str) -> bool:
    """Return True when dnsmasq or UPnP already points at the bridge interface."""
    return bool(ifname and ifname in _configured_lan_service_interfaces(include_firewalld=False))


def _configured_lan_service_interfaces(include_firewalld: bool = True) -> set[str]:
    """Collect interfaces that SyncA LAN-facing services currently reference."""
    interfaces = set(_dnsmasq_configured_interfaces())
    interfaces.update(_legacy_dnsmasq_interfaces())
    interfaces.update(_upnp_lan_interfaces())
    if include_firewalld:
        interfaces.update(_trusted_zone_interfaces())
    return {iface for iface in interfaces if iface}


def _load_config(module: str, default: dict) -> dict:
    """Load a JSON module config while keeping malformed files non-fatal."""
    try:
        data = _config_store().load(module, copy.deepcopy(default))
    except Exception:
        return copy.deepcopy(default)
    return data if isinstance(data, dict) else copy.deepcopy(default)


def _dnsmasq_configured_interfaces(data: dict | None = None) -> set[str]:
    """Return DHCP range interfaces from /etc/server-gui/dnsmasq.json."""
    if data is None:
        data = _load_config("dnsmasq", default_dnsmasq_config())
    ranges = (data.get("dhcp") or {}).get("ranges") or []
    return {
        str(item.get("interface", "")).strip()
        for item in ranges
        if isinstance(item, dict) and str(item.get("interface", "")).strip()
    }


def _legacy_dnsmasq_interfaces() -> set[str]:
    """Return interface tokens still present in the firstboot dnsmasq snippet."""
    try:
        text = LEGACY_FIRSTBOOT_CONFIG_PATH.read_text(encoding="utf-8")
    except OSError:
        return set()
    interfaces: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"interface\s*=\s*([A-Za-z0-9_.:-]+)", stripped)
        if m:
            interfaces.add(m.group(1))
        interfaces.update(re.findall(r"interface:([A-Za-z0-9_.:-]+)", stripped))
    return interfaces


def _default_upnp_config() -> dict:
    """Return the minimum shape needed to edit /etc/server-gui/upnp.json."""
    return {
        "enabled": False,
        "wan_interface": "",
        "lan_interfaces": [],
        "allowed_cidrs": [],
        "control_port": 5000,
        "enable_upnp": True,
        "enable_natpmp": True,
        "secure_mode": True,
    }


def _upnp_lan_interfaces(data: dict | None = None) -> set[str]:
    """Return LAN wait interfaces from /etc/server-gui/upnp.json."""
    if data is None:
        data = _load_config(_UPNP_MODULE_NAME, _default_upnp_config())
    return {
        str(iface).strip()
        for iface in data.get("lan_interfaces", []) or []
        if str(iface).strip()
    }


def _trusted_zone_interfaces() -> set[str]:
    """Return permanent firewalld trusted-zone interfaces when firewalld is reachable."""
    res = sudo_run(["firewall-cmd", "--permanent", "--zone", "trusted", "--list-interfaces"], timeout=10)
    if not res.ok:
        return set()
    return {item.strip() for item in res.stdout.split() if item.strip()}


def _firewalld_direct_rule_lines(permanent: bool = True) -> set[str]:
    """Return firewalld direct rules as raw lines; failures are treated as no data."""
    cmd = ["firewall-cmd"]
    if permanent:
        cmd.append("--permanent")
    cmd.extend(["--direct", "--get-all-rules"])
    res = sudo_run(cmd, timeout=15)
    if not res.ok:
        return set()
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


def _build_lan_bridge_migration_plan(
    bridge_ifname: str,
    members: list[str],
    requested_addresses: list[str] | None = None,
) -> dict:
    """Detect old LAN interfaces and describe service changes before applying them."""
    member_set = set(members)
    dnsmasq_data = _load_config("dnsmasq", default_dnsmasq_config())
    upnp_data = _load_config(_UPNP_MODULE_NAME, _default_upnp_config())
    direct_rules = sorted(_firewalld_direct_rule_lines(permanent=True))

    dnsmasq_ifaces = _dnsmasq_configured_interfaces(dnsmasq_data)
    legacy_ifaces = _legacy_dnsmasq_interfaces()
    upnp_ifaces = _upnp_lan_interfaces(upnp_data)
    trusted_ifaces = _trusted_zone_interfaces()
    direct_ifaces = _direct_rule_lan_interfaces(direct_rules, member_set)
    ip_ifaces = {
        member for member in members
        if _lan_ipv4_addresses_for_interface(member)
    }

    detected = {
        "dnsmasq": sorted(dnsmasq_ifaces),
        "legacy_dnsmasq": sorted(legacy_ifaces),
        "upnp": sorted(upnp_ifaces),
        "firewalld_trusted": sorted(trusted_ifaces),
        "firewalld_direct": sorted(direct_ifaces),
        "member_ipv4": sorted(ip_ifaces),
    }
    old_ifaces = sorted(
        ((dnsmasq_ifaces | legacy_ifaces | upnp_ifaces | trusted_ifaces | direct_ifaces | ip_ifaces)
         & member_set) - {bridge_ifname}
    )
    moved_addresses: list[str] = []
    for iface in old_ifaces:
        moved_addresses = _merge_lan_bridge_addresses(
            moved_addresses,
            _lan_ipv4_addresses_for_interface(iface),
        )

    direct_replacements = _direct_rule_replacements(direct_rules, old_ifaces, bridge_ifname)
    warnings: list[str] = []
    if not old_ifaces and bridge_ifname not in (dnsmasq_ifaces | legacy_ifaces | upnp_ifaces):
        warnings.append("旧LANインターフェースを検出できませんでした。DHCP/DNS/UPnP/firewalldの移行対象はありません。")
    if not moved_addresses:
        warnings.append("旧LANインターフェースのIPv4アドレスを検出できませんでした。BridgeのIPは入力値のみ使用します。")

    return {
        "bridge_if": bridge_ifname,
        "old_lan_interfaces": old_ifaces,
        "already_lan_bridge": bridge_ifname in (dnsmasq_ifaces | legacy_ifaces | upnp_ifaces),
        "detected": detected,
        "moved_addresses": moved_addresses,
        "final_bridge_addresses": _merge_lan_bridge_addresses(requested_addresses or [], moved_addresses),
        "dnsmasq_range_updates": sum(
            1 for item in (dnsmasq_data.get("dhcp") or {}).get("ranges") or []
            if isinstance(item, dict) and str(item.get("interface", "")).strip() in old_ifaces
        ),
        "legacy_dnsmasq_updates": sorted(legacy_ifaces & set(old_ifaces)),
        "upnp_updates": sorted(upnp_ifaces & set(old_ifaces)),
        "firewalld_direct_replacements": direct_replacements,
        "firewalld_trusted_add": bridge_ifname,
        "firewalld_trusted_remove": old_ifaces,
        "warnings": warnings,
    }


def _lan_ipv4_addresses_for_interface(ifname: str) -> list[str]:
    """Return stable IPv4 CIDRs from profiles first, then live addresses."""
    addresses: list[str] = []
    for profile in _connection_profiles_for_interface(ifname):
        for address in (profile.get("ipv4") or {}).get("addresses_list") or []:
            if address and address != "--":
                addresses = _merge_lan_bridge_addresses(addresses, [address])
    addresses = _merge_lan_bridge_addresses(addresses, _live_ipv4_addresses(ifname))
    return addresses


def _merge_lan_bridge_addresses(base: list[str], extra: list[str]) -> list[str]:
    """Merge IPv4 CIDRs while preserving order and ignoring malformed values."""
    merged: list[str] = []
    for value in [*base, *extra]:
        try:
            address = validate_ipv4_cidr(str(value).strip())
        except ValidationError:
            continue
        if address not in merged:
            merged.append(address)
    return merged


def _apply_bridge_lan_migration(
    bridge_ifname: str,
    members: list[str],
    bridge_addresses: list[str],
    plan: dict | None = None,
) -> dict:
    """Move SyncA-managed LAN service references from member NICs to a bridge."""
    plan = plan or _build_lan_bridge_migration_plan(bridge_ifname, members, bridge_addresses)
    if not plan.get("old_lan_interfaces") and not plan.get("already_lan_bridge"):
        return {
            "ok": False,
            "error": "旧LANインターフェースを検出できないため、LANサービス移行を中止しました。",
            "plan": plan,
        }

    if not _firewalld_running():
        return {
            "ok": False,
            "error": "firewalldが動作していないため、dnsmasqを書き換える前にLANサービス移行を中止しました。",
            "failed_step": "firewalld-preflight",
            "plan": plan,
        }

    steps: list[dict] = []
    for apply_step in (
        _apply_dnsmasq_lan_migration,
        _apply_firewalld_lan_migration,
        _apply_upnp_lan_migration,
    ):
        result = apply_step(plan)
        steps.append(result)
        if not result.get("ok"):
            return {
                "ok": False,
                "error": result.get("error") or "LANサービス移行に失敗しました",
                "failed_step": result.get("step"),
                "steps": steps,
                "plan": plan,
            }

    changed = [item for step in steps for item in step.get("changed", [])]
    warnings = [item for step in steps for item in step.get("warnings", [])]
    return {
        "ok": True,
        "message": f"LANサービスを {bridge_ifname} へ移行しました。",
        "changed": changed,
        "warnings": [*plan.get("warnings", []), *warnings],
        "steps": steps,
        "plan": plan,
    }


def _apply_dnsmasq_lan_migration(plan: dict) -> dict:
    """Update dnsmasq JSON/legacy snippet and run dnsmasq --test before restart."""
    old_ifaces = set(plan.get("old_lan_interfaces") or [])
    bridge_ifname = plan["bridge_if"]
    if not old_ifaces:
        return {"ok": True, "step": "dnsmasq", "changed": []}

    store = _config_store()
    before = store.load("dnsmasq", default_dnsmasq_config())
    if not isinstance(before, dict):
        before = default_dnsmasq_config()
    after = copy.deepcopy(before)
    changed: list[str] = []

    for item in (after.get("dhcp") or {}).get("ranges") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("interface", "")).strip() in old_ifaces:
            item["interface"] = bridge_ifname
            changed.append("dnsmasq DHCP range interface")

    legacy_backup = _read_legacy_dnsmasq_backup()
    legacy_changed = _rewrite_legacy_dnsmasq(old_ifaces, bridge_ifname)
    if legacy_changed:
        changed.append(str(LEGACY_FIRSTBOOT_CONFIG_PATH))

    if not changed:
        return {"ok": True, "step": "dnsmasq", "changed": []}

    try:
        store.save("dnsmasq", after)
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except Exception as e:
        store.save("dnsmasq", before)
        _restore_legacy_dnsmasq_backup(legacy_backup)
        return {
            "ok": False,
            "step": "dnsmasq",
            "error": f"dnsmasq --test または再起動に失敗したため移行を中止しました: {e}",
            "changed": changed,
        }
    return {"ok": True, "step": "dnsmasq", "changed": _dedupe_strings(changed)}


def _read_legacy_dnsmasq_backup() -> bytes | None:
    """Read the legacy firstboot dnsmasq snippet for rollback."""
    try:
        return LEGACY_FIRSTBOOT_CONFIG_PATH.read_bytes()
    except OSError:
        return None


def _restore_legacy_dnsmasq_backup(backup: bytes | None) -> None:
    """Restore or remove the legacy firstboot dnsmasq snippet after failure."""
    try:
        if backup is None:
            LEGACY_FIRSTBOOT_CONFIG_PATH.unlink(missing_ok=True)
        else:
            LEGACY_FIRSTBOOT_CONFIG_PATH.write_bytes(backup)
    except OSError:
        pass


def _rewrite_legacy_dnsmasq(old_ifaces: set[str], bridge_ifname: str) -> bool:
    """Replace old LAN interface tokens in /etc/dnsmasq.d/synca-lan.conf."""
    try:
        original = LEGACY_FIRSTBOOT_CONFIG_PATH.read_text(encoding="utf-8")
    except OSError:
        return False
    updated = original
    for old_iface in old_ifaces:
        updated = re.sub(
            rf"(?m)^(\s*interface\s*=\s*){re.escape(old_iface)}(\s*(?:#.*)?)$",
            lambda match: f"{match.group(1)}{bridge_ifname}{match.group(2)}",
            updated,
        )
        updated = updated.replace(f"interface:{old_iface}", f"interface:{bridge_ifname}")
    if updated == original:
        return False
    LEGACY_FIRSTBOOT_CONFIG_PATH.write_text(updated, encoding="utf-8")
    return True


def _apply_upnp_lan_migration(plan: dict) -> dict:
    """Update UPnP LAN interfaces and restart synca-upnp only when active."""
    old_ifaces = set(plan.get("old_lan_interfaces") or [])
    bridge_ifname = plan["bridge_if"]
    if not old_ifaces:
        return {"ok": True, "step": "upnp", "changed": []}

    store = _config_store()
    before = store.load(_UPNP_MODULE_NAME, _default_upnp_config())
    if not isinstance(before, dict):
        before = _default_upnp_config()
    lan_interfaces = [str(iface).strip() for iface in before.get("lan_interfaces", []) if str(iface).strip()]
    if not any(iface in old_ifaces for iface in lan_interfaces):
        return {"ok": True, "step": "upnp", "changed": []}

    after = copy.deepcopy(before)
    migrated: list[str] = []
    for iface in lan_interfaces:
        migrated.append(bridge_ifname if iface in old_ifaces else iface)
    after["lan_interfaces"] = _dedupe_strings(migrated)

    was_active = _systemd_unit_active(_SYNCA_UPNP_UNIT)
    try:
        store.save(_UPNP_MODULE_NAME, after)
        changed = ["/etc/server-gui/upnp.json"]
        if was_active:
            restart = sudo_run(["systemctl", "restart", _SYNCA_UPNP_UNIT], timeout=20)
            if not restart.ok:
                raise RuntimeError((restart.stderr or restart.stdout).strip())
            changed.append(f"systemctl restart {_SYNCA_UPNP_UNIT}")
    except Exception as e:
        store.save(_UPNP_MODULE_NAME, before)
        if was_active:
            sudo_run(["systemctl", "restart", _SYNCA_UPNP_UNIT], timeout=20)
        return {"ok": False, "step": "upnp", "error": f"UPnP設定の移行に失敗しました: {e}"}
    return {"ok": True, "step": "upnp", "changed": changed}


def _apply_firewalld_lan_migration(plan: dict) -> dict:
    """Move trusted-zone and direct FORWARD rules to the bridge interface."""
    if not _firewalld_running():
        return {
            "ok": False,
            "step": "firewalld",
            "error": "firewalldが動作していないため、LAN向けfirewalld設定を移行できません。",
        }

    bridge_ifname = plan["bridge_if"]
    changed: list[str] = []
    errors: list[str] = []
    _collect_firewalld_change(
        ["firewall-cmd", "--permanent", "--zone", "trusted", "--add-interface", bridge_ifname],
        changed, errors,
    )
    _collect_firewalld_change(
        ["firewall-cmd", "--permanent", "--zone", "trusted", "--add-forward"],
        changed, errors,
    )
    for service in ("dhcp", "dns"):
        _collect_firewalld_change(
            ["firewall-cmd", "--permanent", "--zone", "trusted", "--add-service", service],
            changed, errors,
        )
    for old_iface in plan.get("firewalld_trusted_remove") or []:
        _collect_firewalld_change(
            ["firewall-cmd", "--permanent", "--zone", "trusted", "--remove-interface", old_iface],
            changed, errors,
            ignore_missing=True,
        )

    existing = _firewalld_direct_rule_lines(permanent=True)
    for item in plan.get("firewalld_direct_replacements") or []:
        raw = item["raw"]
        replacement = item["replacement"]
        if replacement not in existing:
            new_rule = _parse_direct_rule_line(replacement)
            if new_rule:
                before_errors = len(errors)
                _collect_firewalld_change(
                    ["firewall-cmd", "--permanent", "--direct", "--add-rule",
                     new_rule["ipv"], new_rule["table"], new_rule["chain"],
                     str(new_rule["priority"]), *new_rule["args"]],
                    changed, errors,
                )
                if len(errors) != before_errors:
                    continue
                existing.add(replacement)
        if raw in existing:
            old_rule = _parse_direct_rule_line(raw)
            if old_rule:
                _collect_firewalld_change(
                    ["firewall-cmd", "--permanent", "--direct", "--remove-rule",
                     old_rule["ipv"], old_rule["table"], old_rule["chain"],
                     str(old_rule["priority"]), *old_rule["args"]],
                    changed, errors,
                    ignore_missing=True,
                )
                existing.discard(raw)

    if errors:
        return {"ok": False, "step": "firewalld", "error": "\n".join(errors), "changed": changed}
    if changed:
        reload_res = sudo_run(["firewall-cmd", "--reload"], timeout=30)
        if not reload_res.ok:
            return {
                "ok": False,
                "step": "firewalld",
                "error": (reload_res.stderr or reload_res.stdout).strip() or "firewalld reloadに失敗しました",
                "changed": changed,
            }
        changed.append("firewall-cmd --reload")
    return {"ok": True, "step": "firewalld", "changed": _dedupe_strings(changed)}


def _firewalld_running() -> bool:
    """Return True when firewalld is available for permanent changes."""
    return sudo_run(["firewall-cmd", "--state"], timeout=10).ok


def _collect_firewalld_change(
    cmd: list[str],
    changed: list[str],
    errors: list[str],
    ignore_missing: bool = False,
) -> None:
    """Run a firewalld command and treat idempotent messages as success."""
    res = sudo_run(cmd, timeout=30)
    output = (res.stderr or res.stdout).strip()
    if res.ok:
        changed.append(" ".join(shlex.quote(part) for part in cmd))
        return
    if "ALREADY_ENABLED" in output:
        return
    if ignore_missing and (
        "NOT_ENABLED" in output or "not enabled" in output or "not in list" in output
    ):
        return
    errors.append(output or "firewalld command failed: " + " ".join(cmd))


def _direct_rule_lan_interfaces(direct_rules: list[str], members: set[str]) -> set[str]:
    """Return member interfaces that appear in replaceable LAN direct rules."""
    interfaces: set[str] = set()
    for raw in direct_rules:
        for member in members:
            if _rewrite_direct_rule_for_lan_bridge(raw, member, "br-synca-preview"):
                interfaces.add(member)
    return interfaces


def _direct_rule_replacements(direct_rules: list[str], old_ifaces: list[str], bridge_ifname: str) -> list[dict]:
    """Build direct-rule replacement rows without touching firewalld."""
    replacements: list[dict] = []
    for raw in direct_rules:
        new_raw = raw
        reasons: list[str] = []
        matched_old: list[str] = []
        for old_iface in old_ifaces:
            item = _rewrite_direct_rule_for_lan_bridge(new_raw, old_iface, bridge_ifname)
            if not item:
                continue
            new_raw = item["replacement"]
            reasons.append(item["reason"])
            matched_old.append(old_iface)
        if new_raw != raw:
            replacements.append({
                "raw": raw,
                "replacement": new_raw,
                "old_interfaces": matched_old,
                "reason": " / ".join(_dedupe_strings(reasons)),
            })
    return replacements


def _rewrite_direct_rule_for_lan_bridge(raw: str, old_iface: str, bridge_ifname: str) -> dict | None:
    """Return a rewritten direct rule when the rule is a LAN-side SyncA pattern."""
    rule = _parse_direct_rule_line(raw)
    if not rule or rule["ipv"] != "ipv4":
        return None
    args = list(rule["args"])
    if _has_managed_port_forward_comment(args):
        return None

    changed = False
    reason = ""
    if rule["table"] == "filter" and rule["chain"] == "FORWARD":
        if _arg_value(args, "-i") == old_iface and _jump_target(args) == "ACCEPT":
            args = _replace_arg_value(args, "-i", bridge_ifname)
            changed = True
            reason = "LAN発信FORWARD"
        if _arg_value(args, "-o") == old_iface and _jump_target(args) == "ACCEPT" and _has_related_state(args):
            args = _replace_arg_value(args, "-o", bridge_ifname)
            changed = True
            reason = "LAN戻りFORWARD"
    elif rule["table"] == "nat" and rule["chain"] == "POSTROUTING":
        if _jump_target(args) in {"MASQUERADE", "SNAT", "ACCEPT"}:
            if _arg_value(args, "-i") == old_iface:
                args = _replace_arg_value(args, "-i", bridge_ifname)
                changed = True
                reason = "NAT入力IF"
            if _arg_value(args, "-o") == old_iface:
                args = _replace_arg_value(args, "-o", bridge_ifname)
                changed = True
                reason = "NAT出力IF"

    if not changed:
        return None
    replacement = _format_direct_rule({
        **rule,
        "args": args,
    })
    return {"raw": raw, "replacement": replacement, "reason": reason}


def _parse_direct_rule_line(raw: str) -> dict | None:
    """Parse one `firewall-cmd --direct --get-all-rules` line."""
    try:
        parts = shlex.split(raw)
    except ValueError:
        return None
    if len(parts) < 5:
        return None
    return {
        "ipv": parts[0],
        "table": parts[1],
        "chain": parts[2],
        "priority": parts[3],
        "args": parts[4:],
    }


def _format_direct_rule(rule: dict) -> str:
    """Render a direct rule to a stable single-line representation."""
    parts = [rule["ipv"], rule["table"], rule["chain"], str(rule["priority"]), *rule["args"]]
    return " ".join(shlex.quote(str(part)) for part in parts)


def _arg_value(args: list[str], key: str) -> str:
    """Return the value after an iptables-style argument key."""
    try:
        idx = args.index(key)
    except ValueError:
        return ""
    if idx + 1 >= len(args):
        return ""
    return args[idx + 1]


def _replace_arg_value(args: list[str], key: str, value: str) -> list[str]:
    """Replace every value paired with an iptables-style argument key."""
    replaced = list(args)
    for idx, item in enumerate(replaced[:-1]):
        if item == key:
            replaced[idx + 1] = value
    return replaced


def _jump_target(args: list[str]) -> str:
    """Return the iptables -j target."""
    return _arg_value(args, "-j").upper()


def _has_related_state(args: list[str]) -> bool:
    """Detect RELATED,ESTABLISHED state or conntrack matches."""
    values: list[str] = []
    for key in ("--state", "--ctstate"):
        value = _arg_value(args, key)
        if value:
            values.extend(part.strip().upper() for part in value.split(","))
    return "RELATED" in values and "ESTABLISHED" in values


def _has_managed_port_forward_comment(args: list[str]) -> bool:
    """Avoid rewriting scoped port/protocol forward rules owned by firewall.py."""
    return any(
        "synca-forward-port:" in arg or "synca-protocol-forward:" in arg
        for arg in args
    )


def _systemd_unit_active(unit: str) -> bool:
    """Return True when a systemd unit is currently active."""
    return sudo_run(["systemctl", "is-active", "--quiet", unit], timeout=10).ok


def _dedupe_strings(values: list[str]) -> list[str]:
    """Return unique strings in input order."""
    out: list[str] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def _device_ip_map() -> dict[str, dict]:
    """Return {ifname: {ipv4: [...], ipv6: [...], mac: str, mtu: int}}."""
    res = run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return {}
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return {}
    out: dict[str, dict] = {}
    for entry in data:
        name = entry.get("ifname")
        if not name:
            continue
        v4: list[str] = []
        v6: list[str] = []
        for a in entry.get("addr_info", []):
            family = a.get("family")
            addr = f"{a.get('local')}/{a.get('prefixlen')}"
            if family == "inet":
                v4.append(addr)
            elif family == "inet6":
                # Skip link-local (fe80::/10) to keep the table tidy
                if not (a.get("scope") == "link"):
                    v6.append(addr)
        out[name] = {
            "ipv4": v4,
            "ipv6": v6,
            "mac": entry.get("address"),
            "mtu": entry.get("mtu"),
        }
    return out


def _list_connections() -> list[dict]:
    rows = _nmcli_terse(["-f", "NAME,UUID,TYPE,DEVICE", "connection", "show"])
    conns = []
    for r in rows:
        if len(r) < 4:
            continue
        conns.append({
            "name": r[0],
            "uuid": r[1],
            "type": r[2],
            "device": r[3] or None,
        })
    return conns


def _describe_connection(name: str) -> dict:
    """Return summarized ipv4 settings + a curated subset of fields."""
    res = run(["nmcli", "-t", "-e", "no", "connection", "show", name])
    if not res.ok:
        return {"error": "connection not found", "stderr": res.stderr.strip()}
    raw: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        raw[k.strip()] = v.strip()

    addresses = _split_nm_list(raw.get("ipv4.addresses", ""))
    ipv4 = {
        "method": raw.get("ipv4.method"),
        "addresses": raw.get("ipv4.addresses"),
        "addresses_list": addresses,
        "gateway": raw.get("ipv4.gateway"),
        "dns": raw.get("ipv4.dns"),
        "dns_search": raw.get("ipv4.dns-search"),
    }
    routes = _parse_nm_routes(raw.get("ipv4.routes", ""))
    live = {
        "ip4_address": raw.get("IP4.ADDRESS[1]"),
        "ip4_gateway": raw.get("IP4.GATEWAY"),
        "ip4_dns": [v for k, v in raw.items() if k.startswith("IP4.DNS")],
    }
    pppoe = None
    if raw.get("connection.type") == "pppoe":
        parent = raw.get("connection.interface-name")
        pppoe = {
            "username": raw.get("pppoe.username"),
            # password is not returned by nmcli (it's a Secret); placeholder only
            "mtu": raw.get("ppp.mtu") or raw.get("802-3-ethernet.mtu"),
            "mru": raw.get("ppp.mru"),
            "parent": parent,
            "service": raw.get("pppoe.service"),
        }
        pppoe["parent_ip"] = _pppoe_parent_ip_status(parent)
    bridge = None
    if raw.get("connection.type") == "bridge":
        bridge = {
            "stp": raw.get("bridge.stp") == "yes",
            "priority": raw.get("bridge.priority"),
            "forward_delay": raw.get("bridge.forward-delay"),
            "hello_time": raw.get("bridge.hello-time"),
        }
    return {
        "name": raw.get("connection.id", name),
        "uuid": raw.get("connection.uuid"),
        "type": raw.get("connection.type"),
        "interface": raw.get("connection.interface-name") or raw.get("GENERAL.DEVICES"),
        "master": raw.get("connection.master"),
        "slave_type": raw.get("connection.slave-type"),
        "autoconnect": raw.get("connection.autoconnect") == "yes",
        "state": raw.get("GENERAL.STATE"),
        "ipv4": ipv4,
        "live": live,
        "pppoe": pppoe,
        "bridge": bridge,
        "routes": routes,
    }


def _split_nm_list(value: str) -> list[str]:
    s = (value or "").strip()
    if not s or s == "--":
        return []
    return [part.strip() for part in re.split(r"\s*,\s*|\s*;\s*", s) if part.strip()]


# ---- static routes -----------------------------------------------------

def _parse_nm_routes(value: str) -> list[dict]:
    """Parse nmcli's `ipv4.routes` terse-format value into a list of dicts.

    Accepts inputs like:
        ""                                          (no routes — also "--")
        "{ ip = 10.0.0.0/24, nh = 192.168.1.1 }"   (single)
        "{ ip = 10/24, nh = 1.2.3.4 }; { ip = 172.16/16, nh = 10.0.0.1, mt = 100 }"

    Returns: [{"dest": "10.0.0.0/24", "gateway": "192.168.1.1", "metric": None|int}, …]
    """
    s = (value or "").strip()
    if not s or s == "--":
        return []
    out: list[dict] = []
    chunks = re.findall(r"\{\s*(.+?)\s*\}", s)
    if chunks:
        for chunk in chunks:
            route: dict = {"dest": "", "gateway": "", "metric": None}
            for pair in chunk.split(","):
                k, _, v = pair.partition("=")
                k = k.strip()
                v = v.strip()
                if k == "ip":
                    route["dest"] = v
                elif k == "nh":
                    # NM stores no-gateway link-scope routes as "0.0.0.0"; hide.
                    route["gateway"] = "" if v == "0.0.0.0" else v
                elif k == "mt":
                    try:
                        route["metric"] = int(v)
                    except ValueError:
                        pass
            if route["dest"]:
                out.append(route)
        return out

    # Older nmcli builds may show routes as `dest gateway metric` entries.
    for chunk in re.split(r"\s*[,;]\s*", s.replace("\\;", ";")):
        parts = chunk.split()
        if not parts:
            continue
        route: dict = {"dest": "", "gateway": "", "metric": None}
        route["dest"] = parts[0]
        if len(parts) > 1:
            route["gateway"] = "" if parts[1] == "0.0.0.0" else parts[1]
        if len(parts) > 2:
            try:
                route["metric"] = int(parts[2])
            except ValueError:
                pass
        if route["dest"]:
            out.append(route)
    return out


def _route_spec(route: dict) -> str:
    """Render a single route back to nmcli's `ipv4.routes` spec format.

    nmcli accepts: `<dest>[ <next_hop>[ <metric>]]`
    The gateway field is REQUIRED if metric is given — NM uses 0.0.0.0
    as the sentinel for "no gateway / link-scope route".
    """
    parts = [route["dest"]]
    gw = (route.get("gateway") or "").strip() or "0.0.0.0"
    parts.append(gw)
    metric = route.get("metric")
    if metric is not None and metric != "":
        parts.append(str(int(metric)))
    return " ".join(parts)


def _validate_route(payload: dict) -> dict:
    """Validate + normalise a {dest, gateway, metric} payload."""
    dest = (payload.get("dest") or "").strip()
    gateway = (payload.get("gateway") or "").strip()
    metric_raw = payload.get("metric")
    if not dest:
        raise ValidationError("dest required (例: 10.0.0.0/24)")
    dest = validate_ipv4_cidr(dest)
    # Gateway is REQUIRED for first release (link-scope/blackhole/etc. later)
    if not gateway:
        raise ValidationError("gateway required (例: 192.168.1.254)")
    gateway = validate_ipv4(gateway)
    metric: Optional[int] = None
    if metric_raw not in (None, "", "null"):
        try:
            metric = int(metric_raw)
        except (TypeError, ValueError):
            raise ValidationError("metric must be an integer")
        if not (0 <= metric <= 4294967295):
            raise ValidationError("metric out of range (0..4294967295)")
    return {"dest": dest, "gateway": gateway, "metric": metric}


def _set_nm_routes(name: str, routes: list[dict], reapply: bool = True) -> dict:
    """Push the full routes list to NetworkManager + reapply to live device.

    `nmcli connection modify <name> ipv4.routes "<spec>, <spec>, …"` REPLACES
    the routes list (rather than +/- which appends/removes). Empty string
    clears all routes.

    `nmcli device reapply <iface>` applies pending changes without dropping
    the link — far gentler than `connection up` for adjusting routes on the
    user's own management connection.
    """
    spec = ", ".join(_route_spec(r) for r in routes)
    args = ["nmcli", "connection", "modify", name, "ipv4.routes"]
    args.append(spec if spec else "")  # nmcli accepts "" to clear
    res = sudo_run(args)
    if not res.ok:
        return {"ok": False, "stderr": (res.stderr or res.stdout).strip()}
    if reapply:
        # Find the device this connection is attached to (live)
        det = _describe_connection(name)
        iface = (det or {}).get("interface")
        if iface:
            re_res = sudo_run(["nmcli", "device", "reapply", iface])
            # reapply can fail if the device isn't currently connected; that's
            # fine — the next `nmcli connection up` will pick up the new routes
            if not re_res.ok:
                return {"ok": True, "warning": f"reapply skipped: {re_res.stderr.strip()}"}
    return {"ok": True}


@bp.route("/api/connections/<name>/routes", methods=["GET"])
@login_required
def list_routes(name: str):
    detail = _describe_connection(name)
    if detail.get("error"):
        return jsonify(detail), 404
    return jsonify({"routes": detail.get("routes", [])})


@bp.route("/api/connections/<name>/routes", methods=["POST"])
@login_required
@csrf_protect
def add_route(name: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        route = _validate_route(payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    detail = _describe_connection(name)
    if detail.get("error"):
        return jsonify(detail), 404
    existing = list(detail.get("routes", []))
    # Reject exact duplicate (same dest + gateway). Different metrics OK.
    for r in existing:
        if r["dest"] == route["dest"] and r.get("gateway", "") == route["gateway"] \
                and r.get("metric") == route.get("metric"):
            return jsonify({"error": "identical route already exists"}), 409
    existing.append(route)
    res = _set_nm_routes(name, existing)
    if not res["ok"]:
        return jsonify({"error": res.get("stderr") or "nmcli failed"}), 500
    return jsonify({"ok": True, "route": route, "warning": res.get("warning")}), 201


@bp.route("/api/connections/<name>/routes/<int:idx>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_route(name: str, idx: int):
    detail = _describe_connection(name)
    if detail.get("error"):
        return jsonify(detail), 404
    routes = list(detail.get("routes", []))
    if idx < 0 or idx >= len(routes):
        return jsonify({"error": "index out of range"}), 404
    removed = routes.pop(idx)
    res = _set_nm_routes(name, routes)
    if not res["ok"]:
        return jsonify({"error": res.get("stderr") or "nmcli failed"}), 500
    return jsonify({"ok": True, "removed": removed, "warning": res.get("warning")})


@bp.route("/api/wan", methods=["GET"])
@login_required
def get_wan():
    """Identify the WAN interface (default-route bearer) and its current type."""
    wan_dev = _default_route_device()
    wan_gw = ""
    route = run(["ip", "-j", "route", "show", "default"])
    if route.ok:
        try:
            routes = json.loads(route.stdout)
            if routes:
                wan_gw = routes[0].get("gateway", "")
        except json.JSONDecodeError:
            pass

    # Resolve the connection profile attached to that device
    wan_conn = None
    wan_type = "unknown"
    if wan_dev:
        for c in _list_connections():
            if c.get("device") == wan_dev:
                wan_conn = c
                break
        if not wan_conn and wan_dev.startswith("ppp"):
            wan_conn = _active_pppoe_connection()
    if wan_conn:
        details = _describe_connection(wan_conn["name"])
        if wan_conn["type"] == "pppoe":
            wan_type = "pppoe"
        elif details.get("ipv4", {}).get("method") == "manual":
            wan_type = "static"
        elif details.get("ipv4", {}).get("method") == "auto":
            wan_type = "dhcp"
        else:
            wan_type = wan_conn.get("type", "unknown")
        # Always include the WAN device name from the default route so the
        # frontend has a single field to check regardless of whether we
        # found a managed connection profile.
        details["device"] = wan_dev
        if wan_type == "pppoe":
            details["pppoe_parent"] = (details.get("pppoe") or {}).get("parent") or details.get("interface")
            details["pppoe_parent_ip"] = _pppoe_parent_ip_status(details["pppoe_parent"])
        details["wan_type"] = wan_type
        details["wan_gateway"] = wan_gw
        return jsonify(details)
    return jsonify({"wan_type": "unknown", "device": wan_dev, "wan_gateway": wan_gw})


def _apply_ipv4(name: str, payload: dict) -> dict:
    """Apply an ipv4 mode + (optional) static settings to a connection."""
    mode = payload.get("method")
    if mode not in ("manual", "auto"):
        raise ValidationError("method must be 'manual' or 'auto'")

    if mode == "manual":
        addresses_raw = payload.get("addresses")
        primary = (payload.get("address") or "").strip()
        secondary_raw = payload.get("secondary_addresses") or []
        addresses = _normalize_ipv4_addresses(primary, secondary_raw, addresses_raw)
        if not addresses:
            raise ValidationError("address required for manual mode (e.g. 192.168.1.1/24)")
        gateway: Optional[str] = payload.get("gateway") or None
        if gateway:
            validate_ipv4(gateway)
        dns_list = payload.get("dns") or []
        if not isinstance(dns_list, list):
            raise ValidationError("dns must be a list")
        for d in dns_list:
            validate_ipv4(d)

        cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.addresses", ",".join(addresses),
            "ipv4.gateway", gateway or "",
            "ipv4.dns", ",".join(dns_list),
            "ipv4.never-default", "no" if gateway else "yes",
            "ipv4.method", "manual",
            "ipv6.method", "ignore",
        ]
    else:  # auto / DHCP
        cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.method", "auto",
            "ipv4.addresses", "",
            "ipv4.gateway", "",
            "ipv4.never-default", "no",
        ]
        # Leave DNS alone (auto can still get DNS from DHCP)

    # NetworkManager validates manual profiles after each modify command. Apply
    # address, gateway, DNS, and method atomically so an auto profile can become
    # manual even when it did not previously have ipv4.addresses.
    res = sudo_run(cmd)
    if not res.ok:
        return {"ok": False, "error": "nmcli IPv4 設定変更に失敗しました", "stderr": res.stderr.strip()}

    # Bring the connection back up so changes take effect
    if payload.get("activate", True):
        up = sudo_run(["nmcli", "connection", "up", name])
        if not up.ok:
            return {
                "ok": True,
                "activated": False,
                "warning": "IPv4 設定は保存しましたが、接続を up できませんでした。",
                "stderr": up.stderr.strip(),
            }

    return {"ok": True, "activated": bool(payload.get("activate", True))}
