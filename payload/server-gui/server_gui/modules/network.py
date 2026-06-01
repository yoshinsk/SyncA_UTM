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

import ipaddress
import json
from typing import Optional

from flask import Blueprint, Flask, jsonify, render_template, request

import re

from ..auth import csrf_protect, login_required
from ..shell import run, sudo_run
from ..validators import ValidationError, validate_interface, validate_ipv4, validate_ipv4_cidr

_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{0,63}$")

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
    return jsonify({"devices": _list_devices(), "connections": _list_connections()})


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
        "address":       "192.168.1.1/24",  # optional LAN IP (manual)
        "gateway":       "",                 # optional, usually empty for LAN
        "dns":           ["8.8.8.8"],        # optional, list of IPs
        "stp":           true,
        "stp_priority":  32768,              # 0-65535
        "forward_delay": 4,                  # seconds, 2-30
        "hello_time":    2,                  # seconds, 1-10
        "autoconnect":   true,
        "activate":      true
      }

    Rolls back (deletes bridge + slaves) on any partial failure.
    """
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip()
    ifname = (payload.get("ifname") or name).strip()
    members_raw = payload.get("members") or []
    address = (payload.get("address") or "").strip()
    gateway = (payload.get("gateway") or "").strip()
    dns_raw = payload.get("dns") or []
    stp = bool(payload.get("stp", True))
    stp_priority = int(payload.get("stp_priority", 32768))
    forward_delay = int(payload.get("forward_delay", 4))
    hello_time = int(payload.get("hello_time", 2))
    autoconnect = bool(payload.get("autoconnect", True))
    activate = bool(payload.get("activate", True))

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
    if address:
        try:
            validate_ipv4_cidr(address)
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

    # ---- create bridge ----
    add_cmd = [
        "nmcli", "connection", "add", "type", "bridge",
        "con-name", name, "ifname", ifname,
        "connection.autoconnect", "yes" if autoconnect else "no",
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
    if address:
        ipv4_cmd = [
            "nmcli", "connection", "modify", name,
            "ipv4.method", "manual",
            "ipv4.addresses", address,
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
        slave_res = sudo_run([
            "nmcli", "connection", "add", "type", "bridge-slave",
            "con-name", slave_name, "ifname", m, "master", name,
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

    return jsonify({
        "ok": True, "name": name, "ifname": ifname,
        "members": members, "stp": stp, "address": address,
        "output": output,
    }), 201


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
        sudo_run(["nmcli", "connection", "modify", name, "ipv4.method", "disabled"])

    output = res.stdout + res.stderr
    if activate:
        up = sudo_run(["nmcli", "connection", "up", name], timeout=60)
        output += "\n--- up ---\n" + (up.stdout + up.stderr)
        if not up.ok:
            return jsonify({
                "ok": False, "created": True, "activated": False,
                "error": "created but failed to activate",
                "output": output.strip(),
            }), 500

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
    return jsonify({"ok": True, "changed": changed})


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
        devices.append({
            "device": name,
            "type": r[1],
            "state": state,
            "connection": connection,
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
    res = run(["nmcli", "-t", "connection", "show", name])
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
        pppoe = {
            "username": raw.get("pppoe.username"),
            # password is not returned by nmcli (it's a Secret); placeholder only
            "mtu": raw.get("802-3-ethernet.mtu"),
            "parent": raw.get("connection.interface-name"),
            "service": raw.get("pppoe.service"),
        }
    return {
        "name": raw.get("connection.id", name),
        "uuid": raw.get("connection.uuid"),
        "type": raw.get("connection.type"),
        "interface": raw.get("connection.interface-name") or raw.get("GENERAL.DEVICES"),
        "autoconnect": raw.get("connection.autoconnect") == "yes",
        "state": raw.get("GENERAL.STATE"),
        "ipv4": ipv4,
        "live": live,
        "pppoe": pppoe,
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
    for chunk in s.split(";"):
        chunk = chunk.strip()
        m = re.match(r"^\{\s*(.+?)\s*\}$", chunk)
        if not m:
            continue
        route: dict = {"dest": "", "gateway": "", "metric": None}
        for pair in m.group(1).split(","):
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
        details["wan_type"] = wan_type
        details["wan_gateway"] = wan_gw
        return jsonify(details)
    return jsonify({"wan_type": "unknown", "device": wan_dev, "wan_gateway": wan_gw})


def _apply_ipv4(name: str, payload: dict) -> dict:
    """Apply an ipv4 mode + (optional) static settings to a connection."""
    mode = payload.get("method")
    if mode not in ("manual", "auto"):
        raise ValidationError("method must be 'manual' or 'auto'")

    modifications: list[list[str]] = []

    if mode == "manual":
        addresses_raw = payload.get("addresses")
        if isinstance(addresses_raw, list):
            addresses = [str(a).strip() for a in addresses_raw if str(a).strip()]
        else:
            primary = (payload.get("address") or "").strip()
            secondary_raw = payload.get("secondary_addresses") or []
            addresses = [primary] if primary else []
            if isinstance(secondary_raw, list):
                addresses.extend(str(a).strip() for a in secondary_raw if str(a).strip())
        if not addresses:
            raise ValidationError("address required for manual mode (e.g. 192.168.1.1/24)")
        for address in addresses:
            validate_ipv4_cidr(address)
        gateway: Optional[str] = payload.get("gateway") or None
        if gateway:
            validate_ipv4(gateway)
        dns_list = payload.get("dns") or []
        if not isinstance(dns_list, list):
            raise ValidationError("dns must be a list")
        for d in dns_list:
            validate_ipv4(d)

        modifications.append(["ipv4.method", "manual"])
        modifications.append(["ipv4.addresses", ",".join(addresses)])
        modifications.append(["ipv4.gateway", gateway or ""])
        modifications.append(["ipv4.dns", ",".join(dns_list)])
    else:  # auto / DHCP
        modifications.append(["ipv4.method", "auto"])
        modifications.append(["ipv4.addresses", ""])
        modifications.append(["ipv4.gateway", ""])
        # Leave DNS alone (auto can still get DNS from DHCP)

    # Apply all modifications first
    for key, value in modifications:
        # nmcli accepts "" to clear a property
        cmd = ["nmcli", "connection", "modify", name, key, value]
        res = sudo_run(cmd)
        if not res.ok:
            return {"ok": False, "error": f"nmcli modify {key} failed", "stderr": res.stderr.strip()}

    # Bring the connection back up so changes take effect
    if payload.get("activate", True):
        up = sudo_run(["nmcli", "connection", "up", name])
        if not up.ok:
            return {"ok": False, "error": "connection up failed", "stderr": up.stderr.strip()}

    return {"ok": True}
