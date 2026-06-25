"""payload/server-gui/server_gui/modules/wireguard.py - Manage WireGuard interfaces and peers.

Storage: /etc/server-gui/wireguard.json (file mode 0600 via ConfigStore.save)
    {
      "peers": {
        "<pubkey>": {
          "interface": "wg0",
          "comment": "yoshi-iphone",
          "private_key": "...",            # client privkey, server-side stored
          "preshared_key": "...",          # optional
          "peer_address": "10.252.1.42/32",   # client's VPN IP (single /32 typical)
          "extra_allowed_ips": ["192.168.50.0/24"],  # subnets routed BEHIND peer
          "client_dns": ["10.252.1.1"],
          "client_mtu": null,
          "client_allowed_ips": ["0.0.0.0/0", "::/0"],
          "endpoint": "vpn.example.com:51820",
          "persistent_keepalive": 25,
          "enabled": true,
          "created_at": "2026-05-15T...",
          "updated_at": "2026-05-15T..."
        }
      }
    }

Workflow:
  - Add peer: server generates keys + PSK → stored in JSON → wg conf updated
  - Edit peer: stored metadata is the source of truth → wg conf is regenerated
  - Show / download config / QR: anytime (private key comes from JSON)
  - Pre-existing peers without metadata can still be viewed/deleted, but their
    client config cannot be regenerated (private key unknown).
"""
from __future__ import annotations

import datetime as _dt
import base64
import binascii
import csv
import io
import ipaddress
import json
import logging
import os
import re
import shlex
import zipfile
from pathlib import Path
from typing import Optional

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required, verify_admin_password
from ..config_store import ConfigStore
from ..shell import run, sudo_run
from ..validators import ValidationError, validate_ipv4, validate_ipv4_cidr

logger = logging.getLogger(__name__)

bp = Blueprint("wireguard", __name__, url_prefix="/wg")

WG_DIR = Path("/etc/wireguard")
INTERFACE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,14}$")
MODULE_NAME = "wireguard"

# Table directive accepts "auto" (default), "off" (no auto-routes), or a
# numeric routing table id (RT_TABLE — kernel allows 0..2^32-1 but in
# practice 0..9999 is plenty).
_TABLE_RE = re.compile(r"^(off|auto|\d{1,5})$")

# PostUp / PostDown are arbitrary shell commands executed by wg-quick as
# root. The threat model already trusts the authenticated GUI admin (they
# have full sudo through the rest of the app), but we still cap length
# and reject control characters that could break the conf-file format.
_POST_CMD_MAX_LEN = 512
_MAX_POST_CMDS = 8
_WIREGUARD_LAN_TCP_MSS = 1360


def register(app: Flask) -> None:
    app.register_blueprint(bp)
    _sync_firewalld_for_interfaces_on_startup(app)


def _sync_firewalld_for_interfaces_on_startup(app: Flask) -> None:
    """Repair managed WireGuard firewalld rules when server-gui starts."""
    if os.environ.get("SYNCA_SKIP_WIREGUARD_FIREWALL_STARTUP_SYNC") == "1":
        return
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        import fcntl

        lock_path = Path("/run/server-gui-wireguard-firewall-sync.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            with app.app_context():
                if not WG_DIR.exists():
                    return
                for path in sorted(WG_DIR.glob("*.conf")):
                    iface = path.stem
                    if INTERFACE_RE.match(iface) and _interface_is_active(iface):
                        _sync_firewalld_for_interface(iface, _parse_wg_conf(path))
    except Exception as e:
        logger.warning("startup WireGuard firewalld sync failed: %s", e)


# ---- storage ------------------------------------------------------------

def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default_data() -> dict:
    return {"peers": {}}


def _load_data() -> dict:
    """Load metadata while tolerating the older interface-list JSON shape."""
    data = _store().load(MODULE_NAME, _default_data())
    if not isinstance(data, dict):
        return _default_data()
    peers = data.get("peers")
    if isinstance(peers, dict):
        return data
    normalized = dict(data)
    normalized["peers"] = {}
    return normalized


def _load_meta(pubkey: str) -> Optional[dict]:
    data = _load_data()
    return data["peers"].get(pubkey)


def _save_meta(pubkey: str, meta: dict) -> None:
    with _store().transaction(MODULE_NAME, _default_data()) as data:
        data.setdefault("peers", {})
        data["peers"][pubkey] = meta


def _save_many_meta(items: list[tuple[str, dict]]) -> None:
    with _store().transaction(MODULE_NAME, _default_data()) as data:
        data.setdefault("peers", {})
        for pubkey, meta in items:
            data["peers"][pubkey] = meta


def _delete_meta(pubkey: str) -> None:
    with _store().transaction(MODULE_NAME, _default_data()) as data:
        data.setdefault("peers", {})
        data["peers"].pop(pubkey, None)


def _delete_many_meta(pubkeys: list[str]) -> None:
    """Remove multiple peer metadata entries in one config-store transaction."""
    target = set(pubkeys)
    if not target:
        return
    with _store().transaction(MODULE_NAME, _default_data()) as data:
        data.setdefault("peers", {})
        for pubkey in target:
            data["peers"].pop(pubkey, None)


def _rename_pubkey_meta(old_pubkey: str, new_pubkey: str, new_meta: dict) -> None:
    """Used by regenerate-keys: move metadata to a new pubkey key."""
    with _store().transaction(MODULE_NAME, _default_data()) as data:
        data.setdefault("peers", {})
        data["peers"].pop(old_pubkey, None)
        data["peers"][new_pubkey] = new_meta


def _pubkey_from_route(pubkey: str | None, pubkey_token: str | None) -> str | None:
    """Decode route parameters without letting leading slashes corrupt URLs."""
    if pubkey is not None:
        return pubkey
    if not pubkey_token or not re.match(r"^[A-Za-z0-9_-]{1,128}$", pubkey_token):
        return None
    try:
        padded = pubkey_token + ("=" * (-len(pubkey_token) % 4))
        value = base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not re.match(r"^[A-Za-z0-9+/]{43}=$", value):
        return None
    return value


def _normalize_pubkey_list(value: object) -> list[str]:
    """Return a de-duplicated list of WireGuard public keys from JSON input."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        pubkey = str(item or "").strip()
        if not re.match(r"^[A-Za-z0-9+/]{43}=$", pubkey):
            continue
        if pubkey in seen:
            continue
        seen.add(pubkey)
        out.append(pubkey)
    return out


# ---- views --------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("wireguard.html", active_tab="wireguard")


@bp.route("/api/interfaces", methods=["GET"])
@login_required
def list_interfaces():
    items: list[dict] = []
    if WG_DIR.exists():
        for p in sorted(WG_DIR.glob("*.conf")):
            name = p.stem
            if not INTERFACE_RE.match(name):
                continue
            items.append({"name": name, "path": str(p), "active": _interface_is_active(name)})
    return jsonify({
        "interfaces": items,
        "wan_endpoint": _detect_wan_endpoint(),
        "endpoint_candidates": _detect_endpoint_candidates(),
    })


@bp.route("/api/interfaces/<iface>", methods=["GET"])
@login_required
def get_interface(iface: str):
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    parsed = _parse_wg_conf(path)
    live = _wg_show_dump(iface)

    # Server public key
    server_pub = live["interface"].get("public_key")
    if not server_pub and parsed["interface"].get("private_key"):
        server_pub = _pubkey_from_priv(parsed["interface"]["private_key"])

    # Build merged peer list: conf + metadata + live status
    data = _load_data()
    peers_meta = data["peers"]
    listen_port = parsed["interface"].get("listen_port")

    merged_peers: list[dict] = []
    for p in parsed["peers"]:
        pubkey = p.get("public_key") or ""
        meta = peers_meta.get(pubkey, {})
        status = live["peers_status"].get(pubkey, {})
        merged_peers.append({
            "public_key": pubkey,
            "comment": meta.get("comment") or p.get("comment") or "",
            "account_name": meta.get("account_name") or meta.get("comment") or p.get("comment") or "",
            "display_name": meta.get("display_name", ""),
            "peer_address": meta.get("peer_address") or (p.get("allowed_ips", [None])[0] if p.get("allowed_ips") else None),
            "allowed_ips_in_conf": p.get("allowed_ips", []),
            "extra_allowed_ips": meta.get("extra_allowed_ips", []),
            "endpoint": _effective_client_endpoint(meta.get("endpoint"), listen_port),
            "client_dns": meta.get("client_dns", []),
            "client_mtu": meta.get("client_mtu"),
            "client_allowed_ips": meta.get("client_allowed_ips", []),
            "persistent_keepalive": meta.get("persistent_keepalive"),
            "has_preshared_key": bool(p.get("preshared_key")),
            "enabled": meta.get("enabled", True) if meta else True,
            "managed": bool(meta.get("private_key")) if meta else False,
            "created_at": meta.get("created_at"),
            "updated_at": meta.get("updated_at"),
            "status": status,
        })

    return jsonify({
        "interface": {
            "name": iface,
            "address": parsed["interface"]["address"],
            "listen_port": parsed["interface"]["listen_port"],
            "mtu": parsed["interface"]["mtu"],
            "dns": parsed["interface"]["dns"],
            "table": parsed["interface"]["table"],
            "post_up": parsed["interface"]["post_up"],
            "post_down": parsed["interface"]["post_down"],
            "has_private_key": bool(parsed["interface"]["private_key"]),
            "public_key": server_pub,
            "live": live["interface"],
        },
        "peers": merged_peers,
        "suggestions": _compute_suggestions(iface, parsed, peers_meta, live),
    })


def _compute_suggestions(iface: str, parsed: dict, peers_meta: dict, live: dict | None = None) -> dict:
    """Compute smart defaults for the 'add peer' form."""
    intf_addrs = parsed["interface"].get("address", [])
    free_addrs = _free_peer_addresses(iface, parsed, peers_meta, live, limit=1)
    next_addr = free_addrs[0] if free_addrs else ""
    # WG subnet + local LAN subnets (private only, exclude WAN)
    wg_subnet = _network_str(intf_addrs[0]) if intf_addrs else ""
    lan_subnets = _detect_lan_subnets(exclude=intf_addrs)
    aips = [s for s in [wg_subnet, *lan_subnets] if s]
    return {
        "next_peer_address": next_addr,
        "available_peer_count": _free_peer_address_count(iface, parsed, peers_meta, live),
        "next_account_name": _generate_account_names("User", 1, _existing_account_names(peers_meta))[0],
        "client_allowed_ips": aips,
        "client_mtu": parsed["interface"].get("mtu") or 1450,
        "endpoint": _detect_wan_endpoint(parsed["interface"].get("listen_port")),
        "endpoint_candidates": _detect_endpoint_candidates(parsed["interface"].get("listen_port")),
    }


def _network_str(addr_cidr: str) -> str:
    try:
        return str(ipaddress.IPv4Network(addr_cidr, strict=False))
    except ValueError:
        return ""


def _next_free_address(intf_addrs: list[str], used_addrs: list[Optional[str]]) -> str:
    """Pick the smallest unused IP in the WG subnet."""
    if not intf_addrs:
        return ""
    intf_first = next((a for a in intf_addrs if ":" not in a), None)
    if not intf_first:
        return ""
    try:
        network = ipaddress.IPv4Network(intf_first, strict=False)
        intf_ip = ipaddress.IPv4Address(intf_first.split("/")[0])
    except ValueError:
        return ""
    used: set[ipaddress.IPv4Address] = {intf_ip}
    for addr in used_addrs:
        if not addr:
            continue
        try:
            used.add(ipaddress.IPv4Address(str(addr).split("/")[0]))
        except ValueError:
            continue
    # network.hosts() skips the network and broadcast addresses but for /32
    # nothing is yielded; handle small subnets separately.
    if network.prefixlen >= 31:
        candidates = [network.network_address]
    else:
        candidates = network.hosts()
    for host in candidates:
        if host not in used:
            return f"{host}/32"
    return ""


def _free_peer_addresses(
    iface: str,
    parsed: dict,
    peers_meta: dict | None = None,
    live: dict | None = None,
    *,
    limit: int | None = None,
) -> list[str]:
    """Return free /32 client addresses inside the interface IPv4 subnet."""
    network = _first_interface_network(parsed)
    if not network:
        return []
    reserved_ips, reserved_nets = _reserved_peer_targets(iface, parsed, peers_meta or {}, live or {}, network)
    out: list[str] = []
    for host in _iter_host_candidates(network):
        if host in reserved_ips:
            continue
        if any(host in net for net in reserved_nets):
            continue
        out.append(f"{host}/32")
        if limit is not None and len(out) >= limit:
            break
    return out


def _free_peer_address_count(iface: str, parsed: dict, peers_meta: dict | None = None, live: dict | None = None) -> int:
    """Count allocatable peer addresses while excluding local and used IPs."""
    network = _first_interface_network(parsed)
    if not network:
        return 0
    reserved_ips, reserved_nets = _reserved_peer_targets(iface, parsed, peers_meta or {}, live or {}, network)
    count = 0
    for host in _iter_host_candidates(network):
        if host in reserved_ips:
            continue
        if any(host in net for net in reserved_nets):
            continue
        count += 1
    return count


def _peer_address_available(
    iface: str,
    parsed: dict,
    peers_meta: dict,
    live: dict,
    peer_address: str,
) -> bool:
    network = _first_interface_network(parsed)
    if not network:
        return False
    try:
        ip = ipaddress.IPv4Network(peer_address, strict=False).network_address
    except ValueError:
        return False
    if ip not in network:
        return False
    reserved_ips, reserved_nets = _reserved_peer_targets(iface, parsed, peers_meta, live, network)
    if ip in reserved_ips:
        return False
    return not any(ip in net for net in reserved_nets)


def _first_interface_network(parsed: dict) -> ipaddress.IPv4Network | None:
    for addr in parsed.get("interface", {}).get("address", []):
        if ":" in str(addr):
            continue
        try:
            return ipaddress.IPv4Interface(str(addr)).network
        except ValueError:
            continue
    return None


def _iter_host_candidates(network: ipaddress.IPv4Network):
    if network.prefixlen >= 31:
        yield from network
    else:
        yield from network.hosts()


def _reserved_peer_targets(
    iface: str,
    parsed: dict,
    peers_meta: dict,
    live: dict,
    network: ipaddress.IPv4Network,
) -> tuple[set[ipaddress.IPv4Address], list[ipaddress.IPv4Network]]:
    reserved_ips = _local_ipv4_addresses()
    reserved_nets: list[ipaddress.IPv4Network] = []

    for addr in parsed.get("interface", {}).get("address", []):
        try:
            reserved_ips.add(ipaddress.IPv4Interface(str(addr)).ip)
        except ValueError:
            continue
    for peer in parsed.get("peers", []):
        for allowed in peer.get("allowed_ips") or []:
            _reserve_allowed_ip(allowed, network, reserved_ips, reserved_nets)
    for meta in peers_meta.values():
        if meta.get("interface") and meta.get("interface") != iface:
            continue
        _reserve_allowed_ip(meta.get("peer_address"), network, reserved_ips, reserved_nets)
        for allowed in meta.get("extra_allowed_ips") or []:
            _reserve_allowed_ip(allowed, network, reserved_ips, reserved_nets)
    for status in (live.get("peers_status") or {}).values():
        for allowed in status.get("allowed_ips") or []:
            _reserve_allowed_ip(allowed, network, reserved_ips, reserved_nets)

    return reserved_ips, reserved_nets


def _reserve_allowed_ip(
    value: object,
    target_network: ipaddress.IPv4Network,
    reserved_ips: set[ipaddress.IPv4Address],
    reserved_nets: list[ipaddress.IPv4Network],
) -> None:
    if not value:
        return
    try:
        net = ipaddress.IPv4Network(str(value), strict=False)
    except ValueError:
        return
    if not net.overlaps(target_network):
        return
    if net.prefixlen == 32:
        reserved_ips.add(net.network_address)
    elif net not in reserved_nets:
        reserved_nets.append(net)


def _local_ipv4_addresses() -> set[ipaddress.IPv4Address]:
    """Collect all IPv4 addresses owned by this UTM, not only wg addresses."""
    res = run(["ip", "-j", "addr", "show"], timeout=10)
    if not res.ok:
        return set()
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return set()
    out: set[ipaddress.IPv4Address] = set()
    for entry in data:
        for addr in entry.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            try:
                out.add(ipaddress.IPv4Address(addr.get("local", "")))
            except ValueError:
                continue
    return out


def _existing_account_names(peers_meta: dict) -> set[str]:
    names: set[str] = set()
    for meta in peers_meta.values():
        for key in ("account_name", "comment"):
            name = str(meta.get(key) or "").strip()
            if name:
                names.add(name)
    return names


def _generate_account_names(
    prefix: str,
    count: int,
    existing: set[str],
    *,
    start: int | None = None,
    width: int = 3,
) -> list[str]:
    prefix = _safe_account_prefix(prefix)
    width = min(max(int(width or 3), 1), 6)
    if start is None:
        pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
        highest = 0
        for name in existing:
            m = pattern.match(name)
            if m:
                highest = max(highest, int(m.group(1)))
        start = highest + 1
    n = max(int(start or 1), 1)
    names: list[str] = []
    used = set(existing)
    while len(names) < count:
        candidate = f"{prefix}{n:0{width}d}"
        n += 1
        if candidate in used:
            continue
        used.add(candidate)
        names.append(candidate)
    return names


def _safe_account_prefix(value: object) -> str:
    prefix = re.sub(r"[^A-Za-z0-9_-]", "", str(value or "User").strip()) or "User"
    if not re.match(r"^[A-Za-z]", prefix):
        prefix = f"User{prefix}"
    return prefix[:24]


def _detect_lan_subnets(exclude: list[str] | None = None) -> list[str]:
    """Return private CIDRs of non-WAN, non-WG interfaces (best-effort)."""
    import json as _json
    exclude_nets = set()
    for c in exclude or []:
        try:
            exclude_nets.add(str(ipaddress.IPv4Network(c, strict=False)))
        except ValueError:
            pass
    res = run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return []
    try:
        data = _json.loads(res.stdout)
    except _json.JSONDecodeError:
        return []

    # Find the interface holding the default gateway (treat as WAN)
    route_res = run(["ip", "-j", "route", "show", "default"])
    wan_ifname = ""
    if route_res.ok:
        try:
            routes = _json.loads(route_res.stdout)
            if routes and isinstance(routes, list):
                wan_ifname = routes[0].get("dev", "")
        except _json.JSONDecodeError:
            pass

    subnets: list[str] = []
    for entry in data:
        ifname = entry.get("ifname", "")
        if ifname in ("lo", wan_ifname) or ifname.startswith("wg"):
            continue
        for a in entry.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            if a.get("scope") == "host":
                continue
            try:
                net = ipaddress.IPv4Network(f"{a['local']}/{a['prefixlen']}", strict=False)
            except (KeyError, ValueError):
                continue
            if not net.is_private:
                continue
            s = str(net)
            if s in exclude_nets or s in subnets:
                continue
            subnets.append(s)
    return subnets


@bp.route("/api/interfaces/<iface>/peers", methods=["POST"])
@login_required
@csrf_protect
def add_peer(iface: str):
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    payload = request.get_json(force=True, silent=True) or {}
    try:
        meta = _parse_peer_payload(payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    try:
        peer_priv, peer_pub = _gen_keys()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    psk = _gen_preshared() if payload.get("preshared_key", True) else None

    meta.update({
        "interface": iface,
        "private_key": peer_priv,
        "preshared_key": psk,
        "enabled": bool(payload.get("enabled", True)),
        "created_at": _now(),
        "updated_at": _now(),
    })

    parsed = _parse_wg_conf(path)
    data = _load_data()
    live = _wg_show_dump(iface)
    if not _peer_address_available(iface, parsed, data["peers"], live, meta["peer_address"]):
        return jsonify({"error": "Peer Address はWGサブネット外、または既に利用/予約されています"}), 400
    if any(p.get("public_key") == peer_pub for p in parsed["peers"]):
        return jsonify({"error": "pubkey collision (rare)"}), 500
    parsed["peers"].append(_meta_to_conf_peer(peer_pub, meta))
    try:
        _write_conf(iface, parsed)
        _ensure_interface_running(iface)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    _save_meta(peer_pub, meta)
    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))
    client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
    return jsonify({
        "peer": _peer_summary(peer_pub, meta),
        "client_config": client_conf,
        "qr_svg": _generate_qr_svg(client_conf),
    }), 201


@bp.route("/api/interfaces/<iface>/peers/bulk", methods=["POST"])
@login_required
@csrf_protect
def bulk_add_peers(iface: str):
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    payload = request.get_json(force=True, silent=True) or {}
    try:
        count = int(payload.get("count", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "count must be a number"}), 400
    if not (1 <= count <= 512):
        return jsonify({"error": "count must be 1..512"}), 400

    parsed = _parse_wg_conf(path)
    data = _load_data()
    live = _wg_show_dump(iface)
    free_addrs = _free_peer_addresses(iface, parsed, data["peers"], live, limit=count)
    available_count = _free_peer_address_count(iface, parsed, data["peers"], live)
    if len(free_addrs) < count:
        return jsonify({
            "error": f"作成数が空きIP数を超えています (空き {available_count} / 要求 {count})",
            "available_peer_count": available_count,
        }), 400

    try:
        width = int(payload.get("number_width", 3) or 3)
    except (TypeError, ValueError):
        width = 3
    start_number = payload.get("start_number")
    try:
        start_number = int(start_number) if start_number not in ("", None) else None
    except (TypeError, ValueError):
        return jsonify({"error": "start_number must be a number"}), 400

    prefix = _safe_account_prefix(payload.get("name_prefix") or "User")
    account_names = _generate_account_names(
        prefix,
        count,
        _existing_account_names(data["peers"]),
        start=start_number,
        width=width,
    )
    display_names = _parse_display_names(payload.get("display_names") or payload.get("aliases") or "")
    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))

    created: list[tuple[str, dict, str, str]] = []
    new_meta: list[tuple[str, dict]] = []
    for idx, address in enumerate(free_addrs):
        item_payload = dict(payload)
        account_name = account_names[idx]
        item_payload["peer_address"] = address
        item_payload["comment"] = account_name
        item_payload["account_name"] = account_name
        item_payload["display_name"] = display_names[idx] if idx < len(display_names) else ""
        try:
            meta = _parse_peer_payload(item_payload)
            peer_priv, peer_pub = _gen_unique_peer_keys(parsed)
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 500

        psk = _gen_preshared() if payload.get("preshared_key", True) else None
        now = _now()
        meta.update({
            "interface": iface,
            "private_key": peer_priv,
            "preshared_key": psk,
            "enabled": bool(payload.get("enabled", True)),
            "created_at": now,
            "updated_at": now,
        })
        parsed["peers"].append(_meta_to_conf_peer(peer_pub, meta))
        client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
        filename = _client_filename(meta)
        created.append((peer_pub, meta, client_conf, filename))
        new_meta.append((peer_pub, meta))

    try:
        _write_conf(iface, parsed)
        _ensure_interface_running(iface)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    _save_many_meta(new_meta)
    bundle = _build_bulk_peer_zip(iface, created)
    return jsonify({
        "ok": True,
        "created": [_peer_summary(pubkey, meta) for pubkey, meta, _conf, _filename in created],
        "bundle_filename": f"{iface}-wireguard-accounts.zip",
        "bundle_base64": base64.b64encode(bundle).decode("ascii"),
        "available_peer_count": max(available_count - count, 0),
    }), 201


@bp.route("/api/interfaces/<iface>/peers/bulk-delete", methods=["POST"])
@login_required
@csrf_protect
def bulk_delete_peers(iface: str):
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    payload = request.get_json(force=True, silent=True) or {}
    if not verify_admin_password(str(payload.get("password") or "")):
        return jsonify({"error": "管理者パスワードが正しくありません"}), 401

    requested = _normalize_pubkey_list(payload.get("public_keys"))
    if not requested:
        return jsonify({"error": "削除対象のピアを選択してください"}), 400
    if len(requested) > 512:
        return jsonify({"error": "一括削除は512件以内で指定してください"}), 400

    parsed = _parse_wg_conf(path)
    data = _load_data()
    conf_keys = {p.get("public_key") for p in parsed["peers"] if p.get("public_key")}
    meta_keys = {
        pubkey
        for pubkey, meta in data["peers"].items()
        if isinstance(meta, dict) and meta.get("interface") == iface
    }
    eligible = conf_keys | meta_keys
    targets = [pubkey for pubkey in requested if pubkey in eligible]
    if not targets:
        return jsonify({"error": "削除できるピアが見つかりません"}), 404

    target_set = set(targets)
    before = len(parsed["peers"])
    parsed["peers"] = [p for p in parsed["peers"] if p.get("public_key") not in target_set]
    conf_deleted = before - len(parsed["peers"])
    metadata_deleted = sum(1 for pubkey in targets if pubkey in data["peers"])

    try:
        if conf_deleted:
            _write_conf(iface, parsed)
            _sync_interface(iface)
            _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    _delete_many_meta(targets)
    return jsonify({
        "ok": True,
        "deleted": len(targets),
        "conf_deleted": conf_deleted,
        "metadata_deleted": metadata_deleted,
        "not_found": len(requested) - len(targets),
    })


@bp.route("/api/interfaces/<iface>/peers/key/<pubkey_token>", methods=["PUT"])
@bp.route("/api/interfaces/<iface>/peers/<path:pubkey>", methods=["PUT"])
@login_required
@csrf_protect
def update_peer(iface: str, pubkey: str | None = None, pubkey_token: str | None = None):
    pubkey = _pubkey_from_route(pubkey, pubkey_token)
    if not pubkey:
        return jsonify({"error": "invalid public key token"}), 400
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    payload = request.get_json(force=True, silent=True) or {}
    try:
        new_fields = _parse_peer_payload(payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    existing_meta = _load_meta(pubkey) or {}
    # PSK is preserved across edits unless explicitly toggled
    if "preshared_key_regen" in payload and payload["preshared_key_regen"]:
        psk = _gen_preshared()
    elif payload.get("preshared_key_drop"):
        psk = None
    else:
        psk = existing_meta.get("preshared_key")
    # Private key is preserved if the peer was managed before; if not (adopted),
    # we can't proceed without one — surface a clearer error.
    privkey = existing_meta.get("private_key")
    if not privkey:
        return jsonify({
            "error": "peer is not under GUI management (no stored private key). "
                     "Use 'regenerate keys' to create new ones, then update."
        }), 409

    meta = {
        **existing_meta,
        **new_fields,
        "interface": iface,
        "private_key": privkey,
        "preshared_key": psk,
        "enabled": bool(payload.get("enabled", existing_meta.get("enabled", True))),
        "updated_at": _now(),
    }
    parsed = _parse_wg_conf(path)
    updated = False
    for i, p in enumerate(parsed["peers"]):
        if p.get("public_key") == pubkey:
            if meta["enabled"]:
                parsed["peers"][i] = _meta_to_conf_peer(pubkey, meta)
            else:
                # Disabled → remove from conf so wg won't accept this peer
                parsed["peers"].pop(i)
            updated = True
            break
    if not updated and meta["enabled"]:
        # Was removed from conf but still in metadata — re-add
        parsed["peers"].append(_meta_to_conf_peer(pubkey, meta))
    try:
        _write_conf(iface, parsed)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    _save_meta(pubkey, meta)
    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))
    client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
    return jsonify({
        "peer": _peer_summary(pubkey, meta),
        "client_config": client_conf,
        "qr_svg": _generate_qr_svg(client_conf),
    })


@bp.route("/api/interfaces/<iface>/peers/key/<pubkey_token>", methods=["DELETE"])
@bp.route("/api/interfaces/<iface>/peers/<path:pubkey>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_peer(iface: str, pubkey: str | None = None, pubkey_token: str | None = None):
    pubkey = _pubkey_from_route(pubkey, pubkey_token)
    if not pubkey:
        return jsonify({"error": "invalid public key token"}), 400
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404
    parsed = _parse_wg_conf(path)
    before = len(parsed["peers"])
    parsed["peers"] = [p for p in parsed["peers"] if p.get("public_key") != pubkey]
    if len(parsed["peers"]) == before:
        # Maybe the peer was disabled (in store only). Still remove from store.
        _delete_meta(pubkey)
        return jsonify({"ok": True, "note": "peer not in conf; metadata cleared"})
    try:
        _write_conf(iface, parsed)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    _delete_meta(pubkey)
    return jsonify({"ok": True})


@bp.route("/api/interfaces/<iface>/peers/key/<pubkey_token>/display-name", methods=["PUT", "DELETE"])
@bp.route("/api/interfaces/<iface>/peers/<path:pubkey>/display-name", methods=["PUT", "DELETE"])
@login_required
@csrf_protect
def update_peer_display_name(iface: str, pubkey: str | None = None, pubkey_token: str | None = None):
    pubkey = _pubkey_from_route(pubkey, pubkey_token)
    if not pubkey:
        return jsonify({"error": "invalid public key token"}), 400
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    parsed = _parse_wg_conf(path)
    conf_peer = next((p for p in parsed["peers"] if p.get("public_key") == pubkey), None)
    existing_meta = _load_meta(pubkey) or {}
    if not conf_peer and not existing_meta:
        return jsonify({"error": "peer not found"}), 404

    display_name = ""
    if request.method != "DELETE":
        payload = request.get_json(force=True, silent=True) or {}
        display_name = str(payload.get("display_name") or "").strip()[:128]

    meta = dict(existing_meta)
    if display_name:
        meta["display_name"] = display_name
        meta.setdefault("interface", iface)
        meta.setdefault("created_at", _now())
        meta["updated_at"] = _now()
        _save_meta(pubkey, meta)
    else:
        meta.pop("display_name", None)
        if meta and (meta.get("private_key") or meta.get("peer_address")):
            meta["updated_at"] = _now()
            _save_meta(pubkey, meta)
        else:
            _delete_meta(pubkey)
            meta = {}

    return jsonify({
        "ok": True,
        "public_key": pubkey,
        "display_name": meta.get("display_name", ""),
        "managed": bool(meta.get("private_key")) if meta else False,
    })


@bp.route("/api/interfaces/<iface>/peers/key/<pubkey_token>/client-config", methods=["GET"])
@bp.route("/api/interfaces/<iface>/peers/<path:pubkey>/client-config", methods=["GET"])
@login_required
def get_client_config(iface: str, pubkey: str | None = None, pubkey_token: str | None = None):
    """Re-generate the client .conf + QR at any time. Requires stored metadata."""
    pubkey = _pubkey_from_route(pubkey, pubkey_token)
    if not pubkey:
        return jsonify({"error": "invalid public key token"}), 400
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    meta = _load_meta(pubkey)
    if not meta or not meta.get("private_key"):
        return jsonify({
            "error": "private key not stored for this peer. It was either added outside the GUI, "
                     "or was migrated before metadata was saved. Use 'regenerate keys' to bring it under management."
        }), 404
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404
    parsed = _parse_wg_conf(path)
    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))
    client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
    return jsonify({
        "client_config": client_conf,
        "qr_svg": _generate_qr_svg(client_conf),
        "filename": _client_filename(meta),
    })


@bp.route("/api/interfaces/<iface>/peers/client-configs", methods=["GET"])
@login_required
def get_all_client_configs(iface: str):
    """Bundle all GUI-managed client configs for the interface into one ZIP."""
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    parsed = _parse_wg_conf(path)
    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))
    data = _load_data()
    items: list[tuple[str, dict, str, str]] = []
    for pubkey, meta in sorted(data["peers"].items(), key=lambda item: _client_filename(item[1])):
        if meta.get("interface") != iface or not meta.get("private_key"):
            continue
        client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
        items.append((pubkey, meta, client_conf, _client_filename(meta)))

    if not items:
        return jsonify({"error": "downloadable managed peers not found"}), 404

    bundle = _build_bulk_peer_zip(iface, items)
    return jsonify({
        "ok": True,
        "count": len(items),
        "peers": [_peer_summary(pubkey, meta) for pubkey, meta, _conf, _filename in items],
        "bundle_filename": f"{iface}-wireguard-all-accounts.zip",
        "bundle_base64": base64.b64encode(bundle).decode("ascii"),
    })


@bp.route("/api/interfaces/<iface>/peers/key/<pubkey_token>/adopt-key", methods=["POST"])
@bp.route("/api/interfaces/<iface>/peers/<path:pubkey>/adopt-key", methods=["POST"])
@login_required
@csrf_protect
def adopt_with_existing_key(iface: str, pubkey: str | None = None, pubkey_token: str | None = None):
    """Bring a limited peer under GUI management by uploading its existing
    private key. The submitted private key MUST derive to the peer's public
    key, otherwise the request is rejected.

    Use this when:
      - The peer was originally created by another tool (wireguard-ui etc.)
      - You still have the original client's private key
      - You don't want to regenerate keys (which would force client re-install)
    """
    pubkey = _pubkey_from_route(pubkey, pubkey_token)
    if not pubkey:
        return jsonify({"error": "invalid public key token"}), 400
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404
    payload = request.get_json(force=True, silent=True) or {}
    privkey = (payload.get("private_key") or "").strip()
    if not privkey:
        return jsonify({"error": "private_key required"}), 400

    derived = _pubkey_from_priv(privkey)
    if not derived:
        return jsonify({"error": "invalid private key (wg pubkey rejected it)"}), 400
    if derived != pubkey:
        return jsonify({
            "error": "private key does not derive to this peer's public key",
            "derived_pubkey": derived,
        }), 400

    parsed = _parse_wg_conf(path)
    conf_peer = next((p for p in parsed["peers"] if p.get("public_key") == pubkey), None)
    if not conf_peer:
        return jsonify({"error": "peer not found in conf"}), 404

    existing_meta = _load_meta(pubkey) or {}
    aips = conf_peer.get("allowed_ips") or []
    peer_address = existing_meta.get("peer_address") or (aips[0] if aips else "")
    extra = existing_meta.get("extra_allowed_ips") or (aips[1:] if len(aips) > 1 else [])

    meta = {
        "interface": iface,
        "comment": existing_meta.get("comment") or conf_peer.get("comment", ""),
        "private_key": privkey,
        "preshared_key": existing_meta.get("preshared_key") or conf_peer.get("preshared_key"),
        "peer_address": peer_address,
        "extra_allowed_ips": extra,
        "client_dns": existing_meta.get("client_dns", []),
        "client_mtu": existing_meta.get("client_mtu", 1450),
        "client_allowed_ips": existing_meta.get("client_allowed_ips", ["0.0.0.0/0", "::/0"]),
        "endpoint": existing_meta.get("endpoint") or _detect_wan_endpoint(parsed["interface"].get("listen_port")),
        "persistent_keepalive": existing_meta.get("persistent_keepalive", 25),
        "enabled": True,
        "created_at": existing_meta.get("created_at") or _now(),
        "updated_at": _now(),
    }
    _save_meta(pubkey, meta)

    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))
    client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
    return jsonify({
        "peer": _peer_summary(pubkey, meta),
        "client_config": client_conf,
        "qr_svg": _generate_qr_svg(client_conf),
    })


@bp.route("/api/interfaces/<iface>/peers/key/<pubkey_token>/regenerate-keys", methods=["POST"])
@bp.route("/api/interfaces/<iface>/peers/<path:pubkey>/regenerate-keys", methods=["POST"])
@login_required
@csrf_protect
def regenerate_peer_keys(iface: str, pubkey: str | None = None, pubkey_token: str | None = None):
    """Generate a fresh keypair (and optionally PSK) for an existing peer.

    The peer's public key changes (it's derived from the new private key), so the
    old peer entry is removed from the conf and replaced with the new one. The
    metadata moves to the new pubkey too. Returns the fresh client config.
    """
    pubkey = _pubkey_from_route(pubkey, pubkey_token)
    if not pubkey:
        return jsonify({"error": "invalid public key token"}), 400
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404

    payload = request.get_json(force=True, silent=True) or {}
    regen_psk = bool(payload.get("regenerate_psk", True))

    existing_meta = _load_meta(pubkey)
    # If no metadata exists, build a minimal one from the conf so the peer
    # can be brought under management.
    parsed = _parse_wg_conf(path)
    conf_peer = next((p for p in parsed["peers"] if p.get("public_key") == pubkey), None)
    if not conf_peer and not existing_meta:
        return jsonify({"error": "peer not found in conf"}), 404

    try:
        new_priv, new_pub = _gen_keys()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    new_psk = (_gen_preshared() if regen_psk
               else (existing_meta or {}).get("preshared_key")
               or conf_peer.get("preshared_key") if conf_peer else None)

    if existing_meta:
        meta = {
            **existing_meta,
            "private_key": new_priv,
            "preshared_key": new_psk,
            "updated_at": _now(),
        }
    else:
        # Bring an adopted peer under full management
        conf_aips = conf_peer.get("allowed_ips") or []
        peer_address = conf_aips[0] if conf_aips else "10.252.1.2/32"
        extra = conf_aips[1:] if len(conf_aips) > 1 else []
        meta = {
            "interface": iface,
            "comment": conf_peer.get("comment", ""),
            "private_key": new_priv,
            "preshared_key": new_psk,
            "peer_address": peer_address,
            "extra_allowed_ips": extra,
            "client_dns": [],
            "client_mtu": None,
            "client_allowed_ips": ["0.0.0.0/0", "::/0"],
            "endpoint": _detect_wan_endpoint(parsed["interface"].get("listen_port")),
            "persistent_keepalive": 25,
            "enabled": True,
            "created_at": _now(),
            "updated_at": _now(),
        }

    # Replace in conf: drop old pubkey, add new
    parsed["peers"] = [p for p in parsed["peers"] if p.get("public_key") != pubkey]
    parsed["peers"].append(_meta_to_conf_peer(new_pub, meta))
    try:
        _write_conf(iface, parsed)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    _rename_pubkey_meta(pubkey, new_pub, meta)
    server_pub = _pubkey_from_priv(parsed["interface"].get("private_key"))
    client_conf = _build_client_config(meta, server_pub, parsed["interface"].get("listen_port"))
    return jsonify({
        "new_public_key": new_pub,
        "peer": _peer_summary(new_pub, meta),
        "client_config": client_conf,
        "qr_svg": _generate_qr_svg(client_conf),
    })


@bp.route("/api/interfaces", methods=["POST"])
@login_required
@csrf_protect
def create_interface():
    """Create a new WireGuard interface (wgX.conf).

    Server keypair is generated server-side; the conf file is written to
    /etc/wireguard/<name>.conf with 0600 perms. If `start: true` we also
    call `wg-quick up` afterwards. firewalld is synchronized so the
    listen port and LAN forwarding work without manual firewall edits.
    """
    payload = request.get_json(force=True, silent=True) or {}
    try:
        fields = _parse_interface_payload(payload, is_create=True)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    name = fields.pop("name")
    if not WG_DIR.exists():
        try:
            WG_DIR.mkdir(parents=True, exist_ok=True)
            WG_DIR.chmod(0o700)
        except OSError as e:
            return jsonify({"error": f"failed to create {WG_DIR}: {e}"}), 500
    path = WG_DIR / f"{name}.conf"
    if path.exists():
        return jsonify({"error": f"interface {name!r} already exists"}), 409

    # ListenPort collision check across other GUI/manually-defined ifaces.
    # Allow override via force_port=true so the operator can still create
    # an iface that shares a port with one currently down.
    if fields["listen_port"]:
        for other in WG_DIR.glob("*.conf"):
            if other == path:
                continue
            other_parsed = _parse_wg_conf(other)
            if other_parsed["interface"].get("listen_port") == fields["listen_port"]:
                if not payload.get("force_port"):
                    return jsonify({
                        "error": f"listen_port {fields['listen_port']} はすでに "
                                 f"{other.stem} が使用しています",
                        "collision_with": other.stem,
                    }), 409

    try:
        priv, pub = _gen_keys()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    parsed = {
        "interface": {
            "address": fields["address"],
            "listen_port": fields["listen_port"],
            "private_key": priv,
            "mtu": fields["mtu"],
            "dns": fields["dns"],
            "table": fields["table"],
            "post_up": fields["post_up"],
            "post_down": fields["post_down"],
        },
        "peers": [],
    }
    try:
        _write_conf(name, parsed)
    except OSError as e:
        return jsonify({"error": f"failed to write {path}: {e}"}), 500

    start_result = None
    if payload.get("start"):
        res = sudo_run(["systemctl", "enable", "--now", f"wg-quick@{name}"])
        start_result = {"ok": res.ok, "output": (res.stdout + res.stderr).strip()}
        if res.ok:
            try:
                _sync_firewalld_for_interface(name, parsed)
            except RuntimeError as e:
                start_result = {
                    "ok": False,
                    "output": f"firewalld auto configuration failed: {e}",
                }

    return jsonify({
        "interface": {
            "name": name,
            "public_key": pub,
            "listen_port": fields["listen_port"],
        },
        "start_result": start_result,
    }), 201


@bp.route("/api/interfaces/<iface>", methods=["PUT"])
@login_required
@csrf_protect
def update_interface(iface: str):
    """Apply edited interface settings to <iface>.conf.

    Settings that `wg syncconf` can update live (ListenPort, PrivateKey,
    Peer list) are pushed to the kernel immediately when the interface
    is up. Address/MTU/DNS/Table/PostUp/PostDown are wg-quick-level and
    only take effect on the next wg-quick down/up cycle — we surface a
    `requires_restart: true` flag so the UI can prompt the operator.
    """
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404
    payload = request.get_json(force=True, silent=True) or {}
    try:
        fields = _parse_interface_payload(payload, is_create=False)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    parsed = _parse_wg_conf(path)
    old = parsed["interface"]
    requires_restart = (
        sorted(old.get("address") or []) != sorted(fields["address"])
        or (old.get("mtu") or None) != fields["mtu"]
        or sorted(old.get("dns") or []) != sorted(fields["dns"])
        or (old.get("table") or None) != fields["table"]
        or list(old.get("post_up") or []) != list(fields["post_up"])
        or list(old.get("post_down") or []) != list(fields["post_down"])
    )
    parsed["interface"].update(fields)
    try:
        _write_conf(iface, parsed)
        if not requires_restart:
            _ensure_interface_running(iface)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True, "requires_restart": requires_restart})


@bp.route("/api/interfaces/<iface>/regenerate-server-keys", methods=["POST"])
@login_required
@csrf_protect
def regenerate_server_keys(iface: str):
    """Rotate the server (interface) keypair.

    The new private key is written to the conf, syncconf pushes it to
    the live kernel state, and the response contains the new public key
    plus the list of peers that need to re-download their client config
    (every peer references the server pubkey in its [Peer] block).
    """
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    path = WG_DIR / f"{iface}.conf"
    if not path.exists():
        return jsonify({"error": "interface not found"}), 404
    parsed = _parse_wg_conf(path)
    try:
        priv, pub = _gen_keys()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    parsed["interface"]["private_key"] = priv
    try:
        _write_conf(iface, parsed)
        _sync_interface(iface)
        _sync_firewalld_for_interface(iface, parsed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    affected = [p.get("public_key") for p in parsed["peers"] if p.get("public_key")]
    return jsonify({
        "ok": True,
        "public_key": pub,
        "affected_peers": affected,
        "note": "各ピアのクライアント設定を再ダウンロードしてください (サーバ公開鍵が変更されました)",
    })


@bp.route("/api/interfaces/<iface>/up", methods=["POST"])
@login_required
@csrf_protect
def up_interface(iface: str):
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    res = sudo_run(["systemctl", "enable", "--now", f"wg-quick@{iface}"])
    output = (res.stdout + res.stderr).strip()
    if res.ok:
        try:
            parsed = _parse_wg_conf(WG_DIR / f"{iface}.conf")
            _sync_firewalld_for_interface(iface, parsed)
        except RuntimeError as e:
            return jsonify({"ok": False, "output": f"{output}\nfirewalld auto configuration failed: {e}".strip()})
    return jsonify({"ok": res.ok, "output": output})


@bp.route("/api/interfaces/<iface>/down", methods=["POST"])
@login_required
@csrf_protect
def down_interface(iface: str):
    if not INTERFACE_RE.match(iface):
        return jsonify({"error": "invalid interface name"}), 400
    res = sudo_run(["systemctl", "disable", "--now", f"wg-quick@{iface}"])
    return jsonify({"ok": res.ok, "output": (res.stdout + res.stderr).strip()})


# ---- payload parsing ---------------------------------------------------

def _parse_interface_payload(raw: dict, is_create: bool = False) -> dict:
    """Validate edit / create payload for the [Interface] section.

    Schema:
      {
        "name":         str (create only),
        "address":      [CIDR],
        "listen_port":  int (1..65535) | null,
        "mtu":          int (576..9200) | null,
        "dns":          [IPv4],
        "table":        "auto" | "off" | "<num>" | null,
        "post_up":      [str],   # shell command lines, max 8 each up to 512 chars
        "post_down":    [str],
      }
    """
    out: dict = {}
    if is_create:
        name = (raw.get("name") or "").strip()
        if not INTERFACE_RE.match(name):
            raise ValidationError("interface 名が無効です (英字始まり、英数+_-で15文字以内)")
        out["name"] = name

    # Address
    addrs_raw = raw.get("address") or []
    if isinstance(addrs_raw, str):
        addrs_raw = [s.strip() for s in addrs_raw.split(",") if s.strip()]
    if not isinstance(addrs_raw, list):
        raise ValidationError("address はリストまたはカンマ区切り文字列です")
    out["address"] = [_validate_interface_address(validate_ipv4_cidr(a)) for a in addrs_raw]
    if is_create and not out["address"]:
        raise ValidationError("address は必須です (例: 10.252.1.1/24)")

    # ListenPort
    lp_raw = raw.get("listen_port")
    if lp_raw in (None, ""):
        if is_create:
            raise ValidationError("listen_port は必須です")
        out["listen_port"] = None
    else:
        try:
            lp = int(lp_raw)
        except (TypeError, ValueError):
            raise ValidationError("listen_port が無効です")
        if not (1 <= lp <= 65535):
            raise ValidationError("listen_port は 1-65535 の範囲です")
        out["listen_port"] = lp

    # MTU
    mtu_raw = raw.get("mtu")
    if mtu_raw in (None, "", "null"):
        out["mtu"] = None
    else:
        try:
            mtu = int(mtu_raw)
        except (TypeError, ValueError):
            raise ValidationError("MTU が無効です")
        if not (576 <= mtu <= 9200):
            raise ValidationError("MTU は 576-9200 の範囲です")
        out["mtu"] = mtu

    # DNS — list of IPv4 (WG accepts IPv6 too but we keep it simple)
    dns_raw = raw.get("dns") or []
    if isinstance(dns_raw, str):
        dns_raw = [s.strip() for s in dns_raw.split(",") if s.strip()]
    if not isinstance(dns_raw, list):
        raise ValidationError("dns はリストまたはカンマ区切り文字列です")
    out["dns"] = [validate_ipv4(d) for d in dns_raw]

    # Table
    table_raw = (raw.get("table") or "").strip()
    if table_raw and not _TABLE_RE.match(table_raw):
        raise ValidationError("table は 'auto' / 'off' / 数値のいずれかです")
    out["table"] = table_raw or None

    # PostUp / PostDown
    for key in ("post_up", "post_down"):
        cmds_raw = raw.get(key) or []
        if isinstance(cmds_raw, str):
            cmds_raw = cmds_raw.splitlines()
        if not isinstance(cmds_raw, list):
            raise ValidationError(f"{key} はリストか改行区切り文字列です")
        cmds: list[str] = []
        for c in cmds_raw:
            c = str(c).rstrip()
            if not c.strip():
                continue
            if len(c) > _POST_CMD_MAX_LEN:
                raise ValidationError(f"{key}: コマンドが長すぎます (>{_POST_CMD_MAX_LEN}文字)")
            if "\x00" in c or "\n" in c or "\r" in c:
                raise ValidationError(f"{key}: コマンドに制御文字が含まれます")
            cmds.append(c)
        if len(cmds) > _MAX_POST_CMDS:
            raise ValidationError(f"{key}: コマンドが多すぎます (最大{_MAX_POST_CMDS}行)")
        out[key] = cmds

    return out


def _validate_interface_address(addr_cidr: str) -> str:
    """Reject network/broadcast IPv4 addresses for WireGuard interfaces."""
    try:
        iface = ipaddress.IPv4Interface(addr_cidr)
        network = iface.network
    except ValueError:
        return addr_cidr
    if network.prefixlen < 31:
        if iface.ip == network.network_address:
            raise ValidationError("address にネットワークアドレスは指定できません (例: 10.252.1.1/24)")
        if iface.ip == network.broadcast_address:
            raise ValidationError("address にブロードキャストアドレスは指定できません")
    return addr_cidr


def _parse_peer_payload(payload: dict) -> dict:
    """Validate add/edit payload and return a metadata dict with parsed fields."""
    account_name = (payload.get("account_name") or payload.get("comment") or "").strip()[:64]
    display_name = (payload.get("display_name") or "").strip()[:128]
    comment = (payload.get("comment") or account_name or display_name).strip()[:128]
    peer_address = (payload.get("peer_address") or "").strip()
    if not peer_address:
        raise ValidationError("peer_address required (例: 10.252.1.42/32)")
    peer_address = validate_ipv4_cidr(peer_address)

    extra_raw = payload.get("extra_allowed_ips") or ""
    if isinstance(extra_raw, list):
        extra_list = extra_raw
    else:
        extra_list = [s.strip() for s in str(extra_raw).split(",") if s.strip()]
    extra_allowed = [validate_ipv4_cidr(c) for c in extra_list]

    dns_raw = payload.get("client_dns") or ""
    if isinstance(dns_raw, list):
        dns_list = dns_raw
    else:
        dns_list = [s.strip() for s in str(dns_raw).split(",") if s.strip()]
    client_dns = [validate_ipv4(d) for d in dns_list]

    mtu_raw = payload.get("client_mtu")
    if mtu_raw in ("", None):
        client_mtu = None
    else:
        try:
            client_mtu = int(mtu_raw)
        except (TypeError, ValueError):
            raise ValidationError("invalid MTU")
        if not (576 <= client_mtu <= 9200):
            raise ValidationError("MTU out of range (576-9200)")

    caips_raw = payload.get("client_allowed_ips") or "0.0.0.0/0, ::/0"
    if isinstance(caips_raw, list):
        client_allowed_ips = [c.strip() for c in caips_raw if c.strip()]
    else:
        client_allowed_ips = [c.strip() for c in str(caips_raw).split(",") if c.strip()]
    if not client_allowed_ips:
        client_allowed_ips = ["0.0.0.0/0", "::/0"]

    endpoint = (payload.get("endpoint") or "").strip()
    if endpoint and not re.match(r"^[A-Za-z0-9._\-]+:\d{1,5}$", endpoint):
        raise ValidationError("endpoint must look like host:port")

    keepalive_raw = payload.get("persistent_keepalive")
    if keepalive_raw in ("", None):
        keepalive = 25
    else:
        try:
            keepalive = int(keepalive_raw)
        except (TypeError, ValueError):
            raise ValidationError("invalid persistent_keepalive")
        if not (0 <= keepalive <= 65535):
            raise ValidationError("keepalive out of range")

    return {
        "comment": comment,
        "account_name": account_name or comment,
        "display_name": display_name,
        "peer_address": peer_address,
        "extra_allowed_ips": extra_allowed,
        "client_dns": client_dns,
        "client_mtu": client_mtu,
        "client_allowed_ips": client_allowed_ips,
        "endpoint": endpoint,
        "persistent_keepalive": keepalive,
    }


def _peer_summary(pubkey: str, meta: dict) -> dict:
    """Public-safe summary (no private key)."""
    return {
        "public_key": pubkey,
        "comment": meta.get("comment"),
        "account_name": meta.get("account_name") or meta.get("comment"),
        "display_name": meta.get("display_name", ""),
        "peer_address": meta.get("peer_address"),
        "extra_allowed_ips": meta.get("extra_allowed_ips", []),
        "client_dns": meta.get("client_dns", []),
        "client_mtu": meta.get("client_mtu"),
        "client_allowed_ips": meta.get("client_allowed_ips", []),
        "endpoint": meta.get("endpoint"),
        "persistent_keepalive": meta.get("persistent_keepalive"),
        "has_preshared_key": bool(meta.get("preshared_key")),
        "enabled": meta.get("enabled", True),
        "managed": True,
    }


def _meta_to_conf_peer(pubkey: str, meta: dict) -> dict:
    """Convert stored metadata to the format expected by _write_conf."""
    # Server-side AllowedIPs = peer's primary address + extra subnets behind peer
    server_allowed: list[str] = []
    if meta.get("peer_address"):
        server_allowed.append(meta["peer_address"])
    for ip in meta.get("extra_allowed_ips", []):
        if ip and ip not in server_allowed:
            server_allowed.append(ip)
    return {
        "public_key": pubkey,
        "allowed_ips": server_allowed,
        "endpoint": None,  # server doesn't pin client endpoint
        "preshared_key": meta.get("preshared_key"),
        "persistent_keepalive": None,
        "comment": meta.get("comment", ""),
    }


def _client_filename(meta: dict) -> str:
    name = (meta.get("account_name") or meta.get("comment") or "wg-client").strip() or "wg-client"
    return re.sub(r"[^A-Za-z0-9._\-]", "_", name) + ".conf"


def _client_qr_filename(config_filename: str) -> str:
    stem = config_filename[:-5] if config_filename.lower().endswith(".conf") else config_filename
    return f"{stem}.qr.png"


def _parse_display_names(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip()[:128] for v in value]
    text = str(value or "")
    return [line.strip()[:128] for line in text.splitlines()]


def _build_bulk_peer_zip(iface: str, created: list[tuple[str, dict, str, str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest_buf = io.StringIO()
        writer = csv.writer(manifest_buf)
        writer.writerow(["account_name", "display_name", "peer_address", "filename", "qr_filename", "public_key"])
        for pubkey, meta, client_conf, filename in created:
            qr_filename = _client_qr_filename(filename)
            zf.writestr(filename, client_conf)
            zf.writestr(qr_filename, _generate_qr_png(client_conf))
            writer.writerow([
                meta.get("account_name") or meta.get("comment") or "",
                meta.get("display_name") or "",
                meta.get("peer_address") or "",
                filename,
                qr_filename,
                pubkey,
            ])
        zf.writestr(f"{iface}-accounts.csv", manifest_buf.getvalue())
    return buf.getvalue()


# ---- conf file helpers --------------------------------------------------

def _interface_is_active(iface: str) -> bool:
    res = run(["ip", "-o", "link", "show", iface])
    return res.ok and "UP" in res.stdout


def _ensure_interface_running(iface: str) -> None:
    """Enable and start wg-quick@<iface> when an interface config exists."""
    if _interface_is_active(iface):
        return
    res = sudo_run(["systemctl", "enable", "--now", f"wg-quick@{iface}"], timeout=30)
    if not res.ok:
        raise RuntimeError(f"wg-quick start failed: {(res.stderr or res.stdout).strip()}")


def _detect_wan_endpoint(listen_port: Optional[int] = None) -> str:
    """Return the best default endpoint for generated client configs."""
    candidates = _detect_endpoint_candidates(listen_port)
    if candidates:
        return candidates[0]["value"]
    port = _safe_listen_port(listen_port)
    return f"YOUR-PUBLIC-IP:{port}"


def _detect_endpoint_candidates(listen_port: Optional[int] = None) -> list[dict]:
    """Build WireGuard endpoint candidates in operator-friendly priority order."""
    port = _safe_listen_port(listen_port)
    candidates: list[dict] = []
    candidates.extend(_ddns_endpoint_candidates(port))
    candidates.extend(_wan_ip_endpoint_candidates(port))
    candidates.extend(_lan_ip_endpoint_candidates(port))
    try:
        host = Path("/etc/hostname").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        host = ""
    if host:
        candidates.append({
            "value": f"{host}:{port}",
            "label": f"ホスト名: {host} (ローカルDNSがある場合)",
            "kind": "hostname",
        })
    return _dedupe_endpoint_candidates(candidates)


def _effective_client_endpoint(endpoint: Optional[str], listen_port: Optional[int] = None) -> str:
    """Replace the old auto-generated short hostname endpoint with a usable candidate."""
    raw = (endpoint or "").strip()
    if not raw:
        return _detect_wan_endpoint(listen_port)
    host, port = _split_endpoint(raw)
    local_host = _read_local_hostname()
    if host and local_host and host == local_host:
        return _detect_wan_endpoint(port or listen_port)
    return raw


def _safe_listen_port(listen_port: Optional[int]) -> int:
    try:
        port = int(listen_port or 51820)
    except (TypeError, ValueError):
        return 51820
    return port if 1 <= port <= 65535 else 51820


def _read_local_hostname() -> str:
    try:
        return Path("/etc/hostname").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _split_endpoint(endpoint: str) -> tuple[str, Optional[int]]:
    match = re.match(r"^([A-Za-z0-9._\-]+):(\d{1,5})$", endpoint.strip())
    if not match:
        return endpoint.strip(), None
    try:
        return match.group(1), int(match.group(2))
    except ValueError:
        return match.group(1), None


def _ddns_endpoint_candidates(port: int) -> list[dict]:
    data = _load_ddns_state()
    candidates: list[dict] = []
    for provider in data.get("providers", []) or []:
        if not provider.get("enabled", True):
            continue
        account = str(provider.get("account") or provider.get("name") or "").strip().strip(".")
        domain = str(provider.get("domain") or "").strip().strip(".")
        if not account or not domain:
            continue
        host = account if account.endswith(f".{domain}") else f"{account}.{domain}"
        candidates.append({"value": f"{host}:{port}", "label": f"DDNS: {host}", "kind": "ddns"})
    return candidates


def _load_ddns_state() -> dict:
    paths = []
    try:
        paths.append(Path(current_app.config["CONFIG_DIR"]) / "ddns.json")
    except RuntimeError:
        pass
    paths.append(Path("/etc/server-gui/ddns.json"))
    for path in paths:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    return {}


def _wan_ip_endpoint_candidates(port: int) -> list[dict]:
    candidates: list[dict] = []
    for ip in _detect_wan_global_ipv4s():
        candidates.append({"value": f"{ip}:{port}", "label": f"WAN IP: {ip}", "kind": "wan_ip"})
    return candidates


def _detect_wan_global_ipv4s() -> list[str]:
    route_res = run(["ip", "-j", "route", "show", "default"])
    route_devs: list[str] = []
    route_srcs: list[str] = []
    if route_res.ok:
        try:
            routes = json.loads(route_res.stdout)
        except json.JSONDecodeError:
            routes = []
        for route in routes if isinstance(routes, list) else []:
            dev = route.get("dev")
            if dev and dev not in route_devs:
                route_devs.append(dev)
            src = route.get("prefsrc") or route.get("src")
            if _is_global_ipv4(src) and src not in route_srcs:
                route_srcs.append(src)

    ips: list[str] = list(route_srcs)
    for dev in route_devs:
        for ip in _interface_ipv4s(dev):
            if _is_global_ipv4(ip) and ip not in ips:
                ips.append(ip)
    if ips:
        return ips

    res = run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return []
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    for entry in data if isinstance(data, list) else []:
        if entry.get("ifname") in ("lo",) or str(entry.get("ifname", "")).startswith("wg"):
            continue
        for addr in entry.get("addr_info", []) or []:
            if addr.get("family") == "inet" and _is_global_ipv4(addr.get("local")):
                ip = addr["local"]
                if ip not in ips:
                    ips.append(ip)
    return ips


def _interface_ipv4s(ifname: str) -> list[str]:
    res = run(["ip", "-j", "addr", "show", "dev", ifname])
    if not res.ok:
        return []
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    out: list[str] = []
    for entry in data if isinstance(data, list) else []:
        for addr in entry.get("addr_info", []) or []:
            if addr.get("family") == "inet" and addr.get("local"):
                out.append(addr["local"])
    return out


def _lan_ip_endpoint_candidates(port: int) -> list[dict]:
    candidates: list[dict] = []
    for ip in _detect_lan_private_ipv4s():
        candidates.append({"value": f"{ip}:{port}", "label": f"LAN IP: {ip}", "kind": "lan_ip"})
    return candidates


def _detect_lan_private_ipv4s() -> list[str]:
    route_res = run(["ip", "-j", "route", "show", "default"])
    wan_ifnames: set[str] = set()
    if route_res.ok:
        try:
            routes = json.loads(route_res.stdout)
        except json.JSONDecodeError:
            routes = []
        for route in routes if isinstance(routes, list) else []:
            if route.get("dev"):
                wan_ifnames.add(route["dev"])

    res = run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return []
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    ips: list[str] = []
    for entry in data if isinstance(data, list) else []:
        ifname = entry.get("ifname", "")
        if not ifname or ifname in wan_ifnames or ifname == "lo" or ifname.startswith("wg"):
            continue
        for addr in entry.get("addr_info", []) or []:
            ip = addr.get("local")
            if addr.get("family") == "inet" and _is_private_ipv4(ip) and ip not in ips:
                ips.append(ip)
    return ips


def _is_global_ipv4(value: object) -> bool:
    try:
        ip = ipaddress.IPv4Address(str(value))
    except ValueError:
        return False
    return ip.is_global


def _is_private_ipv4(value: object) -> bool:
    try:
        ip = ipaddress.IPv4Address(str(value))
    except ValueError:
        return False
    return ip.is_private


def _dedupe_endpoint_candidates(candidates: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = str(candidate.get("value") or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append({
            "value": value,
            "label": str(candidate.get("label") or value),
            "kind": str(candidate.get("kind") or "custom"),
        })
    return out


def _parse_wg_conf(path: Path) -> dict:
    interface: dict = {
        "address": [], "listen_port": None, "private_key": None,
        "post_up": [], "post_down": [], "dns": [], "mtu": None, "table": None,
    }
    peers: list[dict] = []
    current = None
    current_peer: Optional[dict] = None
    last_comment = ""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"interface": interface, "peers": peers}

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            last_comment = ""
            continue
        if stripped.startswith("#"):
            last_comment = stripped.lstrip("#").strip()
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section == "interface":
                current = "interface"
            elif section == "peer":
                if current_peer:
                    peers.append(current_peer)
                current = "peer"
                current_peer = {
                    "public_key": None, "allowed_ips": [], "endpoint": None,
                    "preshared_key": None, "persistent_keepalive": None,
                    "comment": last_comment or "",
                }
                last_comment = ""
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if current == "interface":
            if key == "address":
                interface["address"].extend(s.strip() for s in value.split(",") if s.strip())
            elif key == "listenport":
                try: interface["listen_port"] = int(value)
                except ValueError: pass
            elif key == "privatekey":
                interface["private_key"] = value
            elif key == "postup":
                interface["post_up"].append(value)
            elif key == "postdown":
                interface["post_down"].append(value)
            elif key == "dns":
                interface["dns"].extend(s.strip() for s in value.split(",") if s.strip())
            elif key == "mtu":
                try: interface["mtu"] = int(value)
                except ValueError: pass
            elif key == "table":
                interface["table"] = value
        elif current == "peer" and current_peer is not None:
            if key == "publickey":
                current_peer["public_key"] = value
            elif key == "allowedips":
                current_peer["allowed_ips"].extend(s.strip() for s in value.split(",") if s.strip())
            elif key == "endpoint":
                current_peer["endpoint"] = value
            elif key == "presharedkey":
                current_peer["preshared_key"] = value
            elif key == "persistentkeepalive":
                try: current_peer["persistent_keepalive"] = int(value)
                except ValueError: pass
    if current_peer:
        peers.append(current_peer)
    return {"interface": interface, "peers": peers}


def _write_conf(iface: str, parsed: dict) -> None:
    lines: list[str] = ["[Interface]"]
    intf = parsed["interface"]
    if intf.get("address"):
        lines.append(f"Address = {', '.join(intf['address'])}")
    if intf.get("listen_port") is not None:
        lines.append(f"ListenPort = {intf['listen_port']}")
    if intf.get("private_key"):
        lines.append(f"PrivateKey = {intf['private_key']}")
    if intf.get("mtu") is not None:
        lines.append(f"MTU = {intf['mtu']}")
    if intf.get("dns"):
        lines.append(f"DNS = {', '.join(intf['dns'])}")
    if intf.get("table"):
        lines.append(f"Table = {intf['table']}")
    for u in intf.get("post_up", []):
        if u: lines.append(f"PostUp = {u}")
    for d in intf.get("post_down", []):
        if d: lines.append(f"PostDown = {d}")
    for p in parsed["peers"]:
        lines.append("")
        if p.get("comment"):
            lines.append(f"# {p['comment']}")
        lines.append("[Peer]")
        if p.get("public_key"):
            lines.append(f"PublicKey = {p['public_key']}")
        if p.get("preshared_key"):
            lines.append(f"PresharedKey = {p['preshared_key']}")
        if p.get("allowed_ips"):
            lines.append(f"AllowedIPs = {', '.join(p['allowed_ips'])}")
        if p.get("endpoint"):
            lines.append(f"Endpoint = {p['endpoint']}")
        if p.get("persistent_keepalive") is not None:
            lines.append(f"PersistentKeepalive = {p['persistent_keepalive']}")
    path = WG_DIR / f"{iface}.conf"
    tmp = path.with_suffix(".conf.new")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(path)


def _sync_interface(iface: str) -> None:
    if not _interface_is_active(iface):
        return
    strip = sudo_run(["wg-quick", "strip", iface])
    if not strip.ok:
        raise RuntimeError(f"wg-quick strip failed: {strip.stderr.strip()}")
    tmp = Path(f"/tmp/wg-sync-{iface}.conf")
    tmp.write_text(strip.stdout, encoding="utf-8")
    try:
        res = sudo_run(["wg", "syncconf", iface, str(tmp)])
        if not res.ok:
            raise RuntimeError(f"wg syncconf failed: {res.stderr.strip()}")
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _sync_firewalld_for_interface(iface: str, parsed: dict) -> None:
    """Open WireGuard and LAN forwarding for an active interface."""
    active = sudo_run(["systemctl", "is-active", "firewalld"], timeout=15)
    if not active.ok or active.stdout.strip() != "active":
        return

    changed = False
    listen_port = parsed.get("interface", {}).get("listen_port")
    endpoint_zone = _preferred_wireguard_endpoint_zone()
    if endpoint_zone and listen_port:
        if _firewalld_service_available("wireguard"):
            changed |= _firewalld_add(["--zone", endpoint_zone, "--add-service", "wireguard"])
        changed |= _firewalld_add(["--zone", endpoint_zone, "--add-port", f"{listen_port}/udp"])

    changed |= _firewalld_add(["--zone", "trusted", "--add-interface", iface])
    changed |= _firewalld_add(["--zone", "trusted", "--add-forward"])

    wg_nets = _interface_ipv4_networks(parsed.get("interface", {}).get("address", []))
    lan_nets = _detect_lan_subnets(exclude=parsed.get("interface", {}).get("address", []))
    lan_ifaces = _detect_lan_interfaces(exclude_ifaces={iface})
    for lan_iface in lan_ifaces:
        changed |= _add_direct_rule("ipv4", "filter", "FORWARD", 0, f"-i {iface} -o {lan_iface} -j ACCEPT")
        changed |= _add_direct_rule("ipv4", "filter", "FORWARD", 0, f"-i {lan_iface} -o {iface} -j ACCEPT")
        changed |= _remove_direct_rule("ipv4", "filter", "FORWARD", 0, f"-i {lan_iface} -o {iface} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    for wg_net in wg_nets:
        for lan_net in lan_nets:
            changed |= _add_direct_rule("ipv4", "filter", "FORWARD", 0, f"-s {wg_net} -d {lan_net} -j ACCEPT")
            changed |= _add_direct_rule("ipv4", "filter", "FORWARD", 0, f"-s {lan_net} -d {wg_net} -j ACCEPT")
            # Mobile WireGuard paths often have a smaller effective MTU than the
            # LAN. Clamp SMB and other TCP sessions before packet loss causes
            # retransmission-heavy transfers.
            changed |= _add_direct_rule(
                "ipv4", "mangle", "FORWARD", 0,
                f"-s {wg_net} -d {lan_net} -p tcp --tcp-flags SYN,RST SYN "
                f"-m comment --comment synca-wg-mss -j TCPMSS --set-mss {_WIREGUARD_LAN_TCP_MSS}",
            )
            changed |= _add_direct_rule(
                "ipv4", "mangle", "FORWARD", 0,
                f"-s {lan_net} -d {wg_net} -p tcp --tcp-flags SYN,RST SYN "
                f"-m comment --comment synca-wg-mss -j TCPMSS --set-mss {_WIREGUARD_LAN_TCP_MSS}",
            )
            changed |= _remove_direct_rule("ipv4", "filter", "FORWARD", 0, f"-s {lan_net} -d {wg_net} -m state --state RELATED,ESTABLISHED -j ACCEPT")

    if changed:
        reload_res = sudo_run(["firewall-cmd", "--reload"], timeout=30)
        if not reload_res.ok:
            raise RuntimeError((reload_res.stderr or reload_res.stdout).strip())


def _preferred_wireguard_endpoint_zone() -> str | None:
    zones = sudo_run(["firewall-cmd", "--get-zones"], timeout=15)
    if zones.ok and "japan" in zones.stdout.split():
        return "japan"
    default = sudo_run(["firewall-cmd", "--get-default-zone"], timeout=15)
    if default.ok and default.stdout.strip():
        return default.stdout.strip()
    return None


def _interface_ipv4_networks(addrs: list[str]) -> list[str]:
    out: list[str] = []
    for addr in addrs or []:
        try:
            net = ipaddress.IPv4Interface(addr).network
        except ValueError:
            continue
        out.append(str(net))
    return out


def _detect_lan_interfaces(exclude_ifaces: set[str] | None = None) -> list[str]:
    import json as _json
    exclude_ifaces = exclude_ifaces or set()
    route_res = run(["ip", "-j", "route", "show", "default"])
    wan_ifname = ""
    if route_res.ok:
        try:
            routes = _json.loads(route_res.stdout)
            if routes and isinstance(routes, list):
                wan_ifname = routes[0].get("dev", "")
        except _json.JSONDecodeError:
            pass
    res = run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return []
    try:
        data = _json.loads(res.stdout)
    except _json.JSONDecodeError:
        return []
    out: list[str] = []
    for entry in data:
        ifname = entry.get("ifname", "")
        if not ifname or ifname in exclude_ifaces or ifname in ("lo", wan_ifname) or ifname.startswith("wg"):
            continue
        has_private_v4 = False
        for addr in entry.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            try:
                ip = ipaddress.IPv4Address(addr.get("local", ""))
            except ValueError:
                continue
            if ip.is_private:
                has_private_v4 = True
                break
        if has_private_v4:
            out.append(ifname)
    return out


def _firewalld_add(args: list[str]) -> bool:
    query_args = _firewalld_query_args_for_add(args)
    if query_args:
        query = sudo_run(["firewall-cmd", "--permanent", *query_args], timeout=30)
        if query.ok and query.stdout.strip() == "yes":
            return False

    res = sudo_run(["firewall-cmd", "--permanent", *args], timeout=30)
    text = (res.stderr or res.stdout).strip()
    if res.ok:
        return True
    if "ALREADY_ENABLED" in text or "ZONE_ALREADY_SET" in text or "already" in text.lower():
        return False
    raise RuntimeError(text)


def _firewalld_query_args_for_add(args: list[str]) -> list[str] | None:
    """既存firewalld設定をqueryし、不要な定期reloadを避ける。"""
    if "--zone" not in args:
        return None
    zone_index = args.index("--zone")
    if zone_index + 1 >= len(args):
        return None
    zone = args[zone_index + 1]
    if "--add-forward" in args:
        return ["--zone", zone, "--query-forward"]
    checks = {
        "--add-service": "--query-service",
        "--add-port": "--query-port",
        "--add-interface": "--query-interface",
        "--add-source": "--query-source",
        "--add-rich-rule": "--query-rich-rule",
    }
    for add_arg, query_arg in checks.items():
        if add_arg in args:
            value_index = args.index(add_arg) + 1
            if value_index >= len(args):
                return None
            return ["--zone", zone, query_arg, args[value_index]]
    return None


def _firewalld_service_available(service: str) -> bool:
    res = sudo_run(["firewall-cmd", "--get-services"], timeout=15)
    return res.ok and service in set(res.stdout.split())


def _add_direct_rule(ipv: str, table: str, chain: str, priority: int, args: str) -> bool:
    line = f"{ipv} {table} {chain} {priority} {args}"
    existing = sudo_run(["firewall-cmd", "--permanent", "--direct", "--get-all-rules"], timeout=30)
    if existing.ok and line in {ln.strip() for ln in existing.stdout.splitlines()}:
        return False
    res = sudo_run([
        "firewall-cmd", "--permanent", "--direct", "--add-rule",
        ipv, table, chain, str(priority), *shlex.split(args),
    ], timeout=30)
    if not res.ok:
        raise RuntimeError((res.stderr or res.stdout).strip())
    return True


def _remove_direct_rule(ipv: str, table: str, chain: str, priority: int, args: str) -> bool:
    line = f"{ipv} {table} {chain} {priority} {args}"
    existing = sudo_run(["firewall-cmd", "--permanent", "--direct", "--get-all-rules"], timeout=30)
    if not existing.ok or line not in {ln.strip() for ln in existing.stdout.splitlines()}:
        return False
    res = sudo_run([
        "firewall-cmd", "--permanent", "--direct", "--remove-rule",
        ipv, table, chain, str(priority), *shlex.split(args),
    ], timeout=30)
    if not res.ok:
        raise RuntimeError((res.stderr or res.stdout).strip())
    return True


def _wg_show_dump(iface: str) -> dict:
    res = sudo_run(["wg", "show", iface, "dump"])
    if not res.ok:
        return {"interface": {}, "peers_status": {}}
    lines = res.stdout.splitlines()
    if not lines:
        return {"interface": {}, "peers_status": {}}
    parts = lines[0].split("\t")
    iface_info: dict = {}
    if len(parts) >= 4:
        iface_info = {
            "public_key": parts[1],
            "listen_port": int(parts[2]) if parts[2].isdigit() else None,
            "fwmark": parts[3],
        }
    peers_status: dict = {}
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) >= 8:
            peers_status[parts[0]] = {
                "endpoint": parts[2] if parts[2] != "(none)" else None,
                "allowed_ips": parts[3].split(",") if parts[3] and parts[3] != "(none)" else [],
                "latest_handshake": int(parts[4]) if parts[4].isdigit() else 0,
                "rx_bytes": int(parts[5]) if parts[5].isdigit() else 0,
                "tx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
                "persistent_keepalive": int(parts[7]) if parts[7].isdigit() else 0,
            }
    return {"interface": iface_info, "peers_status": peers_status}


def _gen_keys() -> tuple[str, str]:
    priv = run(["wg", "genkey"])
    if not priv.ok:
        raise RuntimeError(f"wg genkey failed: {priv.stderr}")
    privkey = priv.stdout.strip()
    pub = run(["wg", "pubkey"], stdin=privkey)
    if not pub.ok:
        raise RuntimeError(f"wg pubkey failed: {pub.stderr}")
    return privkey, pub.stdout.strip()


def _gen_unique_peer_keys(parsed: dict) -> tuple[str, str]:
    existing = {p.get("public_key") for p in parsed.get("peers", []) if p.get("public_key")}
    for _ in range(5):
        priv, pub = _gen_keys()
        if pub not in existing:
            return priv, pub
    raise RuntimeError("pubkey collision (rare)")


def _gen_preshared() -> str:
    res = run(["wg", "genpsk"])
    return res.stdout.strip() if res.ok else ""


def _pubkey_from_priv(privkey: Optional[str]) -> Optional[str]:
    if not privkey:
        return None
    res = run(["wg", "pubkey"], stdin=privkey)
    return res.stdout.strip() if res.ok else None


def _build_client_config(meta: dict, server_pub: Optional[str], listen_port: Optional[int] = None) -> str:
    address = meta.get("peer_address", "")
    lines = [
        "[Interface]",
        f"PrivateKey = {meta.get('private_key', '<unknown>')}",
        f"Address = {address}",
    ]
    if meta.get("client_dns"):
        lines.append(f"DNS = {', '.join(meta['client_dns'])}")
    if meta.get("client_mtu"):
        lines.append(f"MTU = {meta['client_mtu']}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pub or '<server pubkey unknown>'}")
    if meta.get("preshared_key"):
        lines.append(f"PresharedKey = {meta['preshared_key']}")
    aips = meta.get("client_allowed_ips") or ["0.0.0.0/0", "::/0"]
    lines.append(f"AllowedIPs = {', '.join(aips)}")
    endpoint = _effective_client_endpoint(meta.get("endpoint"), listen_port)
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    if meta.get("persistent_keepalive"):
        lines.append(f"PersistentKeepalive = {meta['persistent_keepalive']}")
    return "\n".join(lines) + "\n"


def _generate_qr_svg(text: str) -> str:
    """Generate QR SVG for a client config without requiring qrencode RPM."""
    if not text:
        return ""
    try:
        import qrcode
        import qrcode.image.svg

        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            border=2,
        )
        qr.add_data(text)
        qr.make(fit=True)
        image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        buf = io.BytesIO()
        image.save(buf)
        return _normalize_inline_svg(buf.getvalue().decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("Python QR generation failed; falling back to qrencode: %s", exc)

    res = run(["qrencode", "-t", "SVG", "-o", "-", text])
    if res.ok and res.stdout.strip():
        return _normalize_inline_svg(res.stdout)
    logger.warning("WireGuard QR generation failed: %s", (res.stderr or res.stdout).strip())
    return ""


def _generate_qr_png(text: str) -> bytes:
    """Generate QR PNG bytes for ZIP downloads."""
    if not text:
        return b""
    try:
        import qrcode

        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            border=2,
        )
        qr.add_data(text)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return buf.getvalue()
    except Exception as exc:
        logger.warning("WireGuard QR PNG generation failed: %s", exc)
        return b""


def _normalize_inline_svg(svg: str) -> str:
    """Return only the SVG element so it can be assigned to innerHTML."""
    start = svg.find("<svg")
    if start > 0:
        svg = svg[start:]
    return svg.strip()


def _now() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")
