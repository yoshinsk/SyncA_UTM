"""payload/server-gui/server_gui/modules/ipv6.py - Manage opt-in IPv6 routing.

SyncA UTM keeps IPv6 disabled by default. This module enables router-grade IPv6
only when the operator explicitly saves an enabled profile. It manages the
kernel forwarding knobs, selected NetworkManager IPv6 methods, radvd prefix
advertisements, optional dnsmasq DHCPv6 ranges, and simple SIT tunnels.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any, Optional

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run, sudo_run
from ..validators import ValidationError, validate_interface

bp = Blueprint("ipv6", __name__, url_prefix="/ipv6")

CONFIG_NAME = "ipv6"
RADVD_CONF = Path("/etc/radvd.conf")
DNSMASQ_IPV6_CONF = Path("/etc/dnsmasq.d/synca-ipv6.conf")
SYSCTL_CONF = Path("/etc/sysctl.d/99-synca-ipv6.conf")
TRANSITION_SCRIPT = Path("/usr/local/sbin/synca-ipv6-transition")
TRANSITION_UNIT = Path("/etc/systemd/system/synca-ipv6-transition.service")
FRR_CONF = Path("/etc/frr/frr.conf")
FRR_DAEMONS = Path("/etc/frr/daemons")
RADVD_UNIT = "radvd.service"
DNSMASQ_UNIT = "dnsmasq.service"
TRANSITION_UNIT_NAME = "synca-ipv6-transition.service"
FRR_UNIT = "frr.service"
MANAGED_HEADER = "# Managed by SyncA UTM IPv6 module."
FRR_MANAGED_HEADER = "! Managed by SyncA UTM IPv6 module."
LIFETIME_RE = re.compile(r"^\d{1,7}$")
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")
DESCRIPTION_RE = re.compile(r"^[A-Za-z0-9_.:@/ +,-]{0,80}$")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def page():
    return render_template("ipv6.html", active_tab="ipv6")


@bp.route("/api/status", methods=["GET"])
@login_required
def status():
    settings = _load_settings()
    return jsonify({
        "settings": settings,
        "interfaces": _interface_rows(),
        "wan_candidates": _default_wan_interfaces(),
        "lan_candidates": _default_lan_interfaces(),
        "tools": _tool_status(),
        "services": {
            "radvd": _service_state(RADVD_UNIT),
            "dnsmasq": _service_state(DNSMASQ_UNIT),
            "transition": _service_state(TRANSITION_UNIT_NAME),
            "frr": _service_state(FRR_UNIT),
        },
        "sysctl": _sysctl_status(),
        "detected_prefixes": _detected_ipv6_prefixes(),
        "transition": _transition_status(),
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


@bp.route("/api/renumber", methods=["POST"])
@login_required
@csrf_protect
def renumber():
    payload = request.get_json(force=True, silent=True) or {}
    old_prefix = str(payload.get("old_prefix") or "").strip()
    new_prefix = str(payload.get("new_prefix") or "").strip()
    try:
        old_net = ipaddress.IPv6Network(old_prefix, strict=False)
        new_net = ipaddress.IPv6Network(new_prefix, strict=False)
    except ValueError as e:
        return jsonify({"ok": False, "error": f"IPv6プレフィックスが不正です: {e}"}), 400
    if old_net.prefixlen != new_net.prefixlen:
        return jsonify({"ok": False, "error": "旧プレフィックスと新プレフィックスのprefix長は同じにしてください"}), 400

    settings = _load_settings()
    changed = False
    for adv in settings.get("advertisements", []):
        if str(ipaddress.IPv6Network(adv.get("prefix", "::/128"), strict=False)) != str(old_net):
            continue
        adv["prefix"] = str(new_net)
        adv["router_address"] = _replace_prefix_address(adv.get("router_address", ""), old_net, new_net)
        adv["dhcp_start"] = _replace_prefix_address(adv.get("dhcp_start", ""), old_net, new_net, host_only=True)
        adv["dhcp_end"] = _replace_prefix_address(adv.get("dhcp_end", ""), old_net, new_net, host_only=True)
        changed = True

    if not changed:
        return jsonify({"ok": False, "error": "指定された旧プレフィックスは通知設定内に見つかりません"}), 404
    _save_settings(settings)
    result = _apply_runtime(settings)
    result["renumbered"] = {"old_prefix": str(old_net), "new_prefix": str(new_net)}
    return jsonify(result), (200 if result.get("ok") else 500)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default_settings() -> dict:
    return {
        "enabled": False,
        "wan": {
            "interface": "",
            "method": "disabled",  # disabled|slaac|dhcpv6|manual
            "address": "",
            "gateway": "",
            "dns_servers": [],
        },
        "advertisements": [],
        "transition": {
            "mode": "disabled",  # disabled|6to4|6in4
            "name": "synca6",
            "local_ipv4": "auto",
            "remote_ipv4": "",
            "tunnel_address": "",
            "routed_prefix": "",
            "default_route": True,
        },
        "firewall": {
            "allow_icmpv6": True,
            "allow_dhcpv6": True,
        },
        "routing": {
            "enabled": False,
            "ospf6": {
                "enabled": False,
                "router_id": "",
                "interfaces": [],
            },
            "bgp": {
                "enabled": False,
                "local_as": "",
                "router_id": "",
                "neighbors": [],
                "networks": [],
            },
        },
    }


def _load_settings() -> dict:
    data = _store().load(CONFIG_NAME, _default_settings())
    if not isinstance(data, dict):
        return _default_settings()
    merged = _deep_merge(_default_settings(), data)
    merged["wan"]["dns_servers"] = _ipv6_list(merged["wan"].get("dns_servers"))
    merged["advertisements"] = [_normalize_advertisement(a, require_enabled=False) for a in merged.get("advertisements", [])]
    merged["transition"] = _normalize_transition(merged.get("transition", {}), require_enabled=False)
    merged["routing"] = _normalize_routing(merged.get("routing", {}), require_enabled=False)
    return merged


def _save_settings(settings: dict) -> None:
    _store().save(CONFIG_NAME, settings)


def _normalize_settings(payload: dict) -> dict:
    current = _load_settings()
    enabled = bool(payload.get("enabled", current.get("enabled", False)))
    raw_wan = payload.get("wan", current.get("wan", {}))
    raw_transition = payload.get("transition", current.get("transition", {}))
    raw_firewall = payload.get("firewall", current.get("firewall", {}))
    raw_routing = payload.get("routing", current.get("routing", {}))
    raw_advertisements = payload.get("advertisements", current.get("advertisements", []))

    wan = _normalize_wan(raw_wan, require_enabled=enabled)
    advertisements = [_normalize_advertisement(a, require_enabled=enabled) for a in (raw_advertisements or [])]
    advertisements = [a for a in advertisements if a.get("interface") or a.get("prefix")]
    transition = _normalize_transition(raw_transition, require_enabled=enabled)
    routing = _normalize_routing(raw_routing, require_enabled=enabled)

    if enabled and not advertisements and transition["mode"] == "disabled" and not routing["enabled"]:
        raise ValidationError("IPv6を有効にする場合はLANプレフィックス通知、トンネル、動的ルーティングのいずれかを設定してください")
    if enabled and wan["method"] != "disabled" and not wan["interface"]:
        raise ValidationError("WAN側IPv6を有効にする場合はWANインターフェースが必要です")

    return {
        "enabled": enabled,
        "wan": wan,
        "advertisements": advertisements,
        "transition": transition,
        "firewall": {
            "allow_icmpv6": bool(raw_firewall.get("allow_icmpv6", current["firewall"].get("allow_icmpv6", True))),
            "allow_dhcpv6": bool(raw_firewall.get("allow_dhcpv6", current["firewall"].get("allow_dhcpv6", True))),
        },
        "routing": routing,
    }


def _normalize_wan(raw: dict, require_enabled: bool) -> dict:
    method = str(raw.get("method", "disabled")).strip().lower() or "disabled"
    if method not in {"disabled", "slaac", "dhcpv6", "manual"}:
        raise ValidationError("WAN取得方式は無効、SLAAC、DHCPv6、手動のいずれかを指定してください")
    interface = str(raw.get("interface", "")).strip()
    if interface:
        interface = validate_interface(interface)
    address = str(raw.get("address", "")).strip()
    gateway = str(raw.get("gateway", "")).strip()
    if method == "manual":
        address = _validate_ipv6_interface(address, "WAN address")
        gateway = _validate_ipv6_address(gateway, "WAN gateway")
    elif method in {"slaac", "dhcpv6"} and require_enabled and not interface:
        raise ValidationError("WANインターフェースが必要です")
    return {
        "interface": interface,
        "method": method,
        "address": address if method == "manual" else "",
        "gateway": gateway if method == "manual" else "",
        "dns_servers": _ipv6_list(raw.get("dns_servers")),
    }


def _normalize_advertisement(raw: dict, require_enabled: bool) -> dict:
    interface = str(raw.get("interface", "")).strip()
    prefix = str(raw.get("prefix", "")).strip()
    if interface:
        interface = validate_interface(interface)
    if prefix:
        prefix = _validate_ipv6_prefix(prefix, require_64=True)
    elif require_enabled and interface:
        raise ValidationError(f"{interface} のIPv6プレフィックスが必要です")
    mode = str(raw.get("mode", "slaac")).strip().lower() or "slaac"
    if mode not in {"slaac", "stateless", "managed"}:
        raise ValidationError("RAモードはSLAAC、ステートレスDHCPv6、ステートフルDHCPv6のいずれかを指定してください")
    valid_lifetime = _validate_lifetime(raw.get("valid_lifetime", 86400), "valid_lifetime")
    preferred_lifetime = _validate_lifetime(raw.get("preferred_lifetime", 14400), "preferred_lifetime")
    if preferred_lifetime > valid_lifetime:
        raise ValidationError("推奨期限は有効期限以下にしてください")
    dns_servers = _ipv6_list(raw.get("dns_servers"))
    domain = str(raw.get("domain", "")).strip()
    if domain and not HOST_LABEL_RE.match(domain):
        raise ValidationError("ドメイン名に使用できない文字が含まれています")
    router_address = str(raw.get("router_address", "")).strip()
    if prefix:
        router_address = _validate_or_default_router_address(router_address, prefix)
    dhcp_start = str(raw.get("dhcp_start", "")).strip()
    dhcp_end = str(raw.get("dhcp_end", "")).strip()
    if mode == "managed":
        if not dhcp_start:
            dhcp_start = _prefix_host(prefix, 0x100)
        if not dhcp_end:
            dhcp_end = _prefix_host(prefix, 0x1ff)
    if dhcp_start:
        dhcp_start = _validate_ipv6_address(dhcp_start, "DHCPv6 start")
    if dhcp_end:
        dhcp_end = _validate_ipv6_address(dhcp_end, "DHCPv6 end")
    if dhcp_start and dhcp_end and ipaddress.IPv6Address(dhcp_start) > ipaddress.IPv6Address(dhcp_end):
        raise ValidationError("DHCPv6開始アドレスは終了アドレス以下にしてください")
    lease = str(raw.get("lease", "12h")).strip() or "12h"
    if not re.match(r"^\d+[smhd]$|^infinite$", lease, re.IGNORECASE):
        raise ValidationError("リース時間は 12h、1d、infinite のように指定してください")
    return {
        "interface": interface,
        "prefix": prefix,
        "mode": mode,
        "router_address": router_address,
        "valid_lifetime": valid_lifetime,
        "preferred_lifetime": preferred_lifetime,
        "dns_servers": dns_servers,
        "domain": domain,
        "dhcp_start": dhcp_start,
        "dhcp_end": dhcp_end,
        "lease": lease,
    }


def _normalize_transition(raw: dict, require_enabled: bool) -> dict:
    mode = str(raw.get("mode", "disabled")).strip().lower() or "disabled"
    if mode not in {"disabled", "6to4", "6in4"}:
        raise ValidationError("トンネル方式は無効、6to4、6in4のいずれかを指定してください")
    name = str(raw.get("name", "synca6")).strip() or "synca6"
    name = validate_interface(name[:15])
    local_ipv4 = str(raw.get("local_ipv4", "auto")).strip() or "auto"
    if local_ipv4 != "auto":
        _validate_ipv4(local_ipv4, "local IPv4")
    remote_ipv4 = str(raw.get("remote_ipv4", "")).strip()
    tunnel_address = str(raw.get("tunnel_address", "")).strip()
    routed_prefix = str(raw.get("routed_prefix", "")).strip()
    if mode == "6in4":
        remote_ipv4 = _validate_ipv4(remote_ipv4, "remote IPv4")
        tunnel_address = _validate_ipv6_interface(tunnel_address, "tunnel address")
        if routed_prefix:
            routed_prefix = _validate_ipv6_prefix(routed_prefix, require_64=False)
        elif require_enabled:
            raise ValidationError("6in4ではルーティングプレフィックスが必要です")
    elif mode == "6to4":
        remote_ipv4 = ""
        tunnel_address = ""
        routed_prefix = ""
    else:
        local_ipv4 = "auto"
        remote_ipv4 = ""
        tunnel_address = ""
        routed_prefix = ""
    return {
        "mode": mode,
        "name": name,
        "local_ipv4": local_ipv4,
        "remote_ipv4": remote_ipv4,
        "tunnel_address": tunnel_address,
        "routed_prefix": routed_prefix,
        "default_route": bool(raw.get("default_route", True)),
    }


def _normalize_routing(raw: dict, require_enabled: bool) -> dict:
    enabled = bool(raw.get("enabled", False))
    ospf6 = _normalize_ospf6(raw.get("ospf6", {}), enabled and require_enabled)
    bgp = _normalize_bgp(raw.get("bgp", {}), enabled and require_enabled)
    if enabled and require_enabled and not ospf6["enabled"] and not bgp["enabled"]:
        raise ValidationError("動的ルーティングではOSPFv3またはBGPを有効にしてください")
    return {
        "enabled": enabled,
        "ospf6": ospf6,
        "bgp": bgp,
    }


def _normalize_ospf6(raw: dict, require_enabled: bool) -> dict:
    enabled = bool(raw.get("enabled", False))
    router_id = str(raw.get("router_id", "")).strip()
    if router_id:
        router_id = _validate_router_id(router_id)
    interfaces = []
    for item in raw.get("interfaces", []) or []:
        if not isinstance(item, dict):
            continue
        iface = str(item.get("interface", "")).strip()
        if not iface:
            continue
        interfaces.append({
            "interface": validate_interface(iface),
            "area": _validate_ospf_area(str(item.get("area", "0.0.0.0")).strip() or "0.0.0.0"),
        })
    if enabled and require_enabled:
        if not router_id:
            raise ValidationError("OSPFv3ルータIDが必要です")
        if not interfaces:
            raise ValidationError("OSPFv3ではインターフェースを1つ以上指定してください")
    return {
        "enabled": enabled,
        "router_id": router_id,
        "interfaces": interfaces,
    }


def _normalize_bgp(raw: dict, require_enabled: bool) -> dict:
    enabled = bool(raw.get("enabled", False))
    local_as = str(raw.get("local_as", "")).strip()
    if local_as:
        local_as = str(_validate_asn(local_as, "BGP local AS"))
    router_id = str(raw.get("router_id", "")).strip()
    if router_id:
        router_id = _validate_router_id(router_id)
    neighbors = []
    for item in raw.get("neighbors", []) or []:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address", "")).strip()
        if not address:
            continue
        description = str(item.get("description", "")).strip()
        if description and not DESCRIPTION_RE.match(description):
            raise ValidationError("BGPネイバー説明に使用できない文字が含まれています")
        iface = str(item.get("interface", "")).strip()
        neighbors.append({
            "address": _validate_bgp_neighbor(address),
            "remote_as": _validate_asn(str(item.get("remote_as", "")).strip(), "BGP remote AS"),
            "interface": validate_interface(iface) if iface else "",
            "description": description,
        })
    networks = []
    for value in raw.get("networks", []) or []:
        text = str(value).strip()
        if text:
            networks.append(_validate_ipv6_prefix(text, require_64=False))
    if enabled and require_enabled:
        if not local_as:
            raise ValidationError("BGPローカルASが必要です")
        if not neighbors:
            raise ValidationError("BGPではIPv6ネイバーを1つ以上指定してください")
    return {
        "enabled": enabled,
        "local_as": local_as,
        "router_id": router_id,
        "neighbors": neighbors,
        "networks": networks,
    }


def _apply_runtime(settings: dict) -> dict:
    changed: list[str] = []
    errors: list[str] = []
    if not settings["enabled"]:
        _disable_runtime(settings, changed, errors)
        return {"ok": not errors, "changed": changed, "errors": errors, "settings": settings}

    _write_sysctl(enabled=True, changed=changed, errors=errors)
    _apply_wan(settings["wan"], changed, errors)
    _apply_lan_addresses(settings["advertisements"], changed, errors)
    _write_radvd(settings["advertisements"], changed, errors)
    _write_dnsmasq_ipv6(settings["advertisements"], changed, errors)
    _apply_firewall(settings, changed, errors)
    _apply_transition(settings["transition"], changed, errors)
    _apply_dynamic_routing(settings["routing"], changed, errors)

    return {
        "ok": not errors,
        "changed": changed,
        "errors": errors,
        "settings": settings,
        "services": {
            "radvd": _service_state(RADVD_UNIT),
            "dnsmasq": _service_state(DNSMASQ_UNIT),
            "transition": _service_state(TRANSITION_UNIT_NAME),
            "frr": _service_state(FRR_UNIT),
        },
    }


def _disable_runtime(settings: dict, changed: list[str], errors: list[str]) -> None:
    _remove_transition(changed, errors, [settings.get("transition", {}).get("name", "")])
    _disable_dynamic_routing(changed, errors)
    _collect(["systemctl", "disable", "--now", RADVD_UNIT], changed, errors, ignore=True)
    if DNSMASQ_IPV6_CONF.exists():
        DNSMASQ_IPV6_CONF.unlink(missing_ok=True)
        changed.append(str(DNSMASQ_IPV6_CONF))
        _collect(["systemctl", "restart", DNSMASQ_UNIT], changed, errors, ignore=True)
    _write_sysctl(enabled=False, changed=changed, errors=errors)


def _write_sysctl(enabled: bool, changed: list[str], errors: list[str]) -> None:
    if enabled:
        text = "\n".join([
            MANAGED_HEADER,
            "net.ipv6.conf.all.disable_ipv6 = 0",
            "net.ipv6.conf.default.disable_ipv6 = 0",
            "net.ipv6.conf.all.forwarding = 1",
            "net.ipv6.conf.default.forwarding = 1",
            "",
        ])
    else:
        text = "\n".join([
            MANAGED_HEADER,
            "net.ipv6.conf.all.forwarding = 0",
            "net.ipv6.conf.default.forwarding = 0",
            "",
        ])
    SYSCTL_CONF.write_text(text, encoding="utf-8")
    os.chmod(SYSCTL_CONF, 0o644)
    changed.append(str(SYSCTL_CONF))
    _collect(["sysctl", "--system"], changed, errors, ignore=True)


def _apply_wan(wan: dict, changed: list[str], errors: list[str]) -> None:
    iface = wan.get("interface") or ""
    method = wan.get("method") or "disabled"
    if not iface or method == "disabled":
        return
    conn = _connection_for_interface(iface)
    if not conn:
        errors.append(f"WAN {iface} のNetworkManager接続が見つかりません")
        return
    if method == "slaac":
        args = ["nmcli", "connection", "modify", conn, "ipv6.method", "auto", "ipv6.never-default", "no"]
    elif method == "dhcpv6":
        args = ["nmcli", "connection", "modify", conn, "ipv6.method", "dhcp", "ipv6.never-default", "no"]
    else:
        args = [
            "nmcli", "connection", "modify", conn,
            "ipv6.method", "manual",
            "ipv6.addresses", wan["address"],
            "ipv6.gateway", wan["gateway"],
            "ipv6.never-default", "no",
        ]
    _collect(args, changed, errors)
    _collect(["sysctl", "-w", f"net.ipv6.conf.{iface}.accept_ra=2"], changed, errors, ignore=True)
    _reapply_connection(conn, iface, changed, errors)


def _apply_lan_addresses(advertisements: list[dict], changed: list[str], errors: list[str]) -> None:
    for adv in advertisements:
        iface = adv.get("interface") or ""
        router_address = adv.get("router_address") or ""
        if not iface or not router_address:
            continue
        conn = _connection_for_interface(iface)
        if not conn:
            errors.append(f"LAN {iface} のNetworkManager接続が見つかりません")
            continue
        _collect([
            "nmcli", "connection", "modify", conn,
            "ipv6.method", "manual",
            "ipv6.addresses", router_address,
            "ipv6.never-default", "yes",
        ], changed, errors)
        _collect(["sysctl", "-w", f"net.ipv6.conf.{iface}.accept_ra=0"], changed, errors, ignore=True)
        _reapply_connection(conn, iface, changed, errors)


def _write_radvd(advertisements: list[dict], changed: list[str], errors: list[str]) -> None:
    if not advertisements:
        _collect(["systemctl", "disable", "--now", RADVD_UNIT], changed, errors, ignore=True)
        return
    _backup_unmanaged(RADVD_CONF)
    lines = [MANAGED_HEADER, ""]
    for adv in advertisements:
        mode = adv["mode"]
        managed = "on" if mode == "managed" else "off"
        other = "on" if mode in {"stateless", "managed"} else "off"
        autonomous = "off" if mode == "managed" else "on"
        lines.extend([
            f"interface {adv['interface']} {{",
            "    AdvSendAdvert on;",
            "    MaxRtrAdvInterval 600;",
            f"    AdvManagedFlag {managed};",
            f"    AdvOtherConfigFlag {other};",
            f"    prefix {adv['prefix']} {{",
            "        AdvOnLink on;",
            f"        AdvAutonomous {autonomous};",
            f"        AdvValidLifetime {adv['valid_lifetime']};",
            f"        AdvPreferredLifetime {adv['preferred_lifetime']};",
            "    };",
        ])
        if adv.get("dns_servers"):
            lines.append(f"    RDNSS {' '.join(adv['dns_servers'])} {{ AdvRDNSSLifetime 1200; }};")
        if adv.get("domain"):
            lines.append(f"    DNSSL {adv['domain']} {{ AdvDNSSLLifetime 1200; }};")
        lines.extend(["};", ""])
    RADVD_CONF.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(RADVD_CONF, 0o644)
    changed.append(str(RADVD_CONF))
    _collect(["radvd", "-c", "-C", str(RADVD_CONF)], changed, errors, ignore=True)
    _collect(["systemctl", "enable", "--now", RADVD_UNIT], changed, errors)
    _collect(["systemctl", "restart", RADVD_UNIT], changed, errors)


def _write_dnsmasq_ipv6(advertisements: list[dict], changed: list[str], errors: list[str]) -> None:
    enabled_adv = [a for a in advertisements if a["mode"] in {"stateless", "managed"}]
    if not enabled_adv:
        if DNSMASQ_IPV6_CONF.exists():
            DNSMASQ_IPV6_CONF.unlink(missing_ok=True)
            changed.append(str(DNSMASQ_IPV6_CONF))
            _collect(["systemctl", "restart", DNSMASQ_UNIT], changed, errors, ignore=True)
        return
    lines = [MANAGED_HEADER, "bind-dynamic", ""]
    for adv in enabled_adv:
        iface = adv["interface"]
        tag = f"synca6-{re.sub(r'[^A-Za-z0-9_-]', '-', iface)}"
        lines.append(f"interface={iface}")
        if adv["mode"] == "stateless":
            lines.append(f"dhcp-range=set:{tag},::,static,64,{adv['lease']}")
        elif adv["mode"] == "managed":
            start = adv.get("dhcp_start") or _prefix_host(adv["prefix"], 0x100)
            end = adv.get("dhcp_end") or _prefix_host(adv["prefix"], 0x1ff)
            lines.append(f"dhcp-range=set:{tag},{start},{end},64,{adv['lease']}")
        if adv.get("dns_servers"):
            dns = ",".join(f"[{addr}]" for addr in adv["dns_servers"])
            lines.append(f"dhcp-option=tag:{tag},option6:dns-server,{dns}")
        if adv.get("domain"):
            lines.append(f"dhcp-option=tag:{tag},option6:domain-search,{adv['domain']}")
        lines.append("")
    DNSMASQ_IPV6_CONF.parent.mkdir(parents=True, exist_ok=True)
    DNSMASQ_IPV6_CONF.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(DNSMASQ_IPV6_CONF, 0o644)
    changed.append(str(DNSMASQ_IPV6_CONF))
    _collect(["dnsmasq", "--test"], changed, errors)
    _collect(["systemctl", "enable", "--now", DNSMASQ_UNIT], changed, errors, ignore=True)
    _collect(["systemctl", "restart", DNSMASQ_UNIT], changed, errors)


def _apply_firewall(settings: dict, changed: list[str], errors: list[str]) -> None:
    if not _firewalld_active():
        return
    for adv in settings.get("advertisements", []):
        iface = adv.get("interface") or ""
        zone = _zone_for_interface(iface) or "trusted"
        if settings["firewall"].get("allow_icmpv6", True):
            _collect(["firewall-cmd", "--permanent", "--zone", zone, "--add-protocol", "ipv6-icmp"], changed, errors, ignore=True)
        if settings["firewall"].get("allow_dhcpv6", True) and adv.get("mode") in {"stateless", "managed"}:
            _collect(["firewall-cmd", "--permanent", "--zone", zone, "--add-port", "547/udp"], changed, errors, ignore=True)
    _collect(["firewall-cmd", "--reload"], changed, errors, ignore=True)


def _apply_transition(transition: dict, changed: list[str], errors: list[str]) -> None:
    if transition["mode"] == "disabled":
        _remove_transition(changed, errors, [transition.get("name", "")])
        return
    _write_transition_script(transition)
    _write_transition_unit(transition)
    changed.extend([str(TRANSITION_SCRIPT), str(TRANSITION_UNIT)])
    _collect(["systemctl", "daemon-reload"], changed, errors)
    _collect(["systemctl", "enable", "--now", TRANSITION_UNIT_NAME], changed, errors)
    _collect(["systemctl", "restart", TRANSITION_UNIT_NAME], changed, errors)


def _remove_transition(changed: list[str], errors: list[str], extra_names: Optional[list[str]] = None) -> None:
    _collect(["systemctl", "disable", "--now", TRANSITION_UNIT_NAME], changed, errors, ignore=True)
    names = [name for name in (extra_names or []) if name]
    names.extend(["synca6", "tun6to4", "sit1"])
    for name in dict.fromkeys(names):
        _collect(["ip", "tunnel", "del", name], changed, errors, ignore=True)


def _write_transition_script(transition: dict) -> None:
    mode = shlex.quote(transition["mode"])
    name = shlex.quote(transition["name"])
    local = shlex.quote(transition.get("local_ipv4") or "auto")
    remote = shlex.quote(transition.get("remote_ipv4") or "")
    tunnel_address = shlex.quote(transition.get("tunnel_address") or "")
    routed_prefix = shlex.quote(transition.get("routed_prefix") or "")
    default_route = "1" if transition.get("default_route", True) else "0"
    text = f"""#!/usr/bin/env bash
set -euo pipefail
MODE={mode}
NAME={name}
LOCAL_IPV4={local}
REMOTE_IPV4={remote}
TUNNEL_ADDRESS={tunnel_address}
ROUTED_PREFIX={routed_prefix}
DEFAULT_ROUTE={default_route}

auto_ipv4() {{
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{{for (i=1;i<=NF;i++) if ($i=="src") {{print $(i+1); exit}}}}'
}}

hex_6to4() {{
  local ip="$1"
  IFS=. read -r a b c d <<<"$ip"
  printf '2002:%02x%02x:%02x%02x::1/16' "$a" "$b" "$c" "$d"
}}

cleanup() {{
  ip tunnel del "$NAME" 2>/dev/null || true
  ip tunnel del tun6to4 2>/dev/null || true
}}

cleanup
if [[ "$MODE" == "disabled" ]]; then
  exit 0
fi
if [[ "$LOCAL_IPV4" == "auto" ]]; then
  LOCAL_IPV4="$(auto_ipv4)"
fi
if [[ -z "$LOCAL_IPV4" ]]; then
  echo "ローカルIPv4アドレスが見つかりません" >&2
  exit 1
fi
if [[ "$MODE" == "6to4" ]]; then
  ip tunnel add "$NAME" mode sit remote any local "$LOCAL_IPV4" ttl 64
  ip link set "$NAME" up
  ip -6 addr add "$(hex_6to4 "$LOCAL_IPV4")" dev "$NAME"
  if [[ "$DEFAULT_ROUTE" == "1" ]]; then
    ip -6 route replace 2000::/3 via ::192.88.99.1 dev "$NAME" metric 2048
  fi
elif [[ "$MODE" == "6in4" ]]; then
  ip tunnel add "$NAME" mode sit remote "$REMOTE_IPV4" local "$LOCAL_IPV4" ttl 255
  ip link set "$NAME" up
  ip -6 addr add "$TUNNEL_ADDRESS" dev "$NAME"
  if [[ -n "$ROUTED_PREFIX" ]]; then
    ip -6 route replace "$ROUTED_PREFIX" dev "$NAME" metric 2048 || true
  fi
  if [[ "$DEFAULT_ROUTE" == "1" ]]; then
    ip -6 route replace ::/0 dev "$NAME" metric 2048
  fi
fi
"""
    TRANSITION_SCRIPT.write_text(text, encoding="utf-8")
    os.chmod(TRANSITION_SCRIPT, 0o755)


def _write_transition_unit(transition: dict) -> None:
    name = transition.get("name") or "synca6"
    text = f"""[Unit]
Description=SyncA UTM IPv6 transition tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={TRANSITION_SCRIPT}
ExecStop=-/usr/sbin/ip tunnel del {name}

[Install]
WantedBy=multi-user.target
"""
    TRANSITION_UNIT.write_text(text, encoding="utf-8")
    os.chmod(TRANSITION_UNIT, 0o644)


def _apply_dynamic_routing(routing: dict, changed: list[str], errors: list[str]) -> None:
    ospf_enabled = routing.get("ospf6", {}).get("enabled", False)
    bgp_enabled = routing.get("bgp", {}).get("enabled", False)
    if not routing.get("enabled") or not (ospf_enabled or bgp_enabled):
        _disable_dynamic_routing(changed, errors)
        return
    _write_frr_daemons(routing)
    _write_frr_conf(routing)
    changed.extend([str(FRR_DAEMONS), str(FRR_CONF)])
    if _has_command("vtysh"):
        _collect(["vtysh", "-C", "-f", str(FRR_CONF)], changed, errors, ignore=True)
    _collect(["systemctl", "enable", "--now", FRR_UNIT], changed, errors)
    _collect(["systemctl", "restart", FRR_UNIT], changed, errors)


def _disable_dynamic_routing(changed: list[str], errors: list[str]) -> None:
    if _is_managed_file(FRR_CONF) or _is_managed_file(FRR_DAEMONS):
        _collect(["systemctl", "disable", "--now", FRR_UNIT], changed, errors, ignore=True)


def _write_frr_daemons(routing: dict) -> None:
    ospf_enabled = "yes" if routing.get("ospf6", {}).get("enabled") else "no"
    bgp_enabled = "yes" if routing.get("bgp", {}).get("enabled") else "no"
    lines = [
        MANAGED_HEADER,
        "zebra=yes",
        f"bgpd={bgp_enabled}",
        "ospfd=no",
        f"ospf6d={ospf_enabled}",
        "ripd=no",
        "ripngd=no",
        "isisd=no",
        "pimd=no",
        "pim6d=no",
        "ldpd=no",
        "nhrpd=no",
        "eigrpd=no",
        "babeld=no",
        "sharpd=no",
        "pbrd=no",
        "bfdd=no",
        "fabricd=no",
        "vrrpd=no",
        "pathd=no",
        "vtysh_enable=yes",
        "zebra_options=\"  -A 127.0.0.1 -s 90000000\"",
        "bgpd_options=\"   -A 127.0.0.1\"",
        "ospf6d_options=\" -A 127.0.0.1\"",
        "",
    ]
    _backup_unmanaged(FRR_DAEMONS)
    FRR_DAEMONS.parent.mkdir(parents=True, exist_ok=True)
    FRR_DAEMONS.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(FRR_DAEMONS, 0o644)


def _write_frr_conf(routing: dict) -> None:
    lines = [
        FRR_MANAGED_HEADER,
        "frr defaults traditional",
        "hostname synca-utm",
        "log syslog informational",
        "service integrated-vtysh-config",
        "!",
    ]
    ospf6 = routing.get("ospf6", {})
    if ospf6.get("enabled"):
        lines.extend([
            "router ospf6",
            f" ospf6 router-id {ospf6['router_id']}",
        ])
        for item in ospf6.get("interfaces", []):
            lines.append(f" interface {item['interface']} area {item['area']}")
        lines.append("!")
    bgp = routing.get("bgp", {})
    if bgp.get("enabled"):
        lines.extend([
            f"router bgp {bgp['local_as']}",
            " no bgp default ipv4-unicast",
        ])
        if bgp.get("router_id"):
            lines.append(f" bgp router-id {bgp['router_id']}")
        for neighbor in bgp.get("neighbors", []):
            peer = neighbor["address"]
            lines.append(f" neighbor {peer} remote-as {neighbor['remote_as']}")
            if neighbor.get("interface"):
                lines.append(f" neighbor {peer} interface {neighbor['interface']}")
            if neighbor.get("description"):
                lines.append(f" neighbor {peer} description {neighbor['description']}")
        lines.append(" address-family ipv6 unicast")
        for neighbor in bgp.get("neighbors", []):
            lines.append(f"  neighbor {neighbor['address']} activate")
        for prefix in bgp.get("networks", []):
            lines.append(f"  network {prefix}")
        lines.extend([" exit-address-family", "!"])
    _backup_unmanaged(FRR_CONF)
    FRR_CONF.parent.mkdir(parents=True, exist_ok=True)
    FRR_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(FRR_CONF, 0o640)


def _connection_for_interface(iface: str) -> str:
    rows = _nmcli_terse(["-f", "NAME,DEVICE", "connection", "show"])
    for row in rows:
        if len(row) >= 2 and row[1] == iface:
            return row[0]
    rows = _nmcli_terse(["-f", "NAME", "connection", "show"])
    for row in rows:
        if not row:
            continue
        name = row[0]
        res = run(["nmcli", "-g", "connection.interface-name", "connection", "show", name])
        if res.ok and res.stdout.strip() == iface:
            return name
    return ""


def _reapply_connection(conn: str, iface: str, changed: list[str], errors: list[str]) -> None:
    res = sudo_run(["nmcli", "device", "reapply", iface], timeout=30)
    if res.ok:
        changed.append(f"nmcli device reapply {iface}")
        return
    _collect(["nmcli", "connection", "up", conn], changed, errors, ignore=True)


def _interface_rows() -> list[dict]:
    res = run(["ip", "-j", "addr", "show"])
    if not res.ok:
        return []
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    rows: list[dict] = []
    wan = set(_default_wan_interfaces())
    for entry in data:
        name = entry.get("ifname", "")
        if not name or name == "lo":
            continue
        rows.append({
            "name": name,
            "is_wan": name in wan,
            "ipv4": [a.get("local") for a in entry.get("addr_info", []) if a.get("family") == "inet"],
            "ipv6": [f"{a.get('local')}/{a.get('prefixlen')}" for a in entry.get("addr_info", []) if a.get("family") == "inet6"],
            "state": entry.get("operstate", ""),
        })
    return rows


def _default_wan_interfaces() -> list[str]:
    res = run(["ip", "-j", "route", "show", "default"])
    if not res.ok:
        return []
    try:
        routes = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    return sorted({r.get("dev", "") for r in routes if r.get("dev")})


def _default_lan_interfaces() -> list[str]:
    wan = set(_default_wan_interfaces())
    return [row["name"] for row in _interface_rows() if row["name"] not in wan and not row["name"].startswith("wg")]


def _tool_status() -> dict:
    return {
        "radvd": _has_command("radvd"),
        "dnsmasq": _has_command("dnsmasq"),
        "nmcli": _has_command("nmcli"),
        "ip": _has_command("ip"),
        "firewall_cmd": _has_command("firewall-cmd"),
        "vtysh": _has_command("vtysh"),
    }


def _sysctl_status() -> dict:
    keys = [
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
    ]
    out = {}
    for key in keys:
        res = run(["sysctl", "-n", key])
        out[key] = res.stdout.strip() if res.ok else None
    return out


def _transition_status() -> dict:
    res = run(["ip", "-d", "link", "show", "type", "sit"])
    return {"sit_links": res.stdout if res.ok else "", "script_exists": TRANSITION_SCRIPT.exists()}


def _service_state(unit: str) -> dict:
    active = run(["systemctl", "is-active", unit], timeout=10)
    enabled = run(["systemctl", "is-enabled", unit], timeout=10)
    return {
        "unit": unit,
        "active": active.stdout.strip() if active.stdout.strip() else "unknown",
        "enabled": enabled.stdout.strip() if enabled.stdout.strip() else "unknown",
    }


def _detected_ipv6_prefixes() -> list[str]:
    prefixes: list[str] = []
    res = run(["ip", "-6", "route", "show"])
    if not res.ok:
        return prefixes
    for line in res.stdout.splitlines():
        token = line.split()[0] if line.split() else ""
        try:
            net = ipaddress.IPv6Network(token, strict=False)
        except ValueError:
            continue
        if net.prefixlen <= 64 and not net.is_link_local and str(net) not in prefixes:
            prefixes.append(str(net))
    return prefixes


def _zone_for_interface(iface: str) -> str:
    res = run(["firewall-cmd", "--get-zone-of-interface", iface])
    return res.stdout.strip() if res.ok else ""


def _firewalld_active() -> bool:
    res = run(["systemctl", "is-active", "firewalld"], timeout=10)
    return res.ok and res.stdout.strip() == "active"


def _backup_unmanaged(path: Path) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if text.startswith(MANAGED_HEADER):
        return
    backup = path.with_name(f"{path.name}.synca-pre-ipv6.bak")
    if not backup.exists():
        backup.write_text(text, encoding="utf-8")


def _is_managed_file(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return text.startswith(MANAGED_HEADER) or text.startswith(FRR_MANAGED_HEADER)


def _collect(cmd: list[str], changed: list[str], errors: list[str], ignore: bool = False) -> None:
    res = sudo_run(cmd, timeout=60)
    display = " ".join(shlex.quote(part) for part in cmd)
    if res.ok:
        changed.append(display)
    elif not ignore:
        errors.append(f"{display}: {(res.stderr or res.stdout).strip()}")


def _nmcli_terse(args: list[str]) -> list[list[str]]:
    res = run(["nmcli", "-t", "-e", "no", *args])
    if not res.ok:
        return []
    return [[part for part in line.split(":")] for line in res.stdout.splitlines() if line.strip()]


def _has_command(name: str) -> bool:
    res = run(["bash", "-lc", f"command -v {shlex.quote(name)} >/dev/null 2>&1"])
    return res.ok


def _deep_merge(base: dict, overlay: dict) -> dict:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _ipv6_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = value
    else:
        raw = [item.strip() for item in str(value or "").split(",")]
    return [_validate_ipv6_address(str(item).strip(), "IPv6アドレス") for item in raw if str(item).strip()]


def _validate_ipv6_address(value: str, label: str) -> str:
    try:
        return str(ipaddress.IPv6Address(value))
    except ValueError as e:
        raise ValidationError(f"{label}が不正です: {value!r}") from e


def _validate_ipv6_interface(value: str, label: str) -> str:
    try:
        return str(ipaddress.IPv6Interface(value))
    except ValueError as e:
        raise ValidationError(f"{label}のIPv6インターフェースアドレスが不正です: {value!r}") from e


def _validate_ipv6_prefix(value: str, require_64: bool) -> str:
    try:
        net = ipaddress.IPv6Network(value, strict=False)
    except ValueError as e:
        raise ValidationError(f"IPv6プレフィックスが不正です: {value!r}") from e
    if require_64 and net.prefixlen != 64:
        raise ValidationError("LANプレフィックス通知は/64で指定してください")
    return str(net)


def _validate_ipv4(value: str, label: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as e:
        raise ValidationError(f"{label}のIPv4アドレスが不正です: {value!r}") from e


def _validate_router_id(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as e:
        raise ValidationError(f"ルーターIDはIPv4アドレス形式で指定してください: {value!r}") from e


def _validate_ospf_area(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as e:
        raise ValidationError(f"OSPFエリアはドット付き10進表記で指定してください: {value!r}") from e


def _validate_asn(value: str, label: str) -> int:
    try:
        asn = int(value)
    except ValueError as e:
        raise ValidationError(f"{label}は数値で指定してください") from e
    if not 1 <= asn <= 4294967295:
        raise ValidationError(f"{label}は1から4294967295の範囲で指定してください")
    return asn


def _validate_bgp_neighbor(value: str) -> str:
    host = value.split("%", 1)[0]
    try:
        ipaddress.IPv6Address(host)
    except ValueError as e:
        raise ValidationError(f"BGPネイバーはIPv6アドレスで指定してください: {value!r}") from e
    if "%" in value:
        host_part, iface = value.split("%", 1)
        if not iface:
            raise ValidationError("BGPリンクローカルネイバーのスコープが空です")
        validate_interface(iface)
        return f"{host_part}%{iface}"
    return str(ipaddress.IPv6Address(host))


def _validate_lifetime(value: Any, label: str) -> int:
    text = str(value)
    if not LIFETIME_RE.match(text):
        raise ValidationError(f"{label}は秒数で指定してください")
    return int(text)


def _validate_or_default_router_address(value: str, prefix: str) -> str:
    net = ipaddress.IPv6Network(prefix, strict=False)
    if value:
        iface = ipaddress.IPv6Interface(value)
        if iface.ip not in net:
            raise ValidationError("ルーターアドレスは通知プレフィックスの範囲内で指定してください")
        return str(iface)
    return f"{net.network_address + 1}/{net.prefixlen}"


def _prefix_host(prefix: str, host_id: int) -> str:
    net = ipaddress.IPv6Network(prefix, strict=False)
    return str(net.network_address + host_id)


def _replace_prefix_address(value: str, old_net: ipaddress.IPv6Network, new_net: ipaddress.IPv6Network, host_only: bool = False) -> str:
    if not value:
        return ""
    try:
        if host_only:
            ip = ipaddress.IPv6Address(value)
            suffix = int(ip) - int(old_net.network_address)
            return str(new_net.network_address + suffix)
        iface = ipaddress.IPv6Interface(value)
        suffix = int(iface.ip) - int(old_net.network_address)
        return f"{new_net.network_address + suffix}/{new_net.prefixlen}"
    except ValueError:
        return value
