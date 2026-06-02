"""payload/server-gui/server_gui/modules/sophos_import.py

Sophos SG UTM XML import helper for SyncA UTM.

The module intentionally separates parsing from applying. A Sophos export can
change firewall, NAT, VPN, and reverse-proxy behavior; the first safe step is a
structured import plan that operators can inspect before later applying it to
SyncA UTM subsystems.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import logging
import re
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..dnsmasq_apply import MODULE_NAME as DNSMASQ_MODULE, apply as apply_dnsmasq, default as dnsmasq_default
from .ipsec import MODULE_NAME as IPSEC_MODULE, _apply as apply_ipsec, _default as ipsec_default
from .nginx_proxy import MODULE_NAME as NGINX_MODULE, _apply_all as apply_nginx, _default as nginx_default

bp = Blueprint("sophos_import", __name__, url_prefix="/sophos-import")
logger = logging.getLogger(__name__)

STORE_DIR = Path("/var/lib/server-gui/sophos-imports")
MAX_XML_BYTES = 16 * 1024 * 1024
IMPORT_MODULE = "sophos_import"
SUPPORTED_DESCR = {
    "interface": "network",
    "PPPoE DSL interface": "network",
    "interface address": "network",
    "additional interface address": "network",
    "static route": "network",
    "firewall rule": "firewall",
    "NAT rule": "firewall",
    "masquerading rule": "firewall",
    "DNS host": "dns",
    "DNS group": "dns",
    "DHCPv4 server": "dhcp",
    "DHCPv4 option": "dhcp",
    "real webserver": "nginx",
    "virtual webserver": "nginx",
    "site path route": "nginx",
    "IPsec site-to-site connection": "ipsec",
    "IPsec remote gateway": "ipsec",
    "IPsec policy": "ipsec",
    "preshared key": "ipsec",
    "X509 certificate with private key": "certs",
    "RSA private key": "certs",
    "private key": "certs",
}
REMOTE_ACCESS_KEYWORDS = (
    "remote access",
    "SSL VPN remote access",
    "L2TP over IPsec remote access",
    "PPTP remote access",
)
SECRET_RE = re.compile(r"(password|preshared|pre-shared|private key|certificate|secret|psk)", re.I)
PLAN_NAME_RE = re.compile(r"^sophos-import-plan-\d{8}-\d{6}\.json$")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def page():
    return render_template("sophos_import.html", active_tab="sophos_import")


@bp.route("/api/preview", methods=["POST"])
@login_required
@csrf_protect
def preview():
    xml_bytes = _read_upload()
    if isinstance(xml_bytes, tuple):
        return xml_bytes
    try:
        logger.info("sophos import preview started: %d bytes", len(xml_bytes))
        plan = _build_plan(xml_bytes)
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse failed: {e}"}), 400
    logger.info("sophos import preview completed: %s", plan.get("summary", {}))
    return jsonify(plan)


@bp.route("/api/save-plan", methods=["POST"])
@login_required
@csrf_protect
def save_plan():
    xml_bytes = _read_upload()
    if isinstance(xml_bytes, tuple):
        return xml_bytes
    try:
        logger.info("sophos import save-plan started: %d bytes", len(xml_bytes))
        plan = _build_plan(xml_bytes)
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse failed: {e}"}), 400
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = STORE_DIR / f"sophos-import-plan-{ts}.json"
    path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    path.chmod(0o600)
    logger.info("sophos import plan saved: %s", path)
    return jsonify({"ok": True, "path": str(path), "summary": plan.get("summary", {})})


@bp.route("/api/plans")
@login_required
def list_plans():
    plans = []
    if STORE_DIR.exists():
        for path in sorted(STORE_DIR.glob("sophos-import-plan-*.json"), reverse=True):
            if not PLAN_NAME_RE.match(path.name):
                continue
            try:
                stat = path.stat()
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            plans.append({
                "name": path.name,
                "path": str(path),
                "size": stat.st_size,
                "mtime": _dt.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "format": data.get("format", {}),
                "summary": data.get("summary", {}),
            })
    return jsonify({"plans": plans})


@bp.route("/api/plans/<name>")
@login_required
def get_plan(name: str):
    if not PLAN_NAME_RE.match(name):
        return jsonify({"error": "invalid plan name"}), 400
    path = STORE_DIR / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return jsonify({"error": "plan not found"}), 404
    except json.JSONDecodeError as e:
        return jsonify({"error": f"plan JSON parse failed: {e}"}), 500
    return jsonify(data)


@bp.route("/api/import-upload", methods=["POST"])
@login_required
@csrf_protect
def import_upload():
    xml_bytes = _read_upload()
    if isinstance(xml_bytes, tuple):
        return xml_bytes
    apply_system = _bool_form("apply_system")
    replace = _bool_form("replace")
    try:
        logger.info("sophos import apply-upload started: %d bytes", len(xml_bytes))
        plan = _build_plan(xml_bytes)
        result = _import_plan(plan, source_name=_upload_name(), replace=replace, apply_system=apply_system)
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse failed: {e}"}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    logger.info("sophos import apply-upload completed: %s", result.get("summary", {}))
    return jsonify(result)


@bp.route("/api/plans/<name>/import", methods=["POST"])
@login_required
@csrf_protect
def import_saved_plan(name: str):
    if not PLAN_NAME_RE.match(name):
        return jsonify({"error": "invalid plan name"}), 400
    payload = request.get_json(force=True, silent=True) or {}
    path = STORE_DIR / name
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
        result = _import_plan(
            plan,
            source_name=name,
            replace=bool(payload.get("replace", False)),
            apply_system=bool(payload.get("apply_system", False)),
        )
    except FileNotFoundError:
        return jsonify({"error": "plan not found"}), 404
    except json.JSONDecodeError as e:
        return jsonify({"error": f"plan JSON parse failed: {e}"}), 500
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(result)


def _read_upload():
    f = request.files.get("xml")
    if f is None:
        return jsonify({"error": "xml file required"}), 400
    data = f.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        return jsonify({"error": "xml file too large"}), 413
    return data


def _upload_name() -> str:
    f = request.files.get("xml")
    return f.filename if f is not None else "upload.xml"


def _bool_form(name: str) -> bool:
    value = request.form.get(name, "")
    return str(value).lower() in {"1", "true", "yes", "on"}


def _build_plan(xml_bytes: bytes) -> dict:
    root = ET.fromstring(xml_bytes)
    header = root.find("header")
    nodes = root.find("nodes")
    objects = _collect_objects(root)
    object_index = _object_index(root)
    supported = []
    unsupported_counts: dict[str, int] = {}
    remote_access_count = 0
    secret_count = 0

    for obj in objects:
        descr = obj["descr"]
        if any(k.lower() in descr.lower() for k in REMOTE_ACCESS_KEYWORDS):
            remote_access_count += 1
            continue
        target = SUPPORTED_DESCR.get(descr)
        if target:
            item = dict(obj)
            item["target"] = target
            item["secrets"] = _secret_fields(obj)
            secret_count += len(item["secrets"])
            supported.append(item)
        else:
            unsupported_counts[descr] = unsupported_counts.get(descr, 0) + 1

    supported_counts: dict[str, int] = {}
    for item in supported:
        supported_counts[item["target"]] = supported_counts.get(item["target"], 0) + 1

    return {
        "format": _header_summary(header),
        "top_sections": [child.tag for child in list(nodes or [])],
        "summary": {
            "supported_items": len(supported),
            "supported_by_target": supported_counts,
            "unsupported_kinds": len(unsupported_counts),
            "remote_access_ignored": remote_access_count,
            "secret_fields_detected": secret_count,
        },
        "supported": supported[:500],
        "ui_preview": _build_ui_preview(object_index),
        "object_index": object_index,
        "unsupported_counts": dict(sorted(unsupported_counts.items())),
        "notes": [
            "リモートアクセス設定は意図的に除外しています。",
            "Web proxy / Webserver Protection は Nginx リバースプロキシ移行対象として扱います。",
            "この画面では取込前の確認用プランを作成します。実適用は各機能ごとの変換ルール確認後に行います。",
        ],
    }


def _import_plan(plan: dict, source_name: str, replace: bool = False, apply_system: bool = False) -> dict:
    """Import converted Sophos items into SyncA GUI-managed JSON stores."""
    source_id = _source_id(source_name)
    index = plan.get("object_index") or {}
    converted = _convert_plan(index, source_id)
    config_dir = current_app.config["CONFIG_DIR"]
    store = ConfigStore(config_dir)

    dnsmasq_data = converted["dnsmasq"]
    nginx_data = converted["nginx"]
    ipsec_data = converted["ipsec"]
    appliance_data = converted["appliance"]

    dnsmasq_result = _merge_dnsmasq(store, dnsmasq_data, source_id, replace)
    nginx_result = _merge_nginx(store, nginx_data, source_id, replace)
    ipsec_result = _merge_ipsec(store, ipsec_data, source_id, replace)
    appliance_result = _merge_appliance(store, appliance_data, source_id, replace)

    applied: dict[str, object] = {"requested": apply_system}
    if apply_system:
        try:
            apply_dnsmasq(config_dir)
            apply_nginx(store.load(NGINX_MODULE, nginx_default()))
            apply_ipsec(store.load(IPSEC_MODULE, ipsec_default()).get("connections", []))
            applied["ok"] = True
        except RuntimeError as e:
            applied["ok"] = False
            applied["error"] = str(e)
            raise

    summary = {
        "dns_hosts": dnsmasq_result["dns_hosts"],
        "dhcp_ranges": dnsmasq_result["dhcp_ranges"],
        "dhcp_options": dnsmasq_result["dhcp_options"],
        "nginx_backends": nginx_result["backends"],
        "nginx_vhosts": nginx_result["vhosts"],
        "ipsec_connections": ipsec_result["connections"],
        "static_interfaces": appliance_result["static_interfaces"],
        "pppoe_profiles": appliance_result["pppoe_profiles"],
        "pppoe_alias_addresses": sum(len(p.get("alias_addresses", [])) for p in appliance_data["pppoe_profiles"]),
        "static_routes": appliance_result["static_routes"],
        "nat_forward_ports": appliance_result["nat_forward_ports"],
        "masquerade_rules": appliance_result["masquerade_rules"],
        "skipped": converted["skipped"],
    }
    return {
        "ok": True,
        "source": source_name,
        "source_id": source_id,
        "replace": replace,
        "apply_system": applied,
        "summary": summary,
        "warnings": converted["warnings"],
    }


def _convert_plan(index: dict[str, dict], source_id: str) -> dict:
    return {
        "dnsmasq": _convert_dnsmasq(index, source_id),
        "nginx": _convert_nginx(index, source_id),
        "ipsec": _convert_ipsec(index, source_id),
        "appliance": _convert_appliance(index, source_id),
        "warnings": _conversion_warnings(index),
        "skipped": _skipped_counts(index),
    }


def _convert_dnsmasq(index: dict[str, dict], source_id: str) -> dict:
    hosts: list[dict] = []
    ranges: list[dict] = []
    options: list[dict] = []
    seen_hosts: set[tuple[str, str]] = set()
    seen_options: set[tuple[str, str, str]] = set()

    for ref, obj in sorted(index.items()):
        fields = obj.get("fields", {})
        if obj.get("descr") == "host":
            ip = fields.get("IPv4 address", "").strip()
            names = _hostnames(fields)
            for domain in names:
                if not _valid_ipv4(ip) or not _valid_hostname_like(domain):
                    continue
                key = (domain, ip)
                if key in seen_hosts:
                    continue
                seen_hosts.add(key)
                hosts.append({
                    "id": uuid.uuid4().hex,
                    "domain": domain,
                    "ip": ip,
                    "origin": _origin(source_id, ref),
                    "sophos_name": fields.get("name", ""),
                })
        elif obj.get("descr") == "DHCPv4 server" and fields.get("status switch") == "1":
            ranges.append({
                "id": uuid.uuid4().hex,
                "interface": None,
                "start": fields.get("range_start", "").strip(),
                "end": fields.get("range_end", "").strip(),
                "netmask": _prefix_to_netmask(fields.get("netmask", "")),
                "lease": _lease_seconds(fields.get("lease time", "")),
                "origin": _origin(source_id, ref),
                "sophos_interface": _name(index, fields.get("interface", "")),
                "sophos_gateway": fields.get("default gateway address", ""),
                "sophos_dns": [v for v in [fields.get("first DNS server", ""), fields.get("second DNS server", "")] if _usable_ipv4(v)],
            })
            _add_option(options, seen_options, "3", fields.get("default gateway address", ""), source_id, ref)
            dns_values = ",".join(v for v in [fields.get("first DNS server", ""), fields.get("second DNS server", "")] if _usable_ipv4(v))
            _add_option(options, seen_options, "6", dns_values, source_id, ref)
            _add_option(options, seen_options, "15", fields.get("domain", ""), source_id, ref)
        elif obj.get("descr") == "DHCPv4 option" and fields.get("status switch") == "1":
            option = fields.get("code number", "").strip()
            if not option.isdigit() or int(option) <= 0:
                continue
            value = fields.get("text value") or fields.get("IPv4 address") or fields.get("hex value")
            _add_option(options, seen_options, option, value, source_id, ref)

    ranges = [r for r in ranges if _valid_ipv4(r["start"]) and _valid_ipv4(r["end"])]
    return {"dns": {"hosts": hosts}, "dhcp": {"ranges": ranges, "options": options}}


def _convert_nginx(index: dict[str, dict], source_id: str) -> dict:
    backends: list[dict] = []
    vhosts: list[dict] = []
    backend_by_ref: dict[str, dict] = {}

    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "real webserver":
            continue
        fields = obj.get("fields", {})
        if fields.get("status switch") != "1":
            continue
        host = _resolve_host(index, fields.get("host", "")).strip()
        if not host:
            continue
        backend = {
            "id": uuid.uuid4().hex,
            "name": _identifier(fields.get("name", ""), ref),
            "host": host,
            "port": _int_or_default(fields.get("port"), 80),
            "scheme": "https" if fields.get("SSL switch") == "1" else "http",
            "origin": _origin(source_id, ref),
            "sophos_name": fields.get("name", ""),
        }
        backend_by_ref[ref] = backend
        backends.append(backend)

    route_by_name: dict[str, dict] = {}
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "site path route":
            continue
        fields = obj.get("fields", {})
        if fields.get("status switch") == "1":
            route_by_name[fields.get("name", "")] = {"ref": ref, "fields": fields}

    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "virtual webserver":
            continue
        fields = obj.get("fields", {})
        if fields.get("status switch") != "1":
            continue
        domains = [d for d in re.split(r"[\s,]+", fields.get("domain list", "")) if _valid_hostname_like(d)]
        if not domains:
            continue
        route = route_by_name.get(fields.get("name", ""))
        backend_id = None
        path = "/"
        if route:
            route_fields = route["fields"]
            path = route_fields.get("path", "/") or "/"
            backend_refs = _split_refs(route_fields.get("real webserver list", ""))
            backend_id = backend_by_ref.get(backend_refs[0], {}).get("id") if backend_refs else None
        if backend_id is None:
            backend = next((b for b in backends if b.get("sophos_name") == fields.get("name", "")), None)
            backend_id = backend.get("id") if backend else None
        ssl_enabled = fields.get("type") == "https"
        cert_name = domains[0]
        vhosts.append({
            "id": uuid.uuid4().hex,
            "name": _identifier(fields.get("name", ""), ref),
            "enabled": True,
            "listens": [{
                "port": _int_or_default(fields.get("port"), 443 if ssl_enabled else 80),
                "ssl": ssl_enabled,
                "http2": ssl_enabled,
                "default_server": False,
            }],
            "server_names": domains,
            "ssl": {
                "cert_path": f"/etc/letsencrypt/live/{cert_name}/fullchain.pem",
                "key_path": f"/etc/letsencrypt/live/{cert_name}/privkey.pem",
                "ciphers": "PROFILE=SYSTEM",
                "protocols": ["TLSv1.2", "TLSv1.3"],
            } if ssl_enabled else None,
            "client_max_body_size": "10m",
            "set_real_ip_from": [],
            "access_log": None,
            "error_log": None,
            "locations": [{
                "path": path if path.startswith("/") else "/",
                "type": "proxy",
                "backend_id": backend_id,
                "websocket": False,
                "proxy_headers": {
                    "X-Real-IP": "$remote_addr",
                    "X-Forwarded-For": "$proxy_add_x_forwarded_for",
                    "X-Forwarded-Proto": "$scheme",
                    "X-Forwarded-Host": "$host",
                    "X-Forwarded-Port": "$server_port",
                    "Host": "$http_host" if fields.get("switch to preserve host header") == "1" else "$host",
                },
                "timeouts": {"connect": 60, "send": 60, "read": 60},
            }],
            "waf": {},
            "origin": _origin(source_id, ref),
            "sophos_name": fields.get("name", ""),
        })
    return {"backends": backends, "vhosts": vhosts}


def _convert_ipsec(index: dict[str, dict], source_id: str) -> dict:
    conns: list[dict] = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "IPsec site-to-site connection":
            continue
        fields = obj.get("fields", {})
        if fields.get("status switch") != "1":
            continue
        gateway = _fields(index, fields.get("remote gateway", ""))
        auth = _fields(index, gateway.get("peer authentication configuration", ""))
        policy = _fields(index, fields.get("policy", ""))
        psk = auth.get("preshared key", "")
        remote_addr = _resolve_host(index, gateway.get("remote host address", ""))
        local_ts = ",".join(v for v in [_resolve_network(index, r) for r in _split_refs(fields.get("network list", ""))] if _valid_cidr(v))
        remote_ts = ",".join(v for v in [_resolve_network(index, r) for r in _split_refs(gateway.get("remote subnet list", ""))] if _valid_cidr(v))
        if not psk or not remote_addr or not remote_ts:
            continue
        conn_name = _identifier(fields.get("name", ""), ref)
        conns.append({
            "id": uuid.uuid4().hex,
            "name": conn_name,
            "auth_type": "psk",
            "local_addrs": "%any",
            "remote_addrs": remote_addr,
            "version": 1,
            "proposals": _ike_proposal(policy),
            "local_id": "",
            "remote_id": _vpn_id(auth),
            "psk": psk,
            "server_cert": "",
            "server_key": "",
            "server_id": "",
            "ca_cert": "",
            "pool_addrs": "",
            "pool_dns": [],
            "eap_users": [],
            "children": [{
                "name": _identifier(f"{conn_name}_child", ref),
                "local_ts": local_ts,
                "remote_ts": remote_ts,
                "esp_proposals": _esp_proposal(policy),
                "start_action": "trap",
                "dpd_action": "restart",
            }],
            "origin": _origin(source_id, ref),
            "sophos_name": fields.get("name", ""),
        })
    return {"connections": conns}


def _convert_appliance(index: dict[str, dict], source_id: str) -> dict:
    static_interfaces: list[dict] = []
    pppoe_profiles: list[dict] = []
    static_routes: list[dict] = []
    nat_forward_ports: list[dict] = []
    masquerade_rules: list[dict] = []

    for ref, obj in sorted(index.items()):
        fields = obj.get("fields", {})
        descr = obj.get("descr")
        if _is_static_ip_interface(fields) and fields.get("status switch") == "1":
            primary_ref = fields.get("primary address", "")
            primary = _fields(index, primary_ref)
            static_interfaces.append({
                "id": uuid.uuid4().hex,
                "name": _identifier(fields.get("name", ""), ref),
                "sophos_name": fields.get("name", ""),
                "hardware_ref": fields.get("interface hardware", ""),
                "hardware_name": _name(index, fields.get("interface hardware", "")),
                "primary_address_ref": primary_ref,
                "address": primary.get("IPv4 address", ""),
                "netmask": _prefix_to_netmask(_ipv4_mask_value(primary)),
                "cidr": _address_cidr(index, primary_ref),
                "gateway": primary.get("IPv4 gateway", "") if primary.get("IPv4 default gateway switch") == "1" else "",
                "gateway_type": primary.get("gateway type", ""),
                "default_gateway": primary.get("IPv4 default gateway switch") == "1",
                "additional_addresses": [_resolve_address(index, r) for r in _split_refs(fields.get("additional addresses", ""))],
                "mtu": _int_or_default(fields.get("maximum transmission unit"), 1500),
                "comment": fields.get("comment", ""),
                "origin": _origin(source_id, ref),
                "apply_status": "needs_linux_ifname",
            })
        elif descr == "PPPoE DSL interface" and fields.get("status switch") == "1":
            alias_addresses = _interface_aliases(index, fields.get("name", ""), fields.get("additional addresses", ""))
            pppoe_profiles.append({
                "id": uuid.uuid4().hex,
                "name": _identifier(fields.get("name", ""), ref),
                "sophos_name": fields.get("name", ""),
                "parent_hardware_ref": fields.get("interface hardware", ""),
                "parent_hardware_name": _name(index, fields.get("interface hardware", "")),
                "username": fields.get("username", ""),
                "password": fields.get("password", ""),
                "mtu": _int_or_default(fields.get("maximum transmission unit"), 1492),
                "vlan_tag": fields.get("VLAN tag", ""),
                "primary_address": _resolve_address(index, fields.get("primary address", "")),
                "additional_addresses": [_resolve_address(index, r) for r in _split_refs(fields.get("additional addresses", ""))],
                "alias_addresses": alias_addresses,
                "comment": fields.get("comment", ""),
                "origin": _origin(source_id, ref),
                "apply_status": "needs_parent_ifname",
            })
        elif descr == "static route" and fields.get("status switch") == "1":
            destination = _resolve_network(index, fields.get("destination network", ""))
            route_type = fields.get("route type", "")
            target_ref = fields.get("target", "")
            route = {
                "id": uuid.uuid4().hex,
                "destination": destination,
                "route_type": route_type,
                "gateway": "" if route_type == "itf" else _resolve_host(index, target_ref),
                "interface": _name(index, target_ref) if route_type == "itf" else "",
                "metric": _int_or_default(fields.get("route metric"), 0),
                "comment": fields.get("comment", ""),
                "origin": _origin(source_id, ref),
                "apply_status": "needs_connection_name",
            }
            if _valid_cidr(route["destination"]):
                static_routes.append(route)
        elif descr == "NAT rule" and fields.get("status switch") == "1":
            for forward in _nat_forward_ports(index, fields, source_id, ref):
                nat_forward_ports.append(forward)
        elif descr == "masquerading rule" and fields.get("status switch") == "1":
            source = _resolve_network(index, fields.get("source network", ""))
            masquerade_rules.append({
                "id": uuid.uuid4().hex,
                "source": source,
                "outgoing_interface": _name(index, fields.get("outgoing interface", "")),
                "outgoing_interface_ref": fields.get("outgoing interface", ""),
                "comment": fields.get("comment", ""),
                "firewalld_direct_rule": f"ipv4 nat POSTROUTING 0 -s {source} -j MASQUERADE" if _valid_cidr(source) else "",
                "origin": _origin(source_id, ref),
                "apply_status": "ready" if _valid_cidr(source) else "needs_review",
            })

    return {
        "static_interfaces": static_interfaces,
        "pppoe_profiles": pppoe_profiles,
        "static_routes": static_routes,
        "nat_forward_ports": nat_forward_ports,
        "masquerade_rules": masquerade_rules,
    }


def _nat_forward_ports(index: dict[str, dict], fields: dict[str, str], source_id: str, ref: str) -> list[dict]:
    traffic_service = _service(index, fields.get("traffic service", ""))
    destination_service = _service(index, fields.get("destination service", ""))
    toaddr = _resolve_host(index, fields.get("destination address", ""))
    source = _resolve_network(index, fields.get("traffic source", ""))
    if not traffic_service or not destination_service or not _valid_ipv4(toaddr):
        return []

    forwards: list[dict] = []
    for proto in sorted(set(traffic_service["protocols"]) & set(destination_service["protocols"])):
        port = traffic_service["port"]
        toport = destination_service["port"]
        spec = f"port={port}:proto={proto}:toport={toport}:toaddr={toaddr}"
        forwards.append({
            "id": uuid.uuid4().hex,
            "zone": "public",
            "source": source,
            "port": port,
            "proto": proto,
            "toport": toport,
            "toaddr": toaddr,
            "firewalld_forward_port": spec,
            "traffic_service_ref": fields.get("traffic service", ""),
            "destination_service_ref": fields.get("destination service", ""),
            "traffic_destination": _resolve_host(index, fields.get("traffic destination", "")),
            "comment": fields.get("comment", ""),
            "origin": _origin(source_id, ref),
            "apply_status": "ready" if source in {"Any", "REF_NetworkAny", "REF_NetworkAny4"} or source == "Any" else "source_scope_needs_review",
        })
    return forwards


def _service(index: dict[str, dict], ref: str) -> dict | None:
    obj = index.get(ref)
    if not obj:
        return None
    descr = obj.get("descr", "")
    fields = obj.get("fields", {})
    first = fields.get("first destination port", "").strip()
    last = fields.get("last destination port", "").strip()
    if not first.isdigit() or not last.isdigit():
        return None
    port = first if first == last else f"{first}-{last}"
    protocols: list[str] = []
    if "TCP" in descr:
        protocols.append("tcp")
    if "UDP" in descr:
        protocols.append("udp")
    if not protocols:
        return None
    return {"name": fields.get("name", ""), "port": port, "protocols": protocols}


def _merge_dnsmasq(store: ConfigStore, imported: dict, source_id: str, replace: bool) -> dict:
    with store.transaction(DNSMASQ_MODULE, dnsmasq_default()) as data:
        if replace:
            _remove_origin(data["dns"].setdefault("hosts", []), source_id)
            _remove_origin(data["dhcp"].setdefault("ranges", []), source_id)
            _remove_origin(data["dhcp"].setdefault("options", []), source_id)
        added_hosts = _append_unique(data["dns"].setdefault("hosts", []), imported["dns"]["hosts"], ("domain", "ip"))
        added_ranges = _append_unique(data["dhcp"].setdefault("ranges", []), imported["dhcp"]["ranges"], ("start", "end", "netmask"))
        added_options = _append_unique(data["dhcp"].setdefault("options", []), imported["dhcp"]["options"], ("option", "value", "tag"))
    return {"dns_hosts": added_hosts, "dhcp_ranges": added_ranges, "dhcp_options": added_options}


def _merge_nginx(store: ConfigStore, imported: dict, source_id: str, replace: bool) -> dict:
    with store.transaction(NGINX_MODULE, nginx_default()) as data:
        if replace:
            _remove_origin(data.setdefault("backends", []), source_id)
            _remove_origin(data.setdefault("vhosts", []), source_id)
        existing_backend_names = {b.get("name") for b in data.setdefault("backends", [])}
        for backend in imported["backends"]:
            backend["name"] = _unique(backend["name"], existing_backend_names)
            existing_backend_names.add(backend["name"])
        added_backends = _append_unique(data["backends"], imported["backends"], ("name", "host", "port", "scheme"))
        valid_backend_ids = {b.get("id") for b in data["backends"]}
        imported_vhosts = [v for v in imported["vhosts"] if (v.get("locations") or [{}])[0].get("backend_id") in valid_backend_ids]
        existing_vhost_names = {v.get("name") for v in data.setdefault("vhosts", [])}
        for vhost in imported_vhosts:
            vhost["name"] = _unique(vhost["name"], existing_vhost_names)
            existing_vhost_names.add(vhost["name"])
        added_vhosts = _append_unique(data["vhosts"], imported_vhosts, ("name",))
    return {"backends": added_backends, "vhosts": added_vhosts}


def _merge_ipsec(store: ConfigStore, imported: dict, source_id: str, replace: bool) -> dict:
    with store.transaction(IPSEC_MODULE, ipsec_default()) as data:
        if replace:
            _remove_origin(data.setdefault("connections", []), source_id)
        existing_names = {c.get("name") for c in data.setdefault("connections", [])}
        for conn in imported["connections"]:
            conn["name"] = _unique(conn["name"], existing_names)
            existing_names.add(conn["name"])
        added = _append_unique(data["connections"], imported["connections"], ("name", "remote_addrs"))
    return {"connections": added}


def _merge_appliance(store: ConfigStore, imported: dict, source_id: str, replace: bool) -> dict:
    default = {
        "static_interfaces": [],
        "pppoe_profiles": [],
        "static_routes": [],
        "nat_forward_ports": [],
        "masquerade_rules": [],
    }
    with store.transaction(IMPORT_MODULE, default) as data:
        for key, keys in {
            "static_interfaces": ("name", "address", "gateway"),
            "pppoe_profiles": ("name", "username"),
            "static_routes": ("destination", "gateway", "interface"),
            "nat_forward_ports": ("port", "proto", "toport", "toaddr"),
            "masquerade_rules": ("source", "outgoing_interface_ref"),
        }.items():
            data.setdefault(key, [])
            if replace:
                _remove_origin(data[key], source_id)
        added_static_interfaces = _append_unique(data["static_interfaces"], imported["static_interfaces"], ("name", "address", "gateway"))
        added_pppoe = _append_unique(data["pppoe_profiles"], imported["pppoe_profiles"], ("name", "username"))
        added_routes = _append_unique(data["static_routes"], imported["static_routes"], ("destination", "gateway", "interface"))
        added_nat = _append_unique(data["nat_forward_ports"], imported["nat_forward_ports"], ("port", "proto", "toport", "toaddr"))
        added_masq = _append_unique(data["masquerade_rules"], imported["masquerade_rules"], ("source", "outgoing_interface_ref"))
    return {
        "static_interfaces": added_static_interfaces,
        "pppoe_profiles": added_pppoe,
        "static_routes": added_routes,
        "nat_forward_ports": added_nat,
        "masquerade_rules": added_masq,
    }


def _append_unique(target: list[dict], items: list[dict], keys: tuple[str, ...]) -> int:
    seen = {tuple(str(row.get(k, "")) for k in keys) for row in target}
    added = 0
    for item in items:
        key = tuple(str(item.get(k, "")) for k in keys)
        if key in seen:
            continue
        target.append(item)
        seen.add(key)
        added += 1
    return added


def _remove_origin(items: list[dict], source_id: str) -> None:
    items[:] = [item for item in items if not str(item.get("origin", "")).startswith(f"sophos:{source_id}:")]


def _header_summary(header: ET.Element | None) -> dict:
    if header is None:
        return {}
    release = header.findtext("./format/release") or ""
    versions = [e.text or "" for e in header.findall("./format/versions/version")]
    data_version = header.findtext("./data/version") or ""
    return {"release": release, "versions": versions, "data_version": data_version}


def _collect_objects(root: ET.Element) -> list[dict]:
    out: list[dict] = []
    for element in root.iter():
        descr = (element.findtext("descr") or "").strip()
        if not descr:
            continue
        contents = _direct_contents(element)
        attrs = dict(element.attrib)
        if attrs.get("type") or attrs.get("class") or attrs.get("link") == "objs" or contents:
            out.append({
                "tag": element.tag,
                "descr": descr,
                "attrs": attrs,
                "contents": contents[:200],
            })
    return out


def _object_index(root: ET.Element) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for element in root.iter():
        if element.attrib.get("object") != "1":
            continue
        out[element.tag] = {
            "tag": element.tag,
            "descr": (element.findtext("descr") or "").strip(),
            "fields": _field_map(element),
        }
    return out


def _field_map(element: ET.Element) -> dict[str, str]:
    content = element.find("content")
    if content is None:
        return {}
    fields: dict[str, str] = {}
    for child in list(content):
        key = (child.findtext("descr") or child.tag).strip()
        value = (child.findtext("content") or "").strip()
        if key:
            fields[key] = value
        if child.tag:
            fields.setdefault(child.tag, value)
    return fields


def _direct_contents(element: ET.Element) -> list[str]:
    values: list[str] = []
    for content in element.findall("content"):
        text = "".join(content.itertext()).strip()
        if text:
            values.append(text)
    return values


def _build_ui_preview(index: dict[str, dict]) -> dict:
    return {
        "network": _preview_network(index),
        "static_routes": _preview_static_routes(index),
        "dhcp": _preview_dhcp(index),
        "dhcp_options": _preview_dhcp_options(index),
        "strongswan": _preview_ipsec(index),
        "nginx": _preview_nginx(index),
        "certificates": _preview_certificates(index),
    }


def _preview_network(index: dict[str, dict]) -> list[dict]:
    rows = []
    for ref, obj in sorted(index.items()):
        f = obj.get("fields", {})
        if "interface hardware" not in f or "primary address" not in f:
            continue
        primary = _resolve_address(index, f.get("primary address", ""))
        primary_fields = _fields(index, f.get("primary address", ""))
        secondary = [_resolve_address(index, r) for r in _split_refs(f.get("additional addresses", ""))]
        secondary = [v for v in secondary if v]
        if f.get("username") or f.get("password"):
            mode = "PPPoE"
            form = {
                "WAN種別": "PPPoE",
                "接続名": f.get("name", ""),
                "PPPoEユーザー": f.get("username", ""),
                "PPPoEパスワード": f.get("password", ""),
                "MTU": f.get("maximum transmission unit", ""),
                "External IP": "PPPoEでは入力不要。Sophos側の参考値: " + (primary or "空"),
            }
        else:
            mode = "Static / LAN"
            form = {
                "接続名": f.get("name", ""),
                "IPv4アドレス": primary,
                "セカンダリIPv4アドレス": ", ".join(secondary),
                "VLANタグ": f.get("VLAN tag", ""),
                "MTU": f.get("maximum transmission unit", ""),
            }
        rows.append({
            "ref": ref,
            "mode": mode,
            "enabled": f.get("status switch") == "1",
            "gateway": primary_fields.get("IPv4 gateway", "") if primary_fields.get("IPv4 default gateway switch") == "1" else "",
            "default_gateway": primary_fields.get("IPv4 default gateway switch") == "1",
            "form": form,
        })
    return rows


def _preview_static_routes(index: dict[str, dict]) -> list[dict]:
    rows = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "static route":
            continue
        f = obj.get("fields", {})
        destination = _resolve_network(index, f.get("destination network", ""))
        route_type = f.get("route type", "")
        target_ref = f.get("target", "")
        if route_type == "itf":
            gateway = ""
            interface = _name(index, target_ref)
        else:
            gateway = _resolve_host(index, target_ref)
            interface = ""
        rows.append({
            "ref": ref,
            "enabled": f.get("status switch") == "1",
            "form": {
                "宛先ネットワーク": destination,
                "ゲートウェイ": gateway or "直接接続 / interface route",
                "接続プロファイル": interface,
                "メトリック": f.get("route metric", ""),
                "Sophos route type": route_type,
                "コメント": f.get("comment", ""),
            },
        })
    return rows


def _preview_ipsec(index: dict[str, dict]) -> list[dict]:
    rows = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "IPsec site-to-site connection":
            continue
        f = obj.get("fields", {})
        if not f.get("name"):
            continue
        gw = _fields(index, f.get("remote gateway", ""))
        auth = _fields(index, gw.get("peer authentication configuration", ""))
        policy = _fields(index, f.get("policy", ""))
        local_networks = [_resolve_network(index, r) for r in _split_refs(f.get("network list", ""))]
        remote_networks = [_resolve_network(index, r) for r in _split_refs(gw.get("remote subnet list", ""))]
        form = {
            "トンネル名": f.get("name", ""),
            "有効": "はい" if f.get("status switch") == "1" else "いいえ",
            "ローカルインターフェース": _name(index, f.get("interface", "")),
            "対向ゲートウェイ": _resolve_host(index, gw.get("remote host address", "")),
            "ローカルサブネット": ", ".join(v for v in local_networks if v),
            "対向サブネット": ", ".join(v for v in remote_networks if v),
            "事前共有鍵(PSK)": auth.get("preshared key", ""),
            "ローカルID": auth.get("VPN ID", ""),
            "IKE暗号": policy.get("IKE SA encryption algorithm", ""),
            "IKEハッシュ": policy.get("IKE SA authentication algorithm", ""),
            "IKE DHグループ": policy.get("IKE SA Diffie-Hellman group", ""),
            "ESP暗号": policy.get("IPsec SA encryption algorithm", ""),
            "ESPハッシュ": policy.get("IPsec SA authentication algorithm", ""),
            "PFSグループ": policy.get("IPsec SA PFS Diffie-Hellman group", ""),
            "Firewall自動許可": "はい" if f.get("auto-packetfilter rule switch") == "1" else "いいえ",
        }
        rows.append({"ref": ref, "form": form})
    return rows


def _preview_dhcp(index: dict[str, dict]) -> list[dict]:
    rows = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "DHCPv4 server":
            continue
        f = obj.get("fields", {})
        rows.append({
            "ref": ref,
            "enabled": f.get("status switch") == "1",
            "form": {
                "対象インターフェース": _name(index, f.get("interface", "")),
                "開始IP": f.get("range_start", ""),
                "終了IP": f.get("range_end", ""),
                "ネットマスク": f.get("netmask", ""),
                "デフォルトゲートウェイ": f.get("default gateway address", ""),
                "DNS 1": f.get("first DNS server", ""),
                "DNS 2": f.get("second DNS server", ""),
                "ドメイン": f.get("domain", ""),
                "リース時間(秒)": f.get("lease time", ""),
                "静的割当のみ": "はい" if f.get("static mappings only switch") == "1" else "いいえ",
                "WINS node type": f.get("WINS node type", ""),
                "WINS server": f.get("WINS server address", ""),
                "Proxy auto-config": "はい" if f.get("proxy-autoconfig switch") == "1" else "いいえ",
                "Relay mode": "はい" if f.get("relay mode switch") == "1" else "いいえ",
                "コメント": f.get("comment", ""),
            },
        })
    return rows


def _preview_dhcp_options(index: dict[str, dict]) -> list[dict]:
    rows = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "DHCPv4 option":
            continue
        f = obj.get("fields", {})
        value = f.get("text value") or f.get("IPv4 address") or f.get("hex value")
        rows.append({
            "ref": ref,
            "enabled": f.get("status switch") == "1",
            "form": {
                "オプション番号": f.get("code number", ""),
                "オプション名": f.get("option name", ""),
                "型": f.get("type", ""),
                "値": value,
                "スコープ": f.get("scope", ""),
                "対象DHCPサーバー": ", ".join(_name(index, r) for r in _split_refs(f.get("server list", ""))),
                "対象ホスト": ", ".join(_name(index, r) for r in _split_refs(f.get("host list", ""))),
                "MAC prefix": f.get("mac prefix", ""),
                "Vendor prefix": f.get("vendor prefix", ""),
            },
        })
    return rows


def _preview_nginx(index: dict[str, dict]) -> list[dict]:
    backends_by_name = {}
    for ref, obj in index.items():
        if obj.get("descr") != "real webserver":
            continue
        f = obj.get("fields", {})
        backends_by_name[f.get("name", "")] = (ref, f)

    rows = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "virtual webserver":
            continue
        f = obj.get("fields", {})
        backend_ref, backend = backends_by_name.get(f.get("name", ""), ("", {}))
        backend_scheme = "https" if backend.get("SSL switch") == "1" else "http"
        backend_host = _resolve_host(index, backend.get("host", ""))
        backend_port = backend.get("port", "")
        domains = [v for v in re.split(r"[\s,]+", f.get("domain list", "")) if v]
        cert_fqdn = domains[0] if domains else ""
        form = {
            "vhost名": f.get("name", ""),
            "有効": "はい" if f.get("status switch") == "1" else "いいえ",
            "server_name": " ".join(domains),
            "待受スキーム": f.get("type", ""),
            "待受ポート": f.get("port", ""),
            "Listen設定": f"{f.get('port', '')} {'ssl' if f.get('type') == 'https' else ''}".strip(),
            "証明書候補": f"/etc/letsencrypt/live/{cert_fqdn}/fullchain.pem" if cert_fqdn else "",
            "秘密鍵候補": f"/etc/letsencrypt/live/{cert_fqdn}/privkey.pem" if cert_fqdn else "",
            "バックエンド名": backend.get("name", ""),
            "バックエンド方式": backend_scheme,
            "バックエンドホスト": backend_host,
            "バックエンドポート": backend_port,
            "バックエンドURL": f"{backend_scheme}://{backend_host}:{backend_port}" if backend else "",
            "Hostヘッダ維持": "はい" if f.get("switch to preserve host header") == "1" else "いいえ",
            "HTTPからHTTPSへリダイレクト": "はい" if f.get("implicit redirection from http to https switch") == "1" else "いいえ",
            "WebSocket対応": "いいえ",
            "client_max_body_size": "10m",
            "set_real_ip_from": "",
            "Sophos profile": f.get("profile", ""),
            "HTML内URL書換": "はい" if f.get("URL rewriting in HTML documents") == "1" else "いいえ",
            "Content-Type補完": "はい" if f.get("add missing Content-Type header switch") == "1" else "いいえ",
            "例外リスト": ", ".join(_name(index, r) for r in _split_refs(f.get("exception list", ""))),
            "コメント": f.get("comment", ""),
        }
        rows.append({"ref": ref, "backend_ref": backend_ref, "form": form})
    return rows


def _preview_certificates(index: dict[str, dict]) -> list[dict]:
    nginx_domains = set()
    for obj in index.values():
        if obj.get("descr") == "virtual webserver":
            for value in re.split(r"[\s,]+", obj.get("fields", {}).get("domain list", "")):
                if value:
                    nginx_domains.add(value)

    rows = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "X509 certificate with private key":
            continue
        f = obj.get("fields", {})
        name = f.get("name", "")
        if "(X509 User Cert)" in name or name == "Local X509 Cert" or name.startswith("WebAdmin certificate for "):
            continue
        is_ddnsft = name.endswith(".ddnsft.com")
        usage = "Nginx候補" if name in nginx_domains else "参考のみ"
        if is_ddnsft:
            usage = "DDNS上書き登録が必要 / 証明書取込候補"
        rows.append({
            "ref": ref,
            "usage": usage,
            "form": {
                "証明書名": name,
                "FQDN": name if "." in name else "",
                "DDNS登録": "上書きが必要" if is_ddnsft else "不要または対象外",
                "DDNSホスト名": name.removesuffix(".ddnsft.com") if is_ddnsft else "",
                "秘密鍵の取込": "はい" if f.get("private key") else "いいえ",
                "証明書の取込": "はい" if f.get("certificate") else "いいえ",
                "issuer certificate": f.get("issuer certificate", ""),
                "コメント": f.get("comment", ""),
            },
        })
    return rows


def _fields(index: dict[str, dict], ref: str) -> dict[str, str]:
    return index.get(ref, {}).get("fields", {})


def _name(index: dict[str, dict], ref: str) -> str:
    return _fields(index, ref).get("name", ref)


def _interface_aliases(index: dict[str, dict], interface_name: str, refs: str) -> list[dict]:
    aliases: list[dict] = []
    for ref in _split_refs(refs):
        f = _fields(index, ref)
        addr = f.get("IPv4 address", "").strip()
        cidr = _address_cidr(index, ref)
        if not addr and not cidr:
            continue
        aliases.append({
            "ref": ref,
            "name": f.get("name", ""),
            "address": addr,
            "netmask": _prefix_to_netmask(_ipv4_mask_value(f)),
            "cidr": cidr or _resolve_address(index, ref),
            "interface_address_refs": _matching_interface_address_refs(index, interface_name, f),
            "comment": f.get("comment", ""),
            "enabled": f.get("status switch") == "1",
        })
    return aliases


def _matching_interface_address_refs(index: dict[str, dict], interface_name: str, alias_fields: dict[str, str]) -> list[str]:
    addr = alias_fields.get("IPv4 address", "").strip()
    alias_name = alias_fields.get("name", "").strip()
    if not addr:
        return []
    refs: list[str] = []
    for ref, obj in sorted(index.items()):
        if obj.get("descr") != "interface address":
            continue
        f = obj.get("fields", {})
        if f.get("IPv4 address", "").strip() != addr:
            continue
        text = " ".join([f.get("name", ""), f.get("comment", "")])
        if (interface_name and interface_name in text) or (alias_name and alias_name in text):
            refs.append(ref)
    return refs


def _resolve_address(index: dict[str, dict], ref: str) -> str:
    f = _fields(index, ref)
    addr = f.get("IPv4 address") or f.get("address")
    mask = _ipv4_mask_value(f)
    if addr and mask:
        return f"{addr}/{mask}"
    return addr or ref


def _address_cidr(index: dict[str, dict], ref: str) -> str:
    f = _fields(index, ref)
    addr = f.get("IPv4 address", "").strip()
    mask = _ipv4_mask_value(f)
    if _valid_ipv4(addr) and mask:
        return f"{addr}/{mask}"
    return ""


def _ipv4_mask_value(fields: dict[str, str]) -> str:
    value = str(fields.get("IPv4 netmask", "") or fields.get("netmask", "") or "").strip()
    if value:
        return value
    if _valid_ipv4(fields.get("IPv4 address", "")):
        fallback = str(fields.get("IPv6 netmask", "") or "").strip()
        if fallback.isdigit() and 0 <= int(fallback) <= 32:
            return fallback
    return ""


def _is_static_ip_interface(fields: dict[str, str]) -> bool:
    primary = fields.get("primary address", "")
    return bool(fields.get("interface hardware") and primary and not fields.get("username") and not fields.get("password"))


def _resolve_network(index: dict[str, dict], ref: str) -> str:
    f = _fields(index, ref)
    addr = f.get("IPv4 address")
    mask = _ipv4_mask_value(f)
    if addr and mask:
        return f"{addr}/{mask}"
    return f.get("name", ref)


def _resolve_host(index: dict[str, dict], ref: str) -> str:
    f = _fields(index, ref)
    return f.get("hostname") or f.get("IPv4 address") or f.get("name") or ref


def _split_refs(value: str) -> list[str]:
    return [v for v in re.split(r"[\s,]+", value or "") if v]


def _secret_fields(obj: dict) -> list[dict]:
    secrets = []
    if SECRET_RE.search(obj["descr"]):
        for value in obj.get("contents", []):
            secrets.append({"descr": obj["descr"], "length": len(value), "preview": _redact(value)})
    return secrets


def _redact(value: str) -> str:
    if not value:
        return ""
    if "BEGIN " in value:
        first = value.splitlines()[0] if value.splitlines() else "PEM"
        return f"{first} ... [redacted {len(value)} chars]"
    if len(value) <= 8:
        return "[redacted]"
    return value[:2] + "..." + value[-2:]


def _source_id(source_name: str) -> str:
    base = Path(source_name or "upload.xml").name
    return re.sub(r"[^A-Za-z0-9_.-]", "_", base)[:96] or "upload.xml"


def _origin(source_id: str, ref: str) -> str:
    return f"sophos:{source_id}:{ref}"


def _identifier(value: str, fallback: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9_-]+", "_", value or "").strip("_")
    if not raw or not re.match(r"^[A-Za-z]", raw):
        raw = re.sub(r"[^A-Za-z0-9_-]+", "_", fallback or "").strip("_")
    if not raw or not re.match(r"^[A-Za-z]", raw):
        raw = "sophos_import"
    return raw[:63]


def _unique(name: str, existing: set[str]) -> str:
    if name not in existing:
        return name
    stem = name[:56]
    index = 2
    while f"{stem}_{index}" in existing:
        index += 1
    return f"{stem}_{index}"


def _hostnames(fields: dict[str, str]) -> list[str]:
    values: list[str] = []
    for raw in [fields.get("hostname list", ""), fields.get("name", "")]:
        for part in re.split(r"[\s,]+", raw or ""):
            part = part.strip().strip(".")
            if "." in part and not _valid_ipv4(part) and part not in values:
                values.append(part)
    return values


def _add_option(items: list[dict], seen: set[tuple[str, str, str]], option: str, value: str, source_id: str, ref: str) -> None:
    option = str(option or "").strip()
    value = str(value or "").strip()
    if not option or not value or value == "0.0.0.0":
        return
    key = (option, value, "")
    if key in seen:
        return
    seen.add(key)
    items.append({"id": uuid.uuid4().hex, "option": option, "value": value, "tag": "", "origin": _origin(source_id, ref)})


def _prefix_to_netmask(value: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if _valid_ipv4(text):
        return text
    try:
        prefix = int(text)
        if not 0 <= prefix <= 32:
            return None
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    except ValueError:
        return None


def _lease_seconds(value: str) -> str:
    text = str(value or "").strip()
    return text if text.isdigit() else "12h"


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(str(value).strip())
        return True
    except ValueError:
        return False


def _usable_ipv4(value: str) -> bool:
    text = str(value or "").strip()
    return _valid_ipv4(text) and text != "0.0.0.0"


def _valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(str(value).strip(), strict=False)
        return True
    except ValueError:
        return False


def _valid_hostname_like(value: str) -> bool:
    text = str(value or "").strip()
    if not text or len(text) > 253 or ".." in text:
        return False
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*[A-Za-z0-9]$", text))


def _int_or_default(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _vpn_id(auth: dict[str, str]) -> str:
    value = (auth.get("VPN ID") or "").strip()
    return "" if value in {"", "0.0.0.0"} else value


def _ike_proposal(policy: dict[str, str]) -> str:
    enc = _proposal_token(policy.get("IKE SA encryption algorithm", ""), "aes256")
    auth = _proposal_token(policy.get("IKE SA authentication algorithm", ""), "sha1")
    dh = _proposal_token(policy.get("IKE SA Diffie-Hellman group", ""), "modp1024")
    return f"{enc}-{auth}-{dh}"


def _esp_proposal(policy: dict[str, str]) -> str:
    enc = _proposal_token(policy.get("IPsec SA encryption algorithm", ""), "aes256")
    auth = _proposal_token(policy.get("IPsec SA authentication algorithm", ""), "sha1")
    dh = _proposal_token(policy.get("IPsec SA PFS Diffie-Hellman group", ""), "")
    return "-".join(v for v in [enc, auth, dh] if v)


def _proposal_token(value: str, default: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_]+", "", str(value or "").lower())
    if token in {"sha", "sha1", "sha_1"}:
        return "sha1"
    if token in {"sha256", "sha2_256"}:
        return "sha256"
    if token in {"sha384", "sha2_384"}:
        return "sha384"
    if token in {"sha512", "sha2_512"}:
        return "sha512"
    if token in {"3des", "des3"}:
        return "3des"
    return token or default


def _conversion_warnings(index: dict[str, dict]) -> list[str]:
    warnings: list[str] = []
    if any(obj.get("descr") in {"PPPoE DSL interface", "static route"} or _is_static_ip_interface(obj.get("fields", {})) for obj in index.values()):
        warnings.append("Static IP interfaces, PPPoE, and static routes are imported into the Sophos import queue; applying them still requires mapping Sophos interface refs to Linux NetworkManager connection names.")
    if any(obj.get("descr") == "firewall rule" for obj in index.values()):
        warnings.append("NAT/masquerade rules are imported; plain Sophos packet filter rules still require manual review before firewalld translation.")
    return warnings


def _skipped_counts(index: dict[str, dict]) -> dict[str, int]:
    skipped = {"interface_addresses": 0, "packet_filter_rules": 0, "certificates": 0}
    for obj in index.values():
        descr = obj.get("descr")
        if descr in {"interface", "interface address", "additional interface address"}:
            skipped["interface_addresses"] += 1
        elif descr == "firewall rule":
            skipped["packet_filter_rules"] += 1
        elif descr in {"X509 certificate with private key", "RSA private key", "private key"}:
            skipped["certificates"] += 1
    return skipped
