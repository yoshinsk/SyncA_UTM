"""payload/server-gui/server_gui/modules/firewall.py - Manage firewalld policy.

Endpoints:
  GET    /firewall/api/zones                       — list zones + active + default
  GET    /firewall/api/zones/<z>                   — zone details
  POST   /firewall/api/zones/<z>/default           — set default zone
  POST   /firewall/api/zones/<z>/ports             — add port
  DELETE /firewall/api/zones/<z>/ports             — remove port
  POST   /firewall/api/zones/<z>/services          — add service
  DELETE /firewall/api/zones/<z>/services          — remove service
  POST   /firewall/api/zones/<z>/sources           — add source
  DELETE /firewall/api/zones/<z>/sources           — remove source
  POST   /firewall/api/zones/<z>/rich-rules        — add rich rule
  DELETE /firewall/api/zones/<z>/rich-rules        — remove rich rule
  POST   /firewall/api/zones/<z>/forward-ports     — add forward port
  DELETE /firewall/api/zones/<z>/forward-ports     — remove forward port
  GET    /firewall/api/zones/<z>/protocol-forwards — list GRE/ESP/AH forwards
  POST   /firewall/api/zones/<z>/protocol-forwards — add GRE/ESP/AH forward
  DELETE /firewall/api/zones/<z>/protocol-forwards — remove GRE/ESP/AH forward
  GET    /firewall/api/services-available          — all installed service defs
  GET    /firewall/api/direct-rules                — global direct rules (read-only)
  POST   /firewall/api/reload                      — firewall-cmd --reload
"""
from __future__ import annotations

import re
import shlex

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..shell import sudo_run
from ..validators import ValidationError, validate_identifier, validate_ipv4

bp = Blueprint("firewall", __name__, url_prefix="/firewall")

PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?/(tcp|udp|sctp|dccp)$")
PORT_RANGE_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")
FORWARD_PROTO_RE = re.compile(r"^(gre|esp|ah)$")
VPN_CLIENT_DEFAULT_INGRESS_ZONE = "trusted"
VPN_CLIENT_PROFILES = {
    "pptp": {
        "label": "PPTP",
        "policy": "synca-pptp-client",
        "service": "synca-pptp-client",
        "ports": ["1723/tcp"],
        "protocols": [],
        "helpers": ["pptp"],
        "conflict_protocols": ["gre"],
    },
    "l2tp-ipsec": {
        "label": "L2TP/IPsec",
        "policy": "synca-l2tp-ipsec-client",
        "service": "synca-l2tp-ipsec-client",
        "ports": ["500/udp", "4500/udp", "1701/udp"],
        "protocols": ["esp", "ah"],
        "helpers": [],
        "conflict_protocols": ["esp", "ah"],
    },
}
FORWARD_PORT_COMMENT_RE = re.compile(
    r"synca-forward-port:"
    r"([A-Za-z0-9_-]{1,63}):"
    r"(tcp|udp|sctp|dccp):"
    r"(\d{1,5}(?:-\d{1,5})?):"
    r"(\d{1,5}(?:-\d{1,5})?|_):"
    r"(\d{1,3}(?:\.\d{1,3}){3}|_):"
    r"([A-Za-z0-9_.+-]{1,64}|_):"
    r"(\d{1,3}(?:\.\d{1,3}){3}|_)"
)
PROTOCOL_FORWARD_COMMENT_RE = re.compile(
    r"synca-protocol-forward:([A-Za-z0-9_-]{1,63}):(gre|esp|ah):(\d{1,3}(?:\.\d{1,3}){3})"
)
INTERFACE_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
SERVICE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,63}$")
SOURCE_RE = re.compile(
    r"^(ipset:[a-zA-Z0-9_\-]+|"
    r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|"
    r"[0-9a-fA-F:]+(?:/\d{1,3})?)$"
)


def register(app: Flask) -> None:
    app.register_blueprint(bp)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("firewall.html", active_tab="firewall")


@bp.route("/api/zones", methods=["GET"])
@login_required
def list_zones():
    res = sudo_run(["firewall-cmd", "--get-zones"])
    zones = res.stdout.split() if res.ok else []
    active_res = sudo_run(["firewall-cmd", "--get-active-zones"])
    default_res = sudo_run(["firewall-cmd", "--get-default-zone"])
    return jsonify({
        "zones": zones,
        "active": _parse_active(active_res.stdout if active_res.ok else ""),
        "default": default_res.stdout.strip() if default_res.ok else None,
    })


@bp.route("/api/zones/<zone>", methods=["GET"])
@login_required
def get_zone(zone: str):
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return jsonify({"error": "invalid zone name"}), 400
    return jsonify(_describe_zone(zone))


@bp.route("/api/zones/<zone>/default", methods=["POST"])
@login_required
@csrf_protect
def set_default(zone: str):
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return jsonify({"error": "invalid zone name"}), 400
    res = sudo_run(["firewall-cmd", "--set-default-zone", zone])
    return jsonify({"ok": res.ok, "output": res.stdout or res.stderr})


@bp.route("/api/zones/<zone>/ports", methods=["POST", "DELETE"])
@login_required
@csrf_protect
def manage_port(zone: str):
    payload = request.get_json(force=True, silent=True) or {}
    port = payload.get("port", "")
    if not PORT_RE.match(port):
        return jsonify({"error": "invalid port (e.g. 443/tcp or 1000-2000/udp)"}), 400
    op = "--add-port" if request.method == "POST" else "--remove-port"
    return jsonify(_apply_change(zone, [op, port]))


@bp.route("/api/zones/<zone>/services", methods=["POST", "DELETE"])
@login_required
@csrf_protect
def manage_service(zone: str):
    payload = request.get_json(force=True, silent=True) or {}
    svc = payload.get("service", "")
    if not svc or not SERVICE_RE.match(svc):
        return jsonify({"error": "invalid service name"}), 400
    op = "--add-service" if request.method == "POST" else "--remove-service"
    return jsonify(_apply_change(zone, [op, svc]))


@bp.route("/api/zones/<zone>/sources", methods=["POST", "DELETE"])
@login_required
@csrf_protect
def manage_source(zone: str):
    payload = request.get_json(force=True, silent=True) or {}
    source = payload.get("source", "")
    if not source or not SOURCE_RE.match(source):
        return jsonify({"error": "invalid source (CIDR or ipset:<name>)"}), 400
    op = "--add-source" if request.method == "POST" else "--remove-source"
    return jsonify(_apply_change(zone, [op, source]))


@bp.route("/api/zones/<zone>/rich-rules", methods=["POST", "DELETE"])
@login_required
@csrf_protect
def manage_rich_rule(zone: str):
    payload = request.get_json(force=True, silent=True) or {}
    rule = payload.get("rule", "")
    if not rule or "\n" in rule or len(rule) > 1024:
        return jsonify({"error": "invalid rich rule"}), 400
    op = "--add-rich-rule" if request.method == "POST" else "--remove-rich-rule"
    return jsonify(_apply_change(zone, [op, rule]))


@bp.route("/api/zones/<zone>/forward-ports", methods=["POST", "DELETE"])
@login_required
@csrf_protect
def manage_forward_port(zone: str):
    """Add or remove a port-forward.

    Body:  {"port": "8080", "proto": "tcp", "toport": "80", "toaddr": "1.2.3.4",
            "interface": "ens34", "inaddr": "203.0.113.10"}
    Either 'toport' or 'toaddr' (or both) must be provided.
    If 'interface' or 'inaddr' is provided, SyncA uses managed direct rules
    because firewalld's forward-port primitive cannot limit the incoming side.
    """
    payload = request.get_json(force=True, silent=True) or {}
    rule, error = _normalize_forward_port_payload(payload)
    if error:
        return jsonify({"error": error}), 400

    add = request.method == "POST"
    if rule["interface"] or rule["inaddr"]:
        result = _apply_scoped_forward_port_change(zone, rule, add)
    else:
        spec = _forward_port_spec(rule)
        result = _apply_forward_port_change(zone, spec, rule["port"], rule["proto"], add)
    return jsonify(result), (200 if result.get("ok") else 500)


def _normalize_forward_port_payload(payload: dict) -> tuple[dict, str | None]:
    port = str(payload.get("port", "")).strip()
    proto = str(payload.get("proto", "")).strip().lower()
    toport = str(payload.get("toport", "")).strip()
    toaddr = str(payload.get("toaddr", "")).strip()
    interface = str(payload.get("interface", "") or payload.get("iface", "")).strip()
    inaddr = str(payload.get("inaddr", "") or payload.get("incoming_addr", "")).strip()

    error = _validate_forward_port_fields(port, proto, toport, toaddr, interface, inaddr)
    if error:
        return {}, error

    return {
        "port": port,
        "proto": proto,
        "toport": toport,
        "toaddr": toaddr,
        "interface": interface,
        "inaddr": inaddr,
    }, None


def _validate_forward_port_fields(
    port: str,
    proto: str,
    toport: str,
    toaddr: str,
    interface: str,
    inaddr: str,
) -> str | None:
    if not _valid_port_range(port):
        return "invalid port (e.g. 80 or 8000-8100)"
    if proto not in ("tcp", "udp", "sctp", "dccp"):
        return "proto must be one of: tcp, udp, sctp, dccp"
    if not toport and not toaddr:
        return "toport or toaddr must be specified"
    if toport and not _valid_port_range(toport):
        return "invalid toport"
    if toaddr:
        try:
            validate_ipv4(toaddr)
        except ValidationError as e:
            return str(e)
    if inaddr:
        try:
            validate_ipv4(inaddr)
        except ValidationError as e:
            return "invalid incoming IP address: " + str(e)
    if interface and not INTERFACE_SELECTOR_RE.match(interface):
        return "invalid incoming interface"
    if (interface or inaddr) and not toaddr:
        return "toaddr is required when incoming IP or interface is specified"
    return None


def _valid_port_range(value: str) -> bool:
    if not PORT_RANGE_RE.match(value):
        return False
    start_text, end_text = value.split("-", 1) if "-" in value else (value, value)
    start = int(start_text)
    end = int(end_text)
    return 1 <= start <= end <= 65535


@bp.route("/api/zones/<zone>/protocol-forwards", methods=["GET", "POST", "DELETE"])
@login_required
@csrf_protect
def manage_protocol_forward(zone: str):
    """List, add, or remove protocol forwards for GRE/ESP/AH.

    firewalld's forward-port supports TCP/UDP-like protocols only. PPTP and
    IPsec passthrough also need protocol forwarding such as GRE or ESP, so
    SyncA manages those as direct DNAT/FORWARD rules with a stable comment.
    """
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return jsonify({"ok": False, "error": "invalid zone name"}), 400

    if request.method == "GET":
        return jsonify({"items": _protocol_forward_rows(zone)})

    payload = request.get_json(force=True, silent=True) or {}
    proto = str(payload.get("proto", "")).strip().lower()
    toaddr = str(payload.get("toaddr", "")).strip()
    if not FORWARD_PROTO_RE.match(proto):
        return jsonify({"ok": False, "error": "proto must be one of: gre, esp, ah"}), 400
    try:
        validate_ipv4(toaddr)
    except ValidationError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    result = _apply_protocol_forward_change(zone, proto, toaddr, request.method == "POST")
    return jsonify(result), (200 if result.get("ok") else 500)


@bp.route("/api/vpn-client-passthrough", methods=["GET", "POST"])
@login_required
@csrf_protect
def vpn_client_passthrough():
    """Manage LAN-side VPN client passthrough policies."""
    if request.method == "GET":
        return jsonify(_vpn_client_passthrough_state())

    payload = request.get_json(force=True, silent=True) or {}
    profile = str(payload.get("profile", "")).strip().lower()
    enabled = bool(payload.get("enabled"))
    ingress_zone = str(payload.get("ingress_zone") or VPN_CLIENT_DEFAULT_INGRESS_ZONE).strip()
    if profile not in VPN_CLIENT_PROFILES:
        return jsonify({"ok": False, "error": "unsupported profile"}), 400
    try:
        ingress_zone = validate_identifier(ingress_zone)
    except ValidationError:
        return jsonify({"ok": False, "error": "invalid ingress zone name"}), 400
    if enabled and ingress_zone not in _zone_names():
        return jsonify({"ok": False, "error": "ingress zone not found"}), 400

    result = _apply_vpn_client_passthrough(profile, enabled, ingress_zone)
    return jsonify(result), (200 if result.get("ok") else 500)


@bp.route("/api/services-available", methods=["GET"])
@login_required
def services_available():
    """All firewalld service definitions installed on the system."""
    res = sudo_run(["firewall-cmd", "--get-services"])
    if not res.ok:
        return jsonify({"services": [], "error": res.stderr.strip()})
    return jsonify({"services": sorted(res.stdout.split())})


@bp.route("/api/ipsets", methods=["GET"])
@login_required
def list_ipsets():
    """All permanent firewalld ipsets for source selection."""
    res = sudo_run(["firewall-cmd", "--permanent", "--get-ipsets"])
    if not res.ok:
        return jsonify({"ipsets": [], "error": res.stderr.strip()})
    items = []
    for name in sorted(res.stdout.split()):
        count = None
        entries = sudo_run(["firewall-cmd", "--permanent", "--ipset", name, "--get-entries"])
        if entries.ok:
            count = len([line for line in entries.stdout.splitlines() if line.strip()])
        items.append({"name": name, "source": f"ipset:{name}", "entry_count": count})
    return jsonify({"ipsets": items})


_DIRECT_IDENT_RE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")


@bp.route("/api/direct-rules", methods=["GET", "POST", "DELETE"])
@login_required
@csrf_protect
def direct_rules():
    """List / add / remove firewalld direct rules (global; not per-zone)."""
    if request.method == "GET":
        res = sudo_run(["firewall-cmd", "--direct", "--get-all-rules"])
        if not res.ok:
            return jsonify({"rules": [], "error": res.stderr.strip()})
        rules: list[dict] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=4)
            if len(parts) >= 5:
                rules.append({
                    "ipv": parts[0], "table": parts[1], "chain": parts[2],
                    "priority": parts[3], "args": parts[4], "raw": line,
                })
            else:
                rules.append({"raw": line, "ipv": "", "table": "", "chain": "", "priority": "", "args": line})
        return jsonify({"rules": rules})

    # POST / DELETE
    payload = request.get_json(force=True, silent=True) or {}
    ipv = str(payload.get("ipv", ""))
    table = str(payload.get("table", ""))
    chain = str(payload.get("chain", ""))
    priority_raw = payload.get("priority", 0)
    args_str = str(payload.get("args", ""))

    if ipv not in ("ipv4", "ipv6", "eb"):
        return jsonify({"error": "ipv must be ipv4, ipv6, or eb"}), 400
    if not _DIRECT_IDENT_RE.match(table):
        return jsonify({"error": "invalid table"}), 400
    if not _DIRECT_IDENT_RE.match(chain):
        return jsonify({"error": "invalid chain"}), 400
    try:
        priority = int(priority_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid priority"}), 400
    if not args_str.strip() or "\n" in args_str:
        return jsonify({"error": "args must be a single non-empty line"}), 400
    try:
        args_list = shlex.split(args_str)
    except ValueError as e:
        return jsonify({"error": f"failed to parse args: {e}"}), 400

    op = "--add-rule" if request.method == "POST" else "--remove-rule"
    cmd = ["firewall-cmd", "--permanent", "--direct", op, ipv, table, chain, str(priority), *args_list]
    res = sudo_run(cmd)
    if not res.ok:
        return jsonify({"ok": False, "error": (res.stderr or res.stdout).strip()}), 500
    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        return jsonify({"ok": False, "error": reload_output}), 500
    return jsonify({"ok": True})


@bp.route("/api/public-ipset-allowlist", methods=["GET", "POST"])
@login_required
@csrf_protect
def public_ipset_allowlist():
    """Switch WAN-facing public access to an ipset allowlist model.

    firewalld accepts source-based zones before interface-based zones. The
    implementation moves selected ipsets into an allow zone, mirrors the
    currently open public services/ports there, then closes those openings on
    public so non-allowlisted WAN sources hit the public DROP target.
    """
    if request.method == "GET":
        return jsonify(_allowlist_state())

    payload = request.get_json(force=True, silent=True) or {}
    ipsets = _normalize_ipsets(payload.get("ipsets") or [])
    allow_zone = str(payload.get("allow_zone") or "japan").strip() or "japan"
    remove_public_openings = bool(payload.get("remove_public_openings", True))
    try:
        allow_zone = validate_identifier(allow_zone)
    except ValidationError:
        return jsonify({"ok": False, "error": "invalid allow zone name"}), 400
    if not ipsets:
        return jsonify({"ok": False, "error": "at least one ipset is required"}), 400

    available = _available_ipset_names()
    missing = [name for name in ipsets if name not in available]
    if missing:
        return jsonify({"ok": False, "error": "missing ipsets: " + ", ".join(missing)}), 400

    result = _apply_public_ipset_allowlist(allow_zone, ipsets, remove_public_openings)
    status = 200 if result.get("ok") else 500
    return jsonify(result), status


@bp.route("/api/wan-hardening", methods=["GET", "POST"])
@login_required
@csrf_protect
def wan_hardening():
    """Report or apply SyncA-managed WAN hardening direct rules."""
    if request.method == "GET":
        expected = _build_wan_hardening_rules()
        existing = _direct_rule_lines(permanent=True)
        rules_present = sum(1 for rule in expected if _direct_rule_raw(rule) in existing)
        return jsonify({
            "rules_expected": len(expected),
            "rules_present": rules_present,
            "rules_missing": max(len(expected) - rules_present, 0),
            "applied": bool(expected) and rules_present == len(expected),
            "wan_interfaces": _wan_interfaces(),
            "drop_zone_sources": _drop_zone_ipsets(),
        })

    expected = _build_wan_hardening_rules()
    existing_direct = _direct_rule_lines(permanent=True)
    applied: list[str] = []
    errors: list[str] = []
    for rule in expected:
        added, error = _ensure_direct_rule(rule, existing_direct)
        if error:
            errors.append(error)
        elif added:
            applied.append(_direct_rule_raw(rule))
    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        errors.append(reload_output)
    return jsonify({
        "ok": not errors,
        "applied": applied,
        "applied_count": len(applied),
        "errors": errors,
        "wan_interfaces": _wan_interfaces(),
    }), (200 if not errors else 500)


@bp.route("/api/reload", methods=["POST"])
@login_required
@csrf_protect
def reload_firewall():
    ok, output = _reload_firewall_and_refresh_fail2ban()
    return jsonify({"ok": ok, "output": output})


# ---- helpers -----------------------------------------------------------

def _apply_forward_port_change(zone: str, spec: str, port: str, proto: str, add: bool) -> dict:
    """Apply a DNAT forward-port and keep the zone input opening in sync."""
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return {"ok": False, "error": "invalid zone name"}

    errors: list[str] = []
    changed: list[str] = []
    op = "--add-forward-port" if add else "--remove-forward-port"
    _collect_firewall_change(
        ["firewall-cmd", "--permanent", "--zone", zone, f"{op}={spec}"],
        changed, errors, ignore_missing=not add,
    )
    port_token = f"{port}/{proto}"
    if add:
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", zone, "--add-port", port_token],
            changed, errors,
        )
    elif not _zone_has_forward_port(zone, port, proto):
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", zone, "--remove-port", port_token],
            changed, errors, ignore_missing=True,
        )

    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        errors.append(reload_output)
    return {"ok": not errors, "changed": changed, "errors": errors}


def _apply_scoped_forward_port_change(zone: str, rule: dict, add: bool) -> dict:
    """Apply an incoming-IP/NIC scoped port-forward as managed direct rules."""
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return {"ok": False, "error": "invalid zone name"}

    errors: list[str] = []
    changed: list[str] = []
    direct_rules = _scoped_forward_port_rules(zone, rule)
    existing_direct = _direct_rule_lines(permanent=True)

    if add:
        for direct_rule in direct_rules:
            added, error = _ensure_direct_rule(direct_rule, existing_direct)
            if error:
                errors.append(error)
            elif added:
                changed.append("direct " + _direct_rule_raw(direct_rule))
    else:
        for direct_rule in direct_rules:
            removed, error = _remove_direct_rule(direct_rule, existing_direct)
            if error:
                errors.append(error)
            elif removed:
                changed.append("removed direct " + _direct_rule_raw(direct_rule))

    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        errors.append(reload_output)
    return {"ok": not errors, "changed": changed, "errors": errors}


def _zone_has_forward_port(zone: str, port: str, proto: str) -> bool:
    info = _describe_zone(zone, permanent=True)
    for item in info.get("forward_ports", []):
        if item.get("managed"):
            continue
        if item.get("port") == port and item.get("proto") == proto:
            return True
    return False


def _scoped_forward_port_rules(zone: str, rule: dict) -> list[dict]:
    comment = _forward_port_comment(zone, rule)
    nat_parts: list[str] = []
    forward_parts: list[str] = []
    if rule.get("interface"):
        nat_parts.extend(["-i", rule["interface"]])
        forward_parts.extend(["-i", rule["interface"]])
    if rule.get("inaddr"):
        nat_parts.extend(["-d", rule["inaddr"]])

    original_port = _iptables_port_match(rule["port"])
    forward_port = _iptables_port_match(rule.get("toport") or rule["port"])
    nat_prefix = (" ".join(nat_parts) + " ") if nat_parts else ""
    forward_prefix = (" ".join(forward_parts) + " ") if forward_parts else ""
    target = rule["toaddr"]
    if rule.get("toport"):
        target += ":" + rule["toport"]

    return _dedupe_direct_rules([
        _direct_rule(
            "ipv4", "nat", "PREROUTING", 0,
            f"{nat_prefix}-p {rule['proto']} --dport {original_port} "
            f"-m comment --comment {comment} -j DNAT --to-destination {target}",
        ),
        _direct_rule(
            "ipv4", "filter", "FORWARD", 0,
            f"{forward_prefix}-p {rule['proto']} -d {rule['toaddr']} --dport {forward_port} "
            f"-m comment --comment {comment} -j ACCEPT",
        ),
    ])


def _forward_port_comment(zone: str, rule: dict) -> str:
    values = [
        zone,
        rule["proto"],
        rule["port"],
        rule.get("toport") or "_",
        rule.get("toaddr") or "_",
        rule.get("interface") or "_",
        rule.get("inaddr") or "_",
    ]
    return "synca-forward-port:" + ":".join(values)


def _iptables_port_match(value: str) -> str:
    return value.replace("-", ":", 1)


def _scoped_forward_port_rows(zone: str | None = None, permanent: bool = True) -> list[dict]:
    rows: dict[tuple[str, str, str, str, str, str, str], dict] = {}
    for raw in _direct_rule_lines(permanent=permanent):
        if "synca-forward-port:" not in raw:
            continue
        m = FORWARD_PORT_COMMENT_RE.search(raw)
        if not m:
            continue
        row_zone, proto, port, toport, toaddr, interface, inaddr = m.groups()
        if zone and row_zone != zone:
            continue
        key = (row_zone, proto, port, toport, toaddr, interface, inaddr)
        normalized = {
            "zone": row_zone,
            "proto": proto,
            "port": port,
            "toport": "" if toport == "_" else toport,
            "toaddr": "" if toaddr == "_" else toaddr,
            "interface": "" if interface == "_" else interface,
            "inaddr": "" if inaddr == "_" else inaddr,
            "managed": True,
            "scope": "direct",
            "rules": [],
        }
        normalized["raw"] = _forward_port_display_spec(normalized)
        row = rows.setdefault(key, normalized)
        row["rules"].append(raw)
    return sorted(
        rows.values(),
        key=lambda item: (
            item["zone"],
            item.get("interface") or "",
            item.get("inaddr") or "",
            item["proto"],
            item["port"],
            item.get("toaddr") or "",
            item.get("toport") or "",
        ),
    )


def _forward_port_display_spec(rule: dict) -> str:
    spec = _forward_port_spec(rule)
    if rule.get("interface"):
        spec += f":interface={rule['interface']}"
    if rule.get("inaddr"):
        spec += f":inaddr={rule['inaddr']}"
    return spec


def _apply_protocol_forward_change(zone: str, proto: str, toaddr: str, add: bool) -> dict:
    """Add or remove a GRE/ESP/AH forward using permanent direct rules."""
    errors: list[str] = []
    changed: list[str] = []
    direct_rules = _protocol_forward_rules(zone, proto, toaddr)
    existing_direct = _direct_rule_lines(permanent=True)

    if add:
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", zone, "--add-protocol", proto],
            changed, errors,
        )
        for rule in direct_rules:
            added, error = _ensure_direct_rule(rule, existing_direct)
            if error:
                errors.append(error)
            elif added:
                changed.append("direct " + _direct_rule_raw(rule))
    else:
        for rule in direct_rules:
            removed, error = _remove_direct_rule(rule, existing_direct)
            if error:
                errors.append(error)
            elif removed:
                changed.append("removed direct " + _direct_rule_raw(rule))
        if not _protocol_forward_rows(zone, proto=proto):
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", "--zone", zone, "--remove-protocol", proto],
                changed, errors, ignore_missing=True,
            )

    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        errors.append(reload_output)
    return {"ok": not errors, "changed": changed, "errors": errors}


def _protocol_forward_rules(zone: str, proto: str, toaddr: str) -> list[dict]:
    comment = f"synca-protocol-forward:{zone}:{proto}:{toaddr}"
    rules: list[dict] = []
    interfaces = _zone_forward_interfaces(zone)
    for iface in interfaces or [""]:
        prefix = f"-i {iface} " if iface else ""
        rules.append(_direct_rule(
            "ipv4", "nat", "PREROUTING", 0,
            f"{prefix}-p {proto} -m comment --comment {comment} -j DNAT --to-destination {toaddr}",
        ))
        rules.append(_direct_rule(
            "ipv4", "filter", "FORWARD", 0,
            f"{prefix}-p {proto} -d {toaddr} -m comment --comment {comment} -j ACCEPT",
        ))
    return _dedupe_direct_rules(rules)


def _zone_forward_interfaces(zone: str) -> list[str]:
    info = _describe_zone(zone, permanent=True)
    interfaces: list[str] = []
    for iface in info.get("interfaces", []):
        if not iface or iface in interfaces:
            continue
        interfaces.append(iface)
        if iface.startswith("ppp") and "ppp+" not in interfaces:
            interfaces.append("ppp+")
    if interfaces:
        return interfaces
    if zone == "public":
        return _wan_interfaces()
    return []


def _protocol_forward_rows(zone: str | None = None, proto: str | None = None) -> list[dict]:
    rows: dict[tuple[str, str, str], dict] = {}
    for raw in _direct_rule_lines(permanent=True):
        if "synca-protocol-forward:" not in raw:
            continue
        m = PROTOCOL_FORWARD_COMMENT_RE.search(raw)
        if not m:
            continue
        row_zone, row_proto, toaddr = m.groups()
        if zone and row_zone != zone:
            continue
        if proto and row_proto != proto:
            continue
        key = (row_zone, row_proto, toaddr)
        row = rows.setdefault(key, {"zone": row_zone, "proto": row_proto, "toaddr": toaddr, "rules": []})
        row["rules"].append(raw)
    return sorted(rows.values(), key=lambda item: (item["zone"], item["proto"], item["toaddr"]))


def _vpn_client_passthrough_state() -> dict:
    supported, support_error = _policies_supported()
    zones = sorted(_zone_names())
    default_zone = VPN_CLIENT_DEFAULT_INGRESS_ZONE if VPN_CLIENT_DEFAULT_INGRESS_ZONE in zones else (zones[0] if zones else "")
    profiles: dict[str, dict] = {}
    helpers = _firewalld_list(["--get-helpers"])
    for key, cfg in VPN_CLIENT_PROFILES.items():
        policy = _policy_info(cfg["policy"]) if supported else {"exists": False}
        service = _service_info(cfg["service"])
        conflicts = _vpn_client_conflicts(cfg)
        service_ports = service.get("ports", [])
        service_protocols = service.get("protocols", [])
        service_helpers = service.get("helpers", [])
        policy_services = policy.get("services", [])
        ingress_zones = policy.get("ingress_zones", [])
        egress_zones = policy.get("egress_zones", [])
        required_helpers = cfg.get("helpers", [])
        enabled = bool(
            supported
            and policy.get("exists")
            and service.get("exists")
            and cfg["service"] in policy_services
            and all(port in service_ports for port in cfg.get("ports", []))
            and all(proto in service_protocols for proto in cfg.get("protocols", []))
            and all(helper in service_helpers for helper in required_helpers)
            and ingress_zones
            and "ANY" in egress_zones
        )
        profiles[key] = {
            "label": cfg["label"],
            "enabled": enabled,
            "policy": cfg["policy"],
            "service": cfg["service"],
            "service_exists": service.get("exists", False),
            "policy_exists": policy.get("exists", False),
            "service_ports": service_ports,
            "service_protocols": service_protocols,
            "service_helpers": service_helpers,
            "required_ports": cfg.get("ports", []),
            "required_protocols": cfg.get("protocols", []),
            "required_helpers": required_helpers,
            "helpers_available": all(helper in helpers for helper in required_helpers),
            "policy_services": policy_services,
            "ingress_zones": ingress_zones,
            "egress_zones": egress_zones,
            "conflict_protocols": cfg.get("conflict_protocols", []),
            "protocol_forward_conflicts": conflicts,
            "conflict_count": len(conflicts),
        }
    return {
        "supported": supported,
        "error": support_error,
        "default_ingress_zone": default_zone,
        "zones": zones,
        "profiles": profiles,
        "nf_conntrack_helper": _sysctl_value("net.netfilter.nf_conntrack_helper"),
    }


def _apply_vpn_client_passthrough(profile: str, enabled: bool, ingress_zone: str) -> dict:
    errors: list[str] = []
    changed: list[str] = []
    supported, support_error = _policies_supported()
    if not supported:
        return {"ok": False, "error": support_error or "firewalld policies are not supported"}
    cfg = VPN_CLIENT_PROFILES[profile]

    if enabled:
        missing_helpers = [helper for helper in cfg.get("helpers", []) if helper not in _firewalld_list(["--get-helpers"])]
        if missing_helpers:
            return {"ok": False, "error": "missing firewalld helpers: " + ", ".join(missing_helpers)}
        _ensure_vpn_client_service(cfg, changed, errors)
        _ensure_vpn_client_policy(cfg, ingress_zone, changed, errors)
    else:
        _remove_vpn_client_policy(cfg, changed, errors)
        _remove_vpn_client_service(cfg, changed, errors)

    if not errors:
        reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
        if not reload_ok:
            errors.append(reload_output)
        elif reload_output:
            changed.append(reload_output)
    state = _vpn_client_passthrough_state() if not errors else {}
    return {"ok": not errors, "changed": changed, "errors": errors, "state": state}


def _ensure_vpn_client_service(cfg: dict, changed: list[str], errors: list[str]) -> None:
    service = cfg["service"]
    if service not in _firewalld_list(["--permanent", "--get-services"]):
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", f"--new-service={service}"],
            changed, errors,
        )
    info = _service_info(service)
    for port in cfg.get("ports", []):
        if port not in info.get("ports", []):
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", f"--service={service}", f"--add-port={port}"],
                changed, errors,
            )
    for proto in cfg.get("protocols", []):
        if proto not in info.get("protocols", []):
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", f"--service={service}", f"--add-protocol={proto}"],
                changed, errors,
            )
    for helper in cfg.get("helpers", []):
        if helper not in info.get("helpers", []):
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", f"--service={service}", f"--add-helper={helper}"],
                changed, errors,
            )


def _ensure_vpn_client_policy(cfg: dict, ingress_zone: str, changed: list[str], errors: list[str]) -> None:
    policy = cfg["policy"]
    service = cfg["service"]
    if policy not in _policy_names():
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", f"--new-policy={policy}"],
            changed, errors,
        )
    info = _policy_info(policy)
    for zone in info.get("ingress_zones", []):
        if zone != ingress_zone:
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", f"--policy={policy}", f"--remove-ingress-zone={zone}"],
                changed, errors, ignore_missing=True,
            )
    if ingress_zone not in info.get("ingress_zones", []):
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", f"--policy={policy}", f"--add-ingress-zone={ingress_zone}"],
            changed, errors,
        )
    if "ANY" not in info.get("egress_zones", []):
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", f"--policy={policy}", "--add-egress-zone=ANY"],
            changed, errors,
        )
    if service not in info.get("services", []):
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", f"--policy={policy}", f"--add-service={service}"],
            changed, errors,
        )


def _remove_vpn_client_policy(cfg: dict, changed: list[str], errors: list[str]) -> None:
    policy = cfg["policy"]
    if policy not in _policy_names():
        return
    _collect_firewall_change(
        ["firewall-cmd", "--permanent", f"--delete-policy={policy}"],
        changed, errors, ignore_missing=True,
    )


def _remove_vpn_client_service(cfg: dict, changed: list[str], errors: list[str]) -> None:
    service = cfg["service"]
    if service not in _firewalld_list(["--permanent", "--get-services"]):
        return
    _collect_firewall_change(
        ["firewall-cmd", "--permanent", f"--delete-service={service}"],
        changed, errors, ignore_missing=True,
    )


def _vpn_client_conflicts(cfg: dict) -> list[dict]:
    rows: list[dict] = []
    for proto in cfg.get("conflict_protocols", []):
        rows.extend(_protocol_forward_rows(proto=proto))
    return sorted(rows, key=lambda item: (item["zone"], item["proto"], item["toaddr"]))


def _policies_supported() -> tuple[bool, str]:
    res = sudo_run(["firewall-cmd", "--permanent", "--get-policies"])
    if res.ok:
        return True, ""
    return False, (res.stderr or res.stdout).strip()


def _policy_names() -> set[str]:
    res = sudo_run(["firewall-cmd", "--permanent", "--get-policies"])
    return set(res.stdout.split()) if res.ok else set()


def _firewalld_list(args: list[str]) -> set[str]:
    res = sudo_run(["firewall-cmd", *args])
    return set(res.stdout.split()) if res.ok else set()


def _service_info(service: str) -> dict:
    if service not in _firewalld_list(["--permanent", "--get-services"]):
        return {"exists": False, "ports": [], "protocols": [], "helpers": []}
    return {
        "exists": True,
        "ports": sorted(_firewalld_list(["--permanent", f"--service={service}", "--get-ports"])),
        "protocols": sorted(_firewalld_list(["--permanent", f"--service={service}", "--get-protocols"])),
        "helpers": sorted(_firewalld_list(["--permanent", f"--service={service}", "--get-service-helpers"])),
    }


def _policy_info(policy: str) -> dict:
    if policy not in _policy_names():
        return {"exists": False, "ingress_zones": [], "egress_zones": [], "services": []}
    res = sudo_run(["firewall-cmd", "--permanent", f"--policy={policy}", "--list-all"])
    info = {"exists": True, "ingress_zones": [], "egress_zones": [], "services": []}
    if not res.ok:
        info["error"] = (res.stderr or res.stdout).strip()
        return info
    for line in res.stdout.splitlines():
        s = line.strip()
        if s.startswith("ingress-zones:"):
            info["ingress_zones"] = s.split(":", 1)[1].split()
        elif s.startswith("egress-zones:"):
            info["egress_zones"] = s.split(":", 1)[1].split()
        elif s.startswith("services:"):
            info["services"] = s.split(":", 1)[1].split()
    return info


def _sysctl_value(name: str) -> str:
    res = sudo_run(["sysctl", "-n", name])
    return res.stdout.strip() if res.ok else ""


def _remove_direct_rule(rule: dict, existing: set[str] | None = None) -> tuple[bool, str | None]:
    raw = _direct_rule_raw(rule)
    if existing is None:
        existing = _direct_rule_lines(permanent=True)
    if raw not in existing:
        return False, None
    try:
        args_list = shlex.split(rule["args"])
    except ValueError as e:
        return False, f"failed to parse managed direct rule: {e}"
    cmd = [
        "firewall-cmd", "--permanent", "--direct", "--remove-rule",
        rule["ipv"], rule["table"], rule["chain"], str(rule["priority"]), *args_list,
    ]
    res = sudo_run(cmd)
    if not res.ok:
        output = (res.stderr or res.stdout).strip()
        if "not in list" not in output:
            return False, output
    existing.discard(raw)
    return True, None


def _allowlist_state() -> dict:
    public = _describe_zone("public", permanent=True)
    allow_zone = "japan" if "japan" in _zone_names() else ""
    allow = _describe_zone(allow_zone, permanent=True) if allow_zone else {}
    public_sources = public.get("sources", []) if isinstance(public, dict) else []
    allow_sources = allow.get("sources", []) if isinstance(allow, dict) else []
    return {
        "public_target": public.get("target") if isinstance(public, dict) else None,
        "public_sources": public_sources,
        "allow_zone": allow_zone,
        "allow_zone_sources": allow_sources,
        "available_ipsets": sorted(_available_ipset_names()),
        "enabled": (
            public.get("target") == "DROP"
            and bool([s for s in allow_sources if s.startswith("ipset:")])
            and not _zone_public_openings(public)
        ) if isinstance(public, dict) else False,
    }


def _apply_public_ipset_allowlist(allow_zone: str, ipsets: list[str], remove_public_openings: bool) -> dict:
    errors: list[str] = []
    changed: list[str] = []
    zones = _zone_names()
    if allow_zone not in zones:
        res = sudo_run(["firewall-cmd", "--permanent", "--new-zone", allow_zone])
        if not res.ok and "NAME_CONFLICT" not in (res.stderr + res.stdout):
            return {"ok": False, "error": (res.stderr or res.stdout).strip()}
        changed.append(f"created zone {allow_zone}")

    public = _describe_zone("public", permanent=True)
    services = list(public.get("services", []))
    ports = list(public.get("ports", []))
    forward_ports = list(public.get("forward_ports", []))

    for cmd in (
        ["firewall-cmd", "--permanent", "--zone", "public", "--set-target=DROP"],
        ["firewall-cmd", "--permanent", "--zone", allow_zone, "--set-target=default"],
    ):
        _collect_firewall_change(cmd, changed, errors)

    for name in ipsets:
        source = f"ipset:{name}"
        _remove_source_from_other_zones(source, allow_zone, changed, errors)
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", allow_zone, "--add-source", source],
            changed, errors,
        )

    for service in services:
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", allow_zone, "--add-service", service],
            changed, errors,
        )
        if remove_public_openings:
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", "--zone", "public", "--remove-service", service],
                changed, errors, ignore_missing=True,
            )
    for port in ports:
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", allow_zone, "--add-port", port],
            changed, errors,
        )
        if remove_public_openings:
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", "--zone", "public", "--remove-port", port],
                changed, errors, ignore_missing=True,
            )
    for fp in forward_ports:
        if fp.get("managed"):
            continue
        spec = _forward_port_spec(fp)
        if not spec:
            continue
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", allow_zone, f"--add-forward-port={spec}"],
            changed, errors,
        )
        if remove_public_openings:
            _collect_firewall_change(
                ["firewall-cmd", "--permanent", "--zone", "public", f"--remove-forward-port={spec}"],
                changed, errors, ignore_missing=True,
            )

    _remove_allowlist_drop_guards(ipsets, changed, errors)
    existing_direct = _direct_rule_lines(permanent=True)
    for rule in _build_drop_zone_guard_rules():
        added, error = _ensure_direct_rule(rule, existing_direct)
        if error:
            errors.append(error)
        elif added:
            changed.append("direct " + _direct_rule_raw(rule))

    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        errors.append(reload_output)
    return {"ok": not errors, "changed": changed, "errors": errors}


def _remove_source_from_other_zones(source: str, keep_zone: str, changed: list[str], errors: list[str]) -> None:
    """Move a source into one zone without leaving it unassigned on ZONE_CONFLICT."""
    for zone in sorted(_zone_names()):
        if zone == keep_zone:
            continue
        info = _describe_zone(zone, permanent=True)
        if source not in info.get("sources", []):
            continue
        _collect_firewall_change(
            ["firewall-cmd", "--permanent", "--zone", zone, "--remove-source", source],
            changed, errors, ignore_missing=True,
        )


def _remove_allowlist_drop_guards(ipsets: list[str], changed: list[str], errors: list[str]) -> None:
    """Remove stale guard rules that accidentally DROP selected allow-list ipsets."""
    selected = set(ipsets)
    for raw in sorted(_direct_rule_lines(permanent=True)):
        if "synca-drop-zone-guard" not in raw:
            continue
        try:
            parts = shlex.split(raw)
        except ValueError:
            continue
        if "--match-set" not in parts:
            continue
        idx = parts.index("--match-set")
        if idx + 1 >= len(parts) or parts[idx + 1] not in selected:
            continue
        res = sudo_run(["firewall-cmd", "--permanent", "--direct", "--remove-rule", *parts])
        if res.ok:
            changed.append("removed stale direct " + raw)
        else:
            output = (res.stderr or res.stdout).strip()
            if "not in list" not in output:
                errors.append(output or "failed to remove stale direct " + raw)


def _reload_firewall_and_refresh_fail2ban() -> tuple[bool, str]:
    """Reload firewalld and rebuild fail2ban firewallcmd-ipset runtime rules."""
    reload_res = sudo_run(["firewall-cmd", "--reload"])
    reload_output = (reload_res.stderr or reload_res.stdout).strip()
    if not reload_res.ok:
        return False, "reload failed: " + reload_output

    f2b_res = sudo_run([
        "/bin/bash", "-lc",
        "if systemctl is-enabled --quiet fail2ban 2>/dev/null; then systemctl restart fail2ban; fi",
    ])
    f2b_output = (f2b_res.stderr or f2b_res.stdout).strip()
    if not f2b_res.ok:
        return False, "fail2ban refresh failed after firewalld reload: " + f2b_output
    return True, reload_output or f2b_output


def _collect_firewall_change(cmd: list[str], changed: list[str], errors: list[str], ignore_missing: bool = False) -> None:
    res = sudo_run(cmd)
    output = (res.stderr or res.stdout).strip()
    if res.ok:
        changed.append(" ".join(shlex.quote(part) for part in cmd))
        return
    if ignore_missing and any(token in output for token in ("NOT_ENABLED", "INVALID_ENTRY", "ZONE_ALREADY_SET")):
        return
    if any(token in output for token in ("ALREADY_ENABLED", "ZONE_ALREADY_SET")):
        return
    errors.append(output or "failed: " + " ".join(cmd))


def _zone_public_openings(zone_info: dict) -> bool:
    return bool(zone_info.get("services") or zone_info.get("ports") or zone_info.get("forward_ports"))


def _available_ipset_names() -> set[str]:
    res = sudo_run(["firewall-cmd", "--permanent", "--get-ipsets"])
    return set(res.stdout.split()) if res.ok else set()


def _zone_names() -> set[str]:
    res = sudo_run(["firewall-cmd", "--get-zones"])
    return set(res.stdout.split()) if res.ok else set()


def _normalize_ipsets(raw) -> list[str]:
    if isinstance(raw, str):
        values = [part.strip() for part in raw.replace(",", " ").split()]
    else:
        values = [str(part).strip() for part in raw]
    out: list[str] = []
    for value in values:
        name = value[6:] if value.startswith("ipset:") else value
        if re.match(r"^[A-Za-z0-9_-]{1,64}$", name) and name not in out:
            out.append(name)
    return out


def _forward_port_spec(fp: dict) -> str:
    port = fp.get("port", "")
    proto = fp.get("proto", "")
    if not port or not proto:
        return ""
    spec = f"port={port}:proto={proto}"
    if fp.get("toport"):
        spec += f":toport={fp['toport']}"
    if fp.get("toaddr"):
        spec += f":toaddr={fp['toaddr']}"
    return spec


def _wan_interfaces() -> list[str]:
    res = sudo_run(["/bin/bash", "-lc", "ip -o -4 route show default | awk '{print $5}' | sort -u"])
    interfaces = [line.strip() for line in res.stdout.splitlines() if line.strip()] if res.ok else []
    out: list[str] = []
    for iface in interfaces:
        if iface not in out:
            out.append(iface)
        if iface.startswith("ppp") and "ppp+" not in out:
            out.append("ppp+")
    return out or ["ppp+", "wan0"]


def _drop_zone_ipsets() -> list[str]:
    res = sudo_run(["firewall-cmd", "--permanent", "--zone", "drop", "--list-sources"])
    if not res.ok:
        return []
    return _normalize_ipsets([source for source in res.stdout.split() if source.startswith("ipset:")])


def _build_drop_zone_guard_rules(ipsets: list[str] | None = None) -> list[dict]:
    names = ipsets or _drop_zone_ipsets()
    rules: list[dict] = []
    for iface in _wan_interfaces():
        for name in names:
            rules.append(_direct_rule(
                "ipv4", "filter", "INPUT", -30,
                f"-i {iface} -m set --match-set {name} src -m comment --comment synca-drop-zone-guard -j DROP",
            ))
    return rules


def _build_wan_hardening_rules() -> list[dict]:
    rules = _build_drop_zone_guard_rules()
    spoofed_sources = [
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    ]
    stealth_flags = [
        "ALL NONE", "ALL ALL", "ALL FIN,URG,PSH", "SYN,FIN SYN,FIN",
        "SYN,RST SYN,RST", "FIN,RST FIN,RST",
    ]
    icmp_types = [
        "timestamp-request", "timestamp-reply", "address-mask-request",
        "address-mask-reply", "redirect", "router-advertisement", "router-solicitation",
    ]
    for iface in _wan_interfaces():
        rules.append(_direct_rule("ipv4", "filter", "INPUT", -25, f"-i {iface} -m conntrack --ctstate INVALID -m comment --comment synca-wan-invalid -j DROP"))
        rules.append(_direct_rule("ipv4", "filter", "INPUT", -25, f"-i {iface} -m addrtype --dst-type BROADCAST -m comment --comment synca-wan-broadcast -j DROP"))
        rules.append(_direct_rule("ipv4", "filter", "INPUT", -25, f"-i {iface} -m addrtype --dst-type MULTICAST -m comment --comment synca-wan-multicast -j DROP"))
        rules.append(_direct_rule("ipv4", "filter", "INPUT", -24, f"-i {iface} -p icmp --icmp-type echo-request -m length --length 1000:65535 -m comment --comment synca-wan-ping-of-death -j DROP"))
        rules.append(_direct_rule("ipv4", "filter", "INPUT", -24, f"-i {iface} -p tcp --syn -m hashlimit --hashlimit-above 30/second --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name synca_synflood -m comment --comment synca-wan-synflood -j DROP"))
        for source in spoofed_sources:
            rules.append(_direct_rule("ipv4", "filter", "INPUT", -24, f"-i {iface} -s {source} -m comment --comment synca-wan-spoof -j DROP"))
        for flags in stealth_flags:
            rules.append(_direct_rule("ipv4", "filter", "INPUT", -24, f"-i {iface} -p tcp --tcp-flags {flags} -m comment --comment synca-wan-stealth -j DROP"))
        for icmp_type in icmp_types:
            rules.append(_direct_rule("ipv4", "filter", "INPUT", -23, f"-i {iface} -p icmp --icmp-type {icmp_type} -m comment --comment synca-wan-icmp-type -j DROP"))
    return _dedupe_direct_rules(rules)


def _direct_rule(ipv: str, table: str, chain: str, priority: int, args: str) -> dict:
    return {"ipv": ipv, "table": table, "chain": chain, "priority": str(priority), "args": args}


def _dedupe_direct_rules(rules: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for rule in rules:
        raw = _direct_rule_raw(rule)
        if raw in seen:
            continue
        seen.add(raw)
        out.append(rule)
    return out


def _direct_rule_raw(rule: dict) -> str:
    return f"{rule['ipv']} {rule['table']} {rule['chain']} {rule['priority']} {rule['args']}"


def _direct_rule_lines(permanent: bool) -> set[str]:
    cmd = ["firewall-cmd"]
    if permanent:
        cmd.append("--permanent")
    cmd.extend(["--direct", "--get-all-rules"])
    res = sudo_run(cmd)
    return {line.strip() for line in res.stdout.splitlines() if line.strip()} if res.ok else set()


def _ensure_direct_rule(rule: dict, existing: set[str] | None = None) -> tuple[bool, str | None]:
    raw = _direct_rule_raw(rule)
    if existing is None:
        existing = _direct_rule_lines(permanent=True)
    if raw in existing:
        return False, None
    try:
        args_list = shlex.split(rule["args"])
    except ValueError as e:
        return False, f"failed to parse managed direct rule: {e}"
    cmd = [
        "firewall-cmd", "--permanent", "--direct", "--add-rule",
        rule["ipv"], rule["table"], rule["chain"], str(rule["priority"]), *args_list,
    ]
    res = sudo_run(cmd)
    if not res.ok:
        return False, (res.stderr or res.stdout).strip()
    existing.add(raw)
    return True, None


def _apply_change(zone: str, op_args: list[str]) -> dict:
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return {"ok": False, "error": "invalid zone name"}
    res = sudo_run(["firewall-cmd", "--zone", zone, *op_args, "--permanent"])
    if not res.ok:
        return {"ok": False, "error": (res.stderr or res.stdout).strip()}
    reload_ok, reload_output = _reload_firewall_and_refresh_fail2ban()
    if not reload_ok:
        return {"ok": False, "error": reload_output}
    return {"ok": True}


def _parse_active(text: str) -> dict[str, list[str]]:
    active: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if not line:
            continue
        if not line.startswith(" ") and not line.startswith("\t"):
            current = line.strip()
            active[current] = []
        elif current is not None:
            active[current].append(line.strip())
    return active


def _describe_zone(zone: str, permanent: bool = False) -> dict:
    cmd = ["firewall-cmd"]
    if permanent:
        cmd.append("--permanent")
    cmd.extend(["--zone", zone, "--list-all"])
    res = sudo_run(cmd)
    if not res.ok:
        return {"error": (res.stderr or res.stdout).strip()}

    info: dict = {
        "zone": zone,
        "target": None,
        "interfaces": [],
        "sources": [],
        "services": [],
        "ports": [],
        "protocols": [],
        "masquerade": False,
        "forward_ports": [],
        "rich_rules": [],
    }
    for line in res.stdout.splitlines():
        s = line.strip()
        if s.startswith("target:"):
            info["target"] = s.split(":", 1)[1].strip()
        elif s.startswith("interfaces:"):
            info["interfaces"] = s.split(":", 1)[1].split()
        elif s.startswith("sources:"):
            info["sources"] = s.split(":", 1)[1].split()
        elif s.startswith("services:"):
            info["services"] = s.split(":", 1)[1].split()
        elif s.startswith("ports:"):
            info["ports"] = s.split(":", 1)[1].split()
        elif s.startswith("protocols:"):
            info["protocols"] = s.split(":", 1)[1].split()
        elif s.startswith("masquerade:"):
            info["masquerade"] = s.split(":", 1)[1].strip() == "yes"

    # forward-ports and rich-rules can be multi-line; use dedicated subcommands
    fp_cmd = ["firewall-cmd"]
    if permanent:
        fp_cmd.append("--permanent")
    fp_cmd.extend(["--zone", zone, "--list-forward-ports"])
    fp = sudo_run(fp_cmd)
    if fp.ok:
        info["forward_ports"] = _parse_forward_ports(fp.stdout)
    info["forward_ports"].extend(_scoped_forward_port_rows(zone, permanent=permanent))

    rr_cmd = ["firewall-cmd"]
    if permanent:
        rr_cmd.append("--permanent")
    rr_cmd.extend(["--zone", zone, "--list-rich-rules"])
    rr = sudo_run(rr_cmd)
    if rr.ok:
        info["rich_rules"] = [ln.rstrip() for ln in rr.stdout.splitlines() if ln.strip()]

    return info


def _parse_forward_ports(text: str) -> list[dict]:
    """Each line of `--list-forward-ports` is: port=PORT:proto=PROTO[:toport=P][:toaddr=A]"""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed: dict = {
            "raw": line,
            "managed": False,
            "scope": "firewalld",
            "interface": "",
            "inaddr": "",
        }
        for kv in line.split(":"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                parsed[k.strip()] = v.strip()
        out.append(parsed)
    return out
