"""firewalld management module.

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
  GET    /firewall/api/services-available          — all installed service defs
  GET    /firewall/api/direct-rules                — global direct rules (read-only)
  POST   /firewall/api/reload                      — firewall-cmd --reload
"""
from __future__ import annotations

import re

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..shell import sudo_run
from ..validators import ValidationError, validate_identifier, validate_ipv4

bp = Blueprint("firewall", __name__, url_prefix="/firewall")

PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?/(tcp|udp|sctp|dccp)$")
PORT_RANGE_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")
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

    Body:  {"port": "8080", "proto": "tcp", "toport": "80", "toaddr": "1.2.3.4"}
    Either 'toport' or 'toaddr' (or both) must be provided.
    """
    payload = request.get_json(force=True, silent=True) or {}
    port = str(payload.get("port", "")).strip()
    proto = str(payload.get("proto", "")).strip().lower()
    toport = str(payload.get("toport", "")).strip()
    toaddr = str(payload.get("toaddr", "")).strip()

    if not PORT_RANGE_RE.match(port):
        return jsonify({"error": "invalid port (e.g. 80 or 8000-8100)"}), 400
    if proto not in ("tcp", "udp", "sctp", "dccp"):
        return jsonify({"error": "proto must be one of: tcp, udp, sctp, dccp"}), 400
    if not toport and not toaddr:
        return jsonify({"error": "toport or toaddr must be specified"}), 400
    if toport and not PORT_RANGE_RE.match(toport):
        return jsonify({"error": "invalid toport"}), 400
    if toaddr:
        try:
            validate_ipv4(toaddr)
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400

    spec = f"port={port}:proto={proto}"
    if toport:
        spec += f":toport={toport}"
    if toaddr:
        spec += f":toaddr={toaddr}"

    op = "--add-forward-port" if request.method == "POST" else "--remove-forward-port"
    return jsonify(_apply_change(zone, [f"{op}={spec}"]))


@bp.route("/api/services-available", methods=["GET"])
@login_required
def services_available():
    """All firewalld service definitions installed on the system."""
    res = sudo_run(["firewall-cmd", "--get-services"])
    if not res.ok:
        return jsonify({"services": [], "error": res.stderr.strip()})
    return jsonify({"services": sorted(res.stdout.split())})


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
    import shlex
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
    reload_res = sudo_run(["firewall-cmd", "--reload"])
    if not reload_res.ok:
        return jsonify({"ok": False, "error": "reload failed: " + reload_res.stderr.strip()}), 500
    return jsonify({"ok": True})


@bp.route("/api/reload", methods=["POST"])
@login_required
@csrf_protect
def reload_firewall():
    res = sudo_run(["firewall-cmd", "--reload"])
    return jsonify({"ok": res.ok, "output": res.stdout or res.stderr})


# ---- helpers -----------------------------------------------------------

def _apply_change(zone: str, op_args: list[str]) -> dict:
    try:
        zone = validate_identifier(zone)
    except ValidationError:
        return {"ok": False, "error": "invalid zone name"}
    res = sudo_run(["firewall-cmd", "--zone", zone, *op_args, "--permanent"])
    if not res.ok:
        return {"ok": False, "error": (res.stderr or res.stdout).strip()}
    reload_res = sudo_run(["firewall-cmd", "--reload"])
    if not reload_res.ok:
        return {"ok": False, "error": "reload failed: " + reload_res.stderr.strip()}
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


def _describe_zone(zone: str) -> dict:
    res = sudo_run(["firewall-cmd", "--zone", zone, "--list-all"])
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
    fp = sudo_run(["firewall-cmd", "--zone", zone, "--list-forward-ports"])
    if fp.ok:
        info["forward_ports"] = _parse_forward_ports(fp.stdout)

    rr = sudo_run(["firewall-cmd", "--zone", zone, "--list-rich-rules"])
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
        parsed: dict = {"raw": line}
        for kv in line.split(":"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                parsed[k.strip()] = v.strip()
        out.append(parsed)
    return out
