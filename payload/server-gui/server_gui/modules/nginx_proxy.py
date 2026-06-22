"""Nginx reverse proxy management.

Owns vhost config files under /etc/nginx/conf.d/vhost-*.conf, generated from
a JSON model stored in CONFIG_DIR/nginx.json. Files NOT matching vhost-*.conf
are left untouched (existing handwritten vhosts are visible as 'unmanaged').

Apply pipeline:
  1. Render all managed vhosts to staging buffer
  2. Backup existing vhost-*.conf to .bak
  3. Write new content
  4. Remove obsolete vhost-*.conf (with backup)
  5. nginx -t  -- on failure, roll back from .bak
  6. systemctl reload nginx
"""
from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run, sudo_run
from ..validators import (
    ValidationError,
    validate_hostname,
    validate_hostname_or_ip,
    validate_identifier,
    validate_ipv4,
    validate_ipv4_cidr,
    validate_port,
    validate_size,
)

logger = logging.getLogger(__name__)

bp = Blueprint("nginx_proxy", __name__, url_prefix="/nginx")

VHOST_DIR = Path("/etc/nginx/conf.d")
VHOST_PREFIX = "vhost-"
VHOST_SUFFIX = ".conf"
MODULE_NAME = "nginx"
# Auxiliary file holding http-context limit_req_zone directives for any
# vhost that has WAF rate-limiting enabled. limit_req_zone must live in
# the http {} context, which means a separate file from per-vhost server
# blocks. The `zz-` prefix makes it sort last under conf.d (irrelevant for
# nginx semantics — just easier to skim with `ls`).
WAF_ZONES_FILE = VHOST_DIR / f"{VHOST_PREFIX}zz-waf-zones{VHOST_SUFFIX}"
WAF_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

# Bot UA preset categories. Selecting a category in the UI expands to the
# patterns below. Patterns are matched case-insensitively via nginx `~*`.
BOT_CATEGORIES: dict[str, dict] = {
    "scanners": {
        "label": "脆弱性スキャナ (sqlmap / nikto / nmap など)",
        "patterns": [
            "sqlmap", "nikto", "nmap", "masscan", "zgrab",
            "acunetix", "nessus", "qualys", "openvas", "wpscan",
            "dirbuster", "gobuster", "ffuf", "feroxbuster",
            "arachni", "skipfish", "w3af",
        ],
    },
    "aggressive_crawlers": {
        "label": "攻撃的クローラ (AhrefsBot / SemrushBot など)",
        "patterns": [
            "ahrefsbot", "semrushbot", "mj12bot", "dotbot",
            "petalbot", "blexbot", "seznambot", "megaindex",
            "serpstatbot", "barkrowler",
        ],
    },
    "scrapers": {
        "label": "スクレイパ系 (wget / libwww / python-requests 等)",
        "patterns": [
            "httrack", "webcopier", "offline explorer",
            "siteripper", "wget", "libwww-perl", "go-http-client",
            "python-requests", "python-urllib", "scrapy",
        ],
    },
    "headless_browsers": {
        "label": "ヘッドレスブラウザ (PhantomJS / Headless Chrome 等)",
        "patterns": [
            "phantomjs", "headlesschrome", "puppeteer",
            "playwright", "selenium",
        ],
    },
    "spam_bots": {
        "label": "スパム/コメント投稿系",
        "patterns": [
            "xrumer", "scrapebox", "gsa-crawler", "senuke",
            "comment-spambot",
        ],
    },
}

# Shared attack pattern maps emitted into the zones file. Patterns are
# nginx-flavour PCRE; matched case-insensitively against $request_uri.
# Patterns are kept conservative to avoid blocking legitimate traffic.
SQLI_PATTERNS: list[str] = [
    r"\bunion\s+select\b",
    r"\bselect\s+.{1,200}\bfrom\b",
    r"\bdrop\s+table\b",
    r"\binsert\s+into\b.{0,200}\bvalues\b",
    r"\b(or|and)\s+1\s*=\s*1\b",
    r"\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#)",
    r"/\*!\d+",
    r"\bsleep\s*\(\s*\d+\s*\)",
    r"\bbenchmark\s*\(",
    r"\bload_file\s*\(",
    r"\binformation_schema\b",
]

XSS_PATTERNS: list[str] = [
    r"<script[\s>]",
    r"javascript\s*:",
    r"on(load|error|click|mouseover|focus|submit)\s*=",
    r"<iframe[\s>]",
    r"<object[\s>]",
    r"<embed[\s>]",
    r"document\.cookie",
    r"document\.write",
    r"\beval\s*\(",
    r"alert\s*\(\s*['\"]",
]

PATH_TRAVERSAL_PATTERNS: list[str] = [
    r"\.\./",
    r"\.\.\\\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\\windows\\system32",
    r"/proc/self/environ",
]

# Dynamic module paths to probe when telling the UI whether ModSecurity is
# available. The first match wins; missing module → toggle disabled in UI.
MODSECURITY_MODULE_PATHS: list[str] = [
    "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so",
    "/usr/lib/nginx/modules/ngx_http_modsecurity_module.so",
]
MODSECURITY_RULES_FILE = "/etc/nginx/modsec/main.conf"

# Marker written as the first line of every file we generate. Files in
# /etc/nginx/conf.d/ that match `vhost-*.conf` but do NOT contain this marker
# (e.g. `vhost-server-gui.conf` installed by install.sh) are left alone and
# never auto-deleted by the apply pipeline.
GENERATED_MARKER = "# server-gui:auto-generated"

# Names we will not let the user create / import — they collide with
# files dropped by the installer.
RESERVED_VHOST_NAMES = {"server-gui"}


def register(app: Flask) -> None:
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default() -> dict:
    return {"backends": [], "vhosts": []}


# ----- views ------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("nginx.html", active_tab="nginx")


# ----- backends ---------------------------------------------------------

@bp.route("/api/backends", methods=["GET"])
@login_required
def list_backends():
    data = _store().load(MODULE_NAME, _default())
    return jsonify({"backends": data["backends"]})


@bp.route("/api/backends", methods=["POST"])
@login_required
@csrf_protect
def create_backend():
    try:
        new = _parse_backend(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    with _store().transaction(MODULE_NAME, _default()) as data:
        if any(b["name"] == new["name"] for b in data["backends"]):
            return jsonify({"error": f"backend name {new['name']!r} already exists"}), 409
        new["id"] = uuid.uuid4().hex
        data["backends"].append(new)
    return jsonify({"backend": new}), 201


@bp.route("/api/backends/<bid>", methods=["PUT"])
@login_required
@csrf_protect
def update_backend(bid: str):
    try:
        new = _parse_backend(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    with _store().transaction(MODULE_NAME, _default()) as data:
        for i, b in enumerate(data["backends"]):
            if b["id"] == bid:
                if any(other["name"] == new["name"] and other["id"] != bid for other in data["backends"]):
                    return jsonify({"error": "name collision"}), 409
                new["id"] = bid
                data["backends"][i] = new
                refreshed = dict(data)
                break
        else:
            return jsonify({"error": "not found"}), 404
    _apply_all(refreshed)
    return jsonify({"backend": new})


@bp.route("/api/backends/<bid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_backend(bid: str):
    with _store().transaction(MODULE_NAME, _default()) as data:
        for v in data["vhosts"]:
            for loc in v["locations"]:
                if loc.get("backend_id") == bid:
                    return jsonify({"error": f"backend used by vhost {v['name']!r}"}), 409
        before = len(data["backends"])
        data["backends"] = [b for b in data["backends"] if b["id"] != bid]
        if len(data["backends"]) == before:
            return jsonify({"error": "not found"}), 404
    return jsonify({"deleted": bid})


# ----- vhosts -----------------------------------------------------------

@bp.route("/api/vhosts", methods=["GET"])
@login_required
def list_vhosts():
    data = _store().load(MODULE_NAME, _default())
    return jsonify({
        "vhosts": data["vhosts"],
        "backends": data["backends"],
        "unmanaged": _scan_unmanaged_files(),
    })


@bp.route("/api/vhosts", methods=["POST"])
@login_required
@csrf_protect
def create_vhost():
    try:
        new = _parse_vhost(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    with _store().transaction(MODULE_NAME, _default()) as data:
        for vhost in data["vhosts"]:
            if vhost["name"] == new["name"]:
                if _same_vhost_payload(vhost, new):
                    return jsonify({"vhost": vhost, "already_exists": True}), 200
                return jsonify({"error": f"vhost name {new['name']!r} already exists"}), 409
        try:
            _check_backend_refs(new, data["backends"])
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400
        new["id"] = uuid.uuid4().hex
        data["vhosts"].append(new)
        refreshed = {"backends": list(data["backends"]), "vhosts": list(data["vhosts"])}
    try:
        _apply_all(refreshed)
    except RuntimeError as e:
        return jsonify({"error": str(e), "vhost": new}), 500
    return jsonify({"vhost": new}), 201


@bp.route("/api/vhosts/<vid>", methods=["PUT"])
@login_required
@csrf_protect
def update_vhost(vid: str):
    try:
        new = _parse_vhost(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    old_name: str | None = None
    with _store().transaction(MODULE_NAME, _default()) as data:
        try:
            _check_backend_refs(new, data["backends"])
        except ValidationError as e:
            return jsonify({"error": str(e)}), 400
        for i, v in enumerate(data["vhosts"]):
            if v["id"] == vid:
                if any(other["name"] == new["name"] and other["id"] != vid for other in data["vhosts"]):
                    return jsonify({"error": "name collision"}), 409
                old_name = v["name"]
                new["id"] = vid
                data["vhosts"][i] = new
                refreshed = {"backends": list(data["backends"]), "vhosts": list(data["vhosts"])}
                break
        else:
            return jsonify({"error": "not found"}), 404
    if old_name and old_name != new["name"]:
        _remove_vhost_file(old_name)
    try:
        _apply_all(refreshed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"vhost": new})


@bp.route("/api/vhosts/<vid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_vhost(vid: str):
    deleted_name: str | None = None
    with _store().transaction(MODULE_NAME, _default()) as data:
        for v in data["vhosts"]:
            if v["id"] == vid:
                deleted_name = v["name"]
                break
        if deleted_name is None:
            return jsonify({"error": "not found"}), 404
        data["vhosts"] = [v for v in data["vhosts"] if v["id"] != vid]
        refreshed = {"backends": list(data["backends"]), "vhosts": list(data["vhosts"])}
    _remove_vhost_file(deleted_name)
    try:
        _apply_all(refreshed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"deleted": vid})


@bp.route("/api/import", methods=["POST"])
@login_required
@csrf_protect
def import_vhost():
    """Import an existing /etc/nginx/conf.d/<file>.conf into GUI management.

    Pipeline:
      1. Parse the file (basic reverse-proxy subset)
      2. Auto-create or reuse backend(s) from each proxy_pass URL
      3. Add the vhost to the managed store
      4. Rename original .conf → .conf.imported so nginx won't load it
      5. Regenerate + nginx -t + reload
      6. Roll everything back on failure
    """
    payload = request.get_json(force=True, silent=True) or {}
    filename = str(payload.get("file", ""))
    if not filename.endswith(".conf") or "/" in filename or ".." in filename:
        return jsonify({"error": "invalid filename"}), 400
    if filename.startswith(VHOST_PREFIX):
        return jsonify({"error": "this file is already managed"}), 400

    source = VHOST_DIR / filename
    if not source.exists():
        return jsonify({"error": "file not found"}), 404
    try:
        content = source.read_text(encoding="utf-8")
    except OSError as e:
        return jsonify({"error": str(e)}), 500

    try:
        parsed_list = _parse_nginx_server_blocks(content)
    except Exception as e:  # parser bugs shouldn't crash the server
        logger.exception("parser crashed: %s", e)
        return jsonify({"error": f"parser error: {e}"}), 500
    if not parsed_list:
        return jsonify({"error": "no server block detected; manual edit required"}), 400

    vhost_data = parsed_list[0]  # import the first server block only
    base_name = re.sub(r"\.conf$", "", filename)
    candidate = re.sub(r"[^a-zA-Z0-9_\-]", "_", base_name)[:63] or "imported"
    if candidate in RESERVED_VHOST_NAMES:
        candidate = f"{candidate}-imported"
    vhost_data["name"] = candidate

    # Move proxy_pass strings into backend refs
    pending_proxy: list[tuple[dict, str]] = []
    for loc in vhost_data["locations"]:
        pp = loc.pop("proxy_pass_raw", None)
        if pp:
            pending_proxy.append((loc, pp))

    with _store().transaction(MODULE_NAME, _default()) as data:
        if any(v["name"] == vhost_data["name"] for v in data["vhosts"]):
            return jsonify({"error": f"vhost name {vhost_data['name']!r} already exists"}), 409
        for loc, pp in pending_proxy:
            backend = _resolve_or_create_backend(data, pp)
            if backend:
                loc["backend_id"] = backend["id"]
        vhost_data["id"] = uuid.uuid4().hex
        data["vhosts"].append(vhost_data)
        refreshed = {"backends": list(data["backends"]), "vhosts": list(data["vhosts"])}

    # Disable the original file so nginx -t doesn't complain about duplicate
    # listeners/default_server when we apply.
    disabled = source.with_suffix(".conf.imported")
    try:
        source.rename(disabled)
    except OSError as e:
        # Roll back the store change
        with _store().transaction(MODULE_NAME, _default()) as data:
            data["vhosts"] = [v for v in data["vhosts"] if v["id"] != vhost_data["id"]]
        return jsonify({"error": f"failed to rename original: {e}"}), 500

    try:
        _apply_all(refreshed)
    except RuntimeError as e:
        # Roll back: restore original, remove the import
        try:
            disabled.rename(source)
        except OSError:
            pass
        with _store().transaction(MODULE_NAME, _default()) as data:
            data["vhosts"] = [v for v in data["vhosts"] if v["id"] != vhost_data["id"]]
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "vhost": vhost_data,
        "original_renamed_to": disabled.name,
        "note": "original file disabled (renamed to .conf.imported)",
    }), 201


# ---- nginx vhost parser (basic) ---------------------------------------

def _parse_nginx_server_blocks(content: str) -> list[dict]:
    """Return a list of vhost dicts parsed from each `server { ... }` block.

    Handles the common reverse-proxy subset: listen, server_name,
    ssl_certificate*, client_max_body_size, set_real_ip_from,
    `location PATH { proxy_pass URL; proxy_set_header ...; }`.
    Anything else is ignored.
    """
    content = re.sub(r"#[^\n]*\n", "\n", content)
    return [_parse_server_body(body) for body in _extract_blocks(content, "server")
            if _parse_server_body(body)]


def _extract_blocks(content: str, block_name: str) -> list[str]:
    blocks: list[str] = []
    n = len(content)
    pos = 0
    pat = re.compile(rf"\b{re.escape(block_name)}\b\s*\{{")
    while pos < n:
        m = pat.search(content, pos)
        if not m:
            break
        start = m.end()
        depth = 1
        i = start
        while i < n and depth > 0:
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth == 0:
            blocks.append(content[start:i])
            pos = i + 1
        else:
            break
    return blocks


def _split_args(stmt: str) -> list[str]:
    tokens: list[str] = []
    n = len(stmt)
    pos = 0
    while pos < n:
        c = stmt[pos]
        if c.isspace():
            pos += 1
            continue
        if c in '"\'':
            quote = c
            end = pos + 1
            while end < n and stmt[end] != quote:
                end += 1
            tokens.append(stmt[pos + 1:end])
            pos = end + 1
        else:
            end = pos
            while end < n and not stmt[end].isspace() and stmt[end] not in '"\'':
                end += 1
            tokens.append(stmt[pos:end])
            pos = end
    return tokens


def _strip_time_unit(s: str) -> int:
    m = re.match(r"^(\d+)([smh]?)$", s)
    if not m:
        return 60
    val = int(m.group(1))
    unit = m.group(2)
    if unit == "m":
        val *= 60
    elif unit == "h":
        val *= 3600
    return val


def _parse_location_body(path: str, body: str) -> dict:
    proxy_pass: str | None = None
    headers: dict[str, str] = {}
    timeouts: dict[str, int] = {}
    websocket = False
    for stmt in re.split(r";", body):
        stmt = stmt.strip()
        if not stmt:
            continue
        parts = _split_args(stmt)
        if not parts:
            continue
        name, args = parts[0], parts[1:]
        if name == "proxy_pass" and args:
            proxy_pass = args[0]
        elif name == "proxy_set_header" and len(args) >= 2:
            headers[args[0]] = " ".join(args[1:])
        elif name == "proxy_connect_timeout" and args:
            timeouts["connect"] = _strip_time_unit(args[0])
        elif name == "proxy_send_timeout" and args:
            timeouts["send"] = _strip_time_unit(args[0])
        elif name == "proxy_read_timeout" and args:
            timeouts["read"] = _strip_time_unit(args[0])
        elif name == "proxy_http_version" and args and args[0] == "1.1":
            websocket = True  # heuristic
    return {
        "path": path,
        "type": "proxy",
        "backend_id": None,
        "proxy_pass_raw": proxy_pass,
        "websocket": websocket,
        "proxy_headers": headers or {
            "X-Real-IP": "$remote_addr",
            "X-Forwarded-For": "$proxy_add_x_forwarded_for",
            "X-Forwarded-Proto": "$scheme",
            "X-Forwarded-Host": "$host",
            "X-Forwarded-Port": "$server_port",
            "Host": "$http_host",
        },
        "timeouts": {
            "connect": timeouts.get("connect", 60),
            "send": timeouts.get("send", 60),
            "read": timeouts.get("read", 60),
        },
    }


def _parse_server_body(body: str) -> dict | None:
    # Pull out location blocks first
    locations: list[dict] = []
    loc_pat = re.compile(r"location\s+([^\s{}]+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}", re.DOTALL)
    def _take_location(m: re.Match) -> str:
        locations.append(_parse_location_body(m.group(1).strip(), m.group(2)))
        return ""
    rest = loc_pat.sub(_take_location, body)

    # Parse top-level directives
    directives: dict[str, list[list[str]]] = {}
    for stmt in re.split(r";", rest):
        stmt = stmt.strip()
        if not stmt:
            continue
        parts = _split_args(stmt)
        if not parts:
            continue
        directives.setdefault(parts[0], []).append(parts[1:])

    if "listen" not in directives:
        return None

    listens: list[dict] = []
    for args in directives["listen"]:
        if not args:
            continue
        first = args[0]
        # Skip IPv6-specific listeners (e.g. "[::]:443") — our renderer adds
        # an IPv6 listen automatically for every IPv4 one.
        if first.startswith("["):
            continue
        address = ""
        if ":" in first:
            address_part, port_part = first.rsplit(":", 1)
            if address_part not in ("", "*", "0.0.0.0"):
                try:
                    address = validate_ipv4(address_part)
                except ValidationError:
                    continue
        else:
            port_part = first
        try:
            port = int(port_part)
        except ValueError:
            continue
        flags = set(args[1:])
        listens.append({
            "address": address,
            "port": port,
            "ssl": "ssl" in flags,
            "http2": "http2" in flags,
            "default_server": "default_server" in flags,
        })
    if not listens:
        return None

    server_names_args = directives.get("server_name", [])
    server_names = [n for args in server_names_args for n in args] or ["_"]

    cert = (directives.get("ssl_certificate", [[None]])[0] or [None])[0]
    key = (directives.get("ssl_certificate_key", [[None]])[0] or [None])[0]
    ssl_cfg = None
    if cert and key:
        ssl_cfg = {
            "cert_path": cert.strip('"').strip("'"),
            "key_path": key.strip('"').strip("'"),
            "ciphers": "PROFILE=SYSTEM",
            "protocols": ["TLSv1.2", "TLSv1.3"],
        }

    body_size_args = directives.get("client_max_body_size", [["1m"]])[0]
    body_size = body_size_args[0] if body_size_args else "1m"

    real_ip_from = [a[0] for a in directives.get("set_real_ip_from", []) if a]

    if not locations:
        locations = [{
            "path": "/",
            "type": "proxy",
            "backend_id": None,
            "proxy_pass_raw": None,
            "websocket": False,
            "proxy_headers": {},
            "timeouts": {"connect": 60, "send": 60, "read": 60},
        }]

    return {
        "enabled": True,
        "listens": listens,
        "server_names": server_names,
        "ssl": ssl_cfg,
        "client_max_body_size": body_size,
        "set_real_ip_from": real_ip_from,
        "access_log": None,
        "error_log": None,
        "locations": locations,
    }


def _resolve_or_create_backend(data: dict, proxy_pass: str) -> dict | None:
    """Match proxy_pass URL to an existing backend or create a new one."""
    m = re.match(r"^(https?)://([^:/\s]+)(?::(\d+))?", proxy_pass.strip().rstrip("/"))
    if not m:
        return None
    scheme, host, port_str = m.group(1), m.group(2), m.group(3)
    port = int(port_str) if port_str else (443 if scheme == "https" else 80)
    for b in data["backends"]:
        if b["host"] == host and b["port"] == port and b["scheme"] == scheme:
            return b
    base = re.sub(r"[^a-zA-Z0-9_\-]", "_", host)[:32] or "imported"
    name = base
    suffix = 1
    while any(b["name"] == name for b in data["backends"]):
        name = f"{base}_{suffix}"
        suffix += 1
    new_b = {"id": uuid.uuid4().hex, "name": name, "host": host, "port": port, "scheme": scheme}
    data["backends"].append(new_b)
    return new_b


@bp.route("/api/apply", methods=["POST"])
@login_required
@csrf_protect
def apply_now():
    data = _store().load(MODULE_NAME, _default())
    try:
        _apply_all(data)
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True})


@bp.route("/api/test", methods=["GET"])
@login_required
def test_config():
    res = sudo_run(["nginx", "-t"])
    return jsonify({"ok": res.ok, "stderr": res.stderr.strip()})


@bp.route("/api/waf-status", methods=["GET"])
@login_required
def waf_status():
    """Tell the UI which WAF features the host actually supports.

    - bot_categories: preset list for the UA-block UI.
    - available_countries: 2-letter codes that have a corresponding
      firewalld `<cc>-ipv4` ipset. Empty if firewalld is not running or
      no country list has been imported via the GeoIP tab yet.
    - modsecurity_available: whether a ModSecurity dynamic module file
      exists. The UI greys out the toggle when false.
    - modsecurity_rules_file_exists: convenience check so the UI can
      warn the operator before enabling.
    """
    return jsonify({
        "bot_categories": [
            {"id": k, "label": v["label"], "count": len(v["patterns"])}
            for k, v in BOT_CATEGORIES.items()
        ],
        "available_countries": _list_geo_countries(),
        "modsecurity_available": _modsecurity_available(),
        "modsecurity_module_paths": MODSECURITY_MODULE_PATHS,
        "modsecurity_rules_file": MODSECURITY_RULES_FILE,
        "modsecurity_rules_file_exists": Path(MODSECURITY_RULES_FILE).exists(),
    })


# ----- parsing ----------------------------------------------------------

def _parse_backend(raw: dict) -> dict:
    name = validate_identifier(raw.get("name", ""))
    host = validate_hostname_or_ip(raw.get("host", ""))
    port = validate_port(raw.get("port", 80))
    scheme = raw.get("scheme", "http")
    if scheme not in ("http", "https"):
        raise ValidationError(f"invalid scheme: {scheme!r}")
    return {"name": name, "host": host, "port": port, "scheme": scheme}


def _parse_vhost(raw: dict) -> dict:
    name = validate_identifier(raw.get("name", ""))
    if name in RESERVED_VHOST_NAMES:
        raise ValidationError(f"vhost name {name!r} is reserved by the installer")
    server_names = raw.get("server_names")
    if not isinstance(server_names, list) or not server_names:
        raise ValidationError("server_names must be a non-empty list")
    server_names = [validate_hostname(s) if s != "_" else "_" for s in server_names]

    listens_raw = raw.get("listens")
    if not isinstance(listens_raw, list) or not listens_raw:
        raise ValidationError("listens must be a non-empty list")
    listens = []
    for li in listens_raw:
        address = str(li.get("address") or li.get("listen_ip") or "").strip()
        if address:
            address = validate_ipv4(address)
        listens.append({
            "address": address,
            "port": validate_port(li.get("port", 80)),
            "ssl": bool(li.get("ssl", False)),
            "http2": bool(li.get("http2", False)),
            "default_server": bool(li.get("default_server", False)),
        })
    any_ssl = any(l["ssl"] for l in listens)
    ssl_cfg = raw.get("ssl")
    if any_ssl:
        if not isinstance(ssl_cfg, dict):
            raise ValidationError("ssl config required when any listen is SSL")
        cert = ssl_cfg.get("cert_path")
        key = ssl_cfg.get("key_path")
        if not cert or not key or not cert.startswith("/") or not key.startswith("/"):
            raise ValidationError("ssl.cert_path and ssl.key_path required and must be absolute")
        ssl_cfg = {
            "cert_path": cert,
            "key_path": key,
            "ciphers": ssl_cfg.get("ciphers", "PROFILE=SYSTEM"),
            "protocols": ssl_cfg.get("protocols", ["TLSv1.2", "TLSv1.3"]),
        }
    else:
        ssl_cfg = None

    locs_raw = raw.get("locations")
    if not isinstance(locs_raw, list) or not locs_raw:
        raise ValidationError("locations must be a non-empty list")
    locations = []
    for loc in locs_raw:
        path = loc.get("path", "/")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValidationError(f"invalid location path: {path!r}")
        ltype = loc.get("type", "proxy")
        if ltype != "proxy":
            raise ValidationError(f"unsupported location type: {ltype!r}")
        headers = loc.get("proxy_headers")
        if not isinstance(headers, dict):
            headers = {
                "X-Real-IP": "$remote_addr",
                "X-Forwarded-For": "$proxy_add_x_forwarded_for",
                "X-Forwarded-Proto": "$scheme",
                "X-Forwarded-Host": "$host",
                "X-Forwarded-Port": "$server_port",
                "Host": "$http_host",
            }
        timeouts = loc.get("timeouts") or {}
        locations.append({
            "path": path,
            "type": "proxy",
            "backend_id": loc.get("backend_id"),
            "websocket": bool(loc.get("websocket", False)),
            "proxy_headers": {str(k): str(v) for k, v in headers.items()},
            "timeouts": {
                "connect": int(timeouts.get("connect", 60)),
                "send": int(timeouts.get("send", 60)),
                "read": int(timeouts.get("read", 60)),
            },
        })

    real_ip = raw.get("set_real_ip_from") or []
    real_ip = [validate_ipv4_cidr(c) for c in real_ip]

    body_size = raw.get("client_max_body_size") or "1m"
    body_size = validate_size(body_size)

    waf = _parse_waf(raw.get("waf") or {})

    return {
        "name": name,
        "enabled": bool(raw.get("enabled", True)),
        "listens": listens,
        "server_names": server_names,
        "ssl": ssl_cfg,
        "client_max_body_size": body_size,
        "set_real_ip_from": real_ip,
        "access_log": raw.get("access_log") or None,
        "error_log": raw.get("error_log") or None,
        "locations": locations,
        "waf": waf,
    }


def _parse_waf(raw: dict) -> dict:
    """WAF (Web Application Firewall) settings per vhost.

    Implemented mostly with nginx built-ins:
      - Rate limiting via `limit_req_zone` (http context) + `limit_req`
        (location context). Zone is named `waf_<vhost-name>`.
      - IP allow / deny lists rendered inside the location block. An
        allow list implies "deny all" for anything not listed.
      - HTTP method whitelist via `limit_except` — listed methods pass,
        others get 403.
      - User-Agent blocking: per-vhost `map $http_user_agent ...` in the
        http context + `if ($waf_ua_<name>) { return 403; }` in location.
        Block by category presets (sqlmap/nikto/etc.), explicit regex
        patterns, or empty UA.
      - SQLi / XSS / path traversal: shared `map $request_uri ...` blocks
        in the http context. Each vhost opts in per-attack.
      - Geo allow: per-vhost list of country codes; each is materialised
        as a `geo $waf_geo_<cc> { ... }` block fed from the firewalld
        `<cc>-ipv4` ipset. A combiner `map` per vhost ORs them together.
      - ModSecurity: per-vhost toggle that emits `modsecurity on;` +
        `modsecurity_rules_file` directives. Requires the dynamic module
        to be installed and loaded in nginx.conf (UI gates this).
      - Body size limit reuses `client_max_body_size` (existing field).

    Schema (additions over Phase 1 marked with ★):
      {
        "enabled":                 bool,
        "rate_limit_rps":          int,
        "rate_limit_burst":        int,
        "ip_allow":                [CIDR],
        "ip_deny":                 [CIDR],
        "allowed_methods":         [str],
      ★ "block_empty_ua":          bool,
      ★ "blocked_ua_patterns":     [str],          # nginx regex (case-insensitive)
      ★ "blocked_ua_categories":   [str],          # keys of BOT_CATEGORIES
      ★ "block_sql_injection":     bool,
      ★ "block_xss":               bool,
      ★ "block_path_traversal":    bool,
      ★ "geo_allow_countries":     [str],          # 2-letter codes, lowercase
      ★ "modsecurity":             bool,
      }
    """
    out = {
        "enabled": bool(raw.get("enabled", False)),
        "rate_limit_rps": 0,
        "rate_limit_burst": 0,
        "ip_allow": [],
        "ip_deny": [],
        "allowed_methods": [],
        "block_empty_ua": False,
        "blocked_ua_patterns": [],
        "blocked_ua_categories": [],
        "block_sql_injection": False,
        "block_xss": False,
        "block_path_traversal": False,
        "geo_allow_countries": [],
        "modsecurity": False,
    }
    if not isinstance(raw, dict):
        return out
    try:
        out["rate_limit_rps"] = max(0, int(raw.get("rate_limit_rps") or 0))
        out["rate_limit_burst"] = max(0, int(raw.get("rate_limit_burst") or 0))
    except (TypeError, ValueError):
        raise ValidationError("invalid waf rate-limit value (must be integer)")
    for field in ("ip_allow", "ip_deny"):
        items = raw.get(field) or []
        if isinstance(items, str):
            items = [s.strip() for s in items.replace(",", "\n").split() if s.strip()]
        if not isinstance(items, list):
            raise ValidationError(f"waf.{field} must be a list of CIDR strings")
        out[field] = [validate_ipv4_cidr(c) for c in items]
    methods = raw.get("allowed_methods") or []
    if isinstance(methods, str):
        methods = [m.strip().upper() for m in methods.replace(",", "\n").split() if m.strip()]
    if not isinstance(methods, list):
        raise ValidationError("waf.allowed_methods must be a list")
    for m in methods:
        if m.upper() not in WAF_ALLOWED_METHODS:
            raise ValidationError(f"unsupported HTTP method in waf.allowed_methods: {m!r}")
    out["allowed_methods"] = [m.upper() for m in methods]

    out["block_empty_ua"] = bool(raw.get("block_empty_ua", False))

    ua_patterns_raw = raw.get("blocked_ua_patterns") or []
    if isinstance(ua_patterns_raw, str):
        ua_patterns_raw = [s.strip() for s in ua_patterns_raw.splitlines() if s.strip()]
    if not isinstance(ua_patterns_raw, list):
        raise ValidationError("waf.blocked_ua_patterns must be a list")
    out["blocked_ua_patterns"] = [_validate_ua_pattern(p) for p in ua_patterns_raw]

    cats_raw = raw.get("blocked_ua_categories") or []
    if not isinstance(cats_raw, list):
        raise ValidationError("waf.blocked_ua_categories must be a list")
    for c in cats_raw:
        if c not in BOT_CATEGORIES:
            raise ValidationError(f"unknown bot category: {c!r}")
    out["blocked_ua_categories"] = list(cats_raw)

    out["block_sql_injection"] = bool(raw.get("block_sql_injection", False))
    out["block_xss"] = bool(raw.get("block_xss", False))
    out["block_path_traversal"] = bool(raw.get("block_path_traversal", False))

    ccs_raw = raw.get("geo_allow_countries") or []
    if isinstance(ccs_raw, str):
        ccs_raw = [s.strip() for s in ccs_raw.replace(",", "\n").split() if s.strip()]
    if not isinstance(ccs_raw, list):
        raise ValidationError("waf.geo_allow_countries must be a list")
    seen_cc: set[str] = set()
    ccs_out: list[str] = []
    for cc in ccs_raw:
        cc_norm = str(cc).strip().lower()
        if not re.fullmatch(r"[a-z]{2}", cc_norm):
            raise ValidationError(f"invalid country code: {cc!r}")
        if cc_norm not in seen_cc:
            seen_cc.add(cc_norm)
            ccs_out.append(cc_norm)
    out["geo_allow_countries"] = ccs_out

    out["modsecurity"] = bool(raw.get("modsecurity", False))
    return out


def _validate_ua_pattern(p) -> str:
    s = str(p).strip()
    if not s:
        raise ValidationError("UA pattern must not be empty")
    if len(s) > 200:
        raise ValidationError("UA pattern too long (>200 chars)")
    if re.search(r"[\x00-\x1f\x7f]", s):
        raise ValidationError("UA pattern contains control characters")
    # We render patterns inside `"..."` and escape backslash+quote at emit
    # time. Reject a literal `\n` line ending or `"` we couldn't escape.
    return s


def _waf_zone_name(vhost_name: str) -> str:
    """nginx zone names accept [A-Za-z0-9_] only — normalise the vhost name."""
    return "waf_" + re.sub(r"[^A-Za-z0-9_]", "_", vhost_name)


def _render_waf_zones(vhosts: list[dict]) -> str:
    """Generate every http-context support directive the per-vhost WAF
    blocks reference: limit_req_zone, attack pattern maps, per-vhost UA
    maps, geo country blocks, geo combiner maps.

    Returns "" when no vhost needs any of them — the caller deletes the
    file via the apply pipeline's obsolete-file path.
    """
    sections: list[str] = []
    enabled_vhosts = [v for v in vhosts if v.get("enabled", True) and (v.get("waf") or {}).get("enabled")]

    # --- 1. Rate-limit zones ------------------------------------------
    zone_lines: list[str] = []
    for v in enabled_vhosts:
        waf = v["waf"]
        rps = int(waf.get("rate_limit_rps") or 0)
        if rps > 0:
            zone_lines.append(
                f"limit_req_zone $binary_remote_addr "
                f"zone={_waf_zone_name(v['name'])}:10m rate={rps}r/s;"
            )
    if zone_lines:
        sections.append("# Rate-limit zones\n" + "\n".join(zone_lines))

    # --- 2. Shared attack pattern maps --------------------------------
    needs_sqli = any(v["waf"].get("block_sql_injection") for v in enabled_vhosts)
    needs_xss = any(v["waf"].get("block_xss") for v in enabled_vhosts)
    needs_pt = any(v["waf"].get("block_path_traversal") for v in enabled_vhosts)
    if needs_sqli or needs_xss or needs_pt:
        sections.append(_render_attack_maps(needs_sqli, needs_xss, needs_pt))

    # --- 3. Per-vhost UA blocking maps --------------------------------
    ua_maps: list[str] = []
    for v in enabled_vhosts:
        block = _render_ua_map(v["name"], v["waf"])
        if block:
            ua_maps.append(block)
    if ua_maps:
        sections.append("# Per-vhost User-Agent block maps\n" + "\n\n".join(ua_maps))

    # --- 4. Geo country blocks + per-vhost combiners ------------------
    countries: set[str] = set()
    for v in enabled_vhosts:
        for cc in v["waf"].get("geo_allow_countries") or []:
            countries.add(cc)
    if countries:
        geo_blocks: list[str] = []
        # Read each ipset once. If a country has no entries (ipset missing
        # or empty) we render an empty `geo` block — every request will
        # evaluate to 0 and the vhost's combiner will reject it. That's
        # the correct fail-closed behaviour for "geo allow".
        for cc in sorted(countries):
            entries = _read_ipset_entries(f"{cc}-ipv4")
            geo_blocks.append(_render_geo_block(cc, entries))
        sections.append("# Geo country IP blocks (from firewalld ipsets <cc>-ipv4)\n"
                        + "\n\n".join(geo_blocks))

        combiners: list[str] = []
        for v in enabled_vhosts:
            ccs = v["waf"].get("geo_allow_countries") or []
            if ccs:
                combiners.append(_render_geo_combiner(v["name"], ccs))
        if combiners:
            sections.append("# Per-vhost geo-allow combiners\n" + "\n\n".join(combiners))

    if not sections:
        return ""
    return "\n".join([
        GENERATED_MARKER,
        "# WAF runtime support (http context) for GUI-managed vhosts.",
        "",
        "\n\n".join(sections),
        "",
    ])


def _render_attack_maps(sqli: bool, xss: bool, pt: bool) -> str:
    parts: list[str] = []
    if sqli:
        parts.append(_render_pattern_map("$request_uri", "$waf_sqli", SQLI_PATTERNS))
    if xss:
        parts.append(_render_pattern_map("$request_uri", "$waf_xss", XSS_PATTERNS))
    if pt:
        parts.append(_render_pattern_map("$request_uri", "$waf_path_traversal", PATH_TRAVERSAL_PATTERNS))
    return "# Attack pattern maps (shared across vhosts)\n" + "\n\n".join(parts)


def _render_pattern_map(input_var: str, output_var: str, patterns: list[str]) -> str:
    lines = [f"map {input_var} {output_var} {{", "    default 0;"]
    for p in patterns:
        lines.append(f'    "~*{_escape_map_pattern(p)}" 1;')
    lines.append("}")
    return "\n".join(lines)


def _escape_map_pattern(p: str) -> str:
    """Escape characters that break nginx map patterns inside double quotes.

    nginx's map patterns are quoted strings; backslash and embedded double
    quote both need escaping. Backslash is doubled, double-quote becomes
    `\\"`. (Our SQLi/XSS patterns don't contain double quotes, but UA
    patterns supplied by the user might.)
    """
    return p.replace("\\", "\\\\").replace('"', '\\"')


def _render_ua_map(vhost_name: str, waf: dict) -> str:
    """Render the `map $http_user_agent $waf_ua_<vhost>` block for a vhost.

    Returns "" if the vhost has no UA-based rules — caller skips it.
    """
    patterns: list[str] = []
    block_empty = bool(waf.get("block_empty_ua"))
    for cat in waf.get("blocked_ua_categories") or []:
        defn = BOT_CATEGORIES.get(cat)
        if defn:
            patterns.extend(defn["patterns"])
    patterns.extend(waf.get("blocked_ua_patterns") or [])
    if not patterns and not block_empty:
        return ""
    var = f"$waf_ua_{_ident(vhost_name)}"
    lines = [f"map $http_user_agent {var} {{", "    default 0;"]
    if block_empty:
        lines.append('    ""    1;')
    seen: set[str] = set()
    for p in patterns:
        if p in seen:
            continue
        seen.add(p)
        lines.append(f'    "~*{_escape_map_pattern(p)}" 1;')
    lines.append("}")
    return "\n".join(lines)


def _render_geo_block(cc: str, entries: list[str]) -> str:
    var = f"$waf_geo_{_ident(cc)}"
    lines = [f"geo {var} {{", "    default 0;"]
    for e in entries:
        lines.append(f"    {e} 1;")
    lines.append("}")
    return "\n".join(lines)


def _render_geo_combiner(vhost_name: str, ccs: list[str]) -> str:
    """Produce a map that ORs the per-country geo variables together.

    Concatenates the per-country 0/1 values with `:` separators and uses
    nginx's `~1` regex check ("does the string contain a 1?") to set the
    combined variable. Cheaper than nested `if`s and avoids relying on
    arithmetic in the config.
    """
    combined = f"$waf_geo_allowed_{_ident(vhost_name)}"
    sources = ":".join(f"$waf_geo_{_ident(cc)}" for cc in ccs)
    return "\n".join([
        f'map "{sources}" {combined} {{',
        "    default 0;",
        '    "~1"    1;',
        "}",
    ])


def _ident(s: str) -> str:
    """Normalise a string to characters legal in an nginx variable name."""
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def _read_ipset_entries(ipset_name: str) -> list[str]:
    """Read CIDR entries for a firewalld ipset.

    Returns [] on any failure (firewalld not running, ipset missing,
    permission error) — the caller handles the empty case as "fail
    closed" for that country.
    """
    res = sudo_run(["firewall-cmd", "--permanent", f"--ipset={ipset_name}", "--get-entries"])
    if not res.ok:
        return []
    entries: list[str] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "/" in line:
            entries.append(line)
        elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
            entries.append(line + "/32")
    return entries


def _list_geo_countries() -> list[str]:
    """List 2-letter country codes available as firewalld `<cc>-ipv4` ipsets."""
    res = sudo_run(["firewall-cmd", "--permanent", "--get-ipsets"])
    if not res.ok:
        return []
    out: list[str] = []
    for tok in res.stdout.split():
        m = re.fullmatch(r"([a-z]{2})-ipv4", tok)
        if m:
            out.append(m.group(1))
    return sorted(set(out))


def _modsecurity_available() -> bool:
    for p in MODSECURITY_MODULE_PATHS:
        if Path(p).exists():
            return True
    return False


def _check_backend_refs(vhost: dict, backends: list) -> None:
    ids = {b["id"] for b in backends}
    for loc in vhost["locations"]:
        bid = loc.get("backend_id")
        if bid and bid not in ids:
            raise ValidationError(f"backend_id {bid!r} does not exist")


def _same_vhost_payload(existing: dict, requested: dict) -> bool:
    """Treat a repeated create request as successful when it already applied."""
    return {k: v for k, v in existing.items() if k != "id"} == requested


# ----- rendering --------------------------------------------------------

def _vhost_path(name: str) -> Path:
    return VHOST_DIR / f"{VHOST_PREFIX}{name}{VHOST_SUFFIX}"


def _render_vhost(vhost: dict, backends_by_id: dict[str, dict]) -> str:
    preamble = [
        GENERATED_MARKER,
        "# Managed by server-gui. Do not edit by hand — changes will be overwritten.",
        f"# vhost: {vhost['name']}",
    ]
    if not vhost["enabled"]:
        return "\n".join(preamble + ["# (disabled)", ""])
    lines: list[str] = list(preamble)
    lines.append("server {")
    for li in vhost["listens"]:
        flags = []
        if li["ssl"]:
            flags.append("ssl")
        if li["http2"]:
            flags.append("http2")
        if li["default_server"]:
            flags.append("default_server")
        suffix = (" " + " ".join(flags)) if flags else ""
        address = li.get("address") or ""
        if address:
            lines.append(f"    listen {address}:{li['port']}{suffix};")
        else:
            lines.append(f"    listen {li['port']}{suffix};")
            lines.append(f"    listen [::]:{li['port']}{suffix};")
    lines.append(f"    server_name {' '.join(vhost['server_names'])};")
    if vhost.get("ssl"):
        ssl = vhost["ssl"]
        lines.append(f"    ssl_certificate \"{ssl['cert_path']}\";")
        lines.append(f"    ssl_certificate_key \"{ssl['key_path']}\";")
        if ssl.get("ciphers"):
            lines.append(f"    ssl_ciphers {ssl['ciphers']};")
        if ssl.get("protocols"):
            lines.append(f"    ssl_protocols {' '.join(ssl['protocols'])};")
        # Use a per-vhost zone name so multiple SSL vhosts don't collide on size
        lines.append(f"    ssl_session_cache shared:ssl-{vhost['name']}:1m;")
        lines.append("    ssl_session_timeout 10m;")
    if vhost.get("client_max_body_size"):
        lines.append(f"    client_max_body_size {vhost['client_max_body_size']};")
    for cidr in vhost.get("set_real_ip_from") or []:
        lines.append(f"    set_real_ip_from {cidr};")
    if vhost.get("set_real_ip_from"):
        lines.append("    real_ip_header X-Forwarded-For;")
    if vhost.get("access_log"):
        lines.append(f"    access_log {vhost['access_log']};")
    if vhost.get("error_log"):
        lines.append(f"    error_log {vhost['error_log']};")
    # ---- WAF server-context directives (ModSecurity goes here, not in
    # location, so the same modsec rules apply to every location) ----
    waf_server = vhost.get("waf") or {}
    if waf_server.get("enabled") and waf_server.get("modsecurity"):
        lines.append("    modsecurity on;")
        lines.append(f"    modsecurity_rules_file {MODSECURITY_RULES_FILE};")
    lines.extend([
        "    location ^~ /.well-known/acme-challenge/ {",
        "        root /var/www/letsencrypt;",
        "        default_type \"text/plain\";",
        "        try_files $uri =404;",
        "    }",
    ])
    for loc in vhost["locations"]:
        backend = backends_by_id.get(loc.get("backend_id") or "")
        lines.append(f"    location {loc['path']} {{")
        # ---- WAF directives (location context) ----
        waf = vhost.get("waf") or {}
        if waf.get("enabled"):
            rps = int(waf.get("rate_limit_rps") or 0)
            if rps > 0:
                burst = int(waf.get("rate_limit_burst") or 0)
                clause = f" burst={burst} nodelay" if burst > 0 else ""
                lines.append(f"        limit_req zone={_waf_zone_name(vhost['name'])}{clause};")
            # ip_deny first, then explicit ip_allow (with implicit deny all)
            for cidr in waf.get("ip_deny") or []:
                lines.append(f"        deny {cidr};")
            if waf.get("ip_allow"):
                for cidr in waf["ip_allow"]:
                    lines.append(f"        allow {cidr};")
                lines.append("        deny all;")
            if waf.get("allowed_methods"):
                lines.append("        limit_except " + " ".join(waf["allowed_methods"]) + " {")
                lines.append("            deny all;")
                lines.append("        }")
            # User-Agent map — present only when the vhost actually has UA
            # rules (the zones renderer skips empty UA maps, so we must
            # mirror that condition here or we'd reference an undefined
            # variable and `nginx -t` would fail.)
            ua_active = (
                waf.get("block_empty_ua")
                or waf.get("blocked_ua_patterns")
                or waf.get("blocked_ua_categories")
            )
            if ua_active:
                lines.append(f"        if ($waf_ua_{_ident(vhost['name'])}) {{ return 403; }}")
            if waf.get("block_sql_injection"):
                lines.append("        if ($waf_sqli) { return 403; }")
            if waf.get("block_xss"):
                lines.append("        if ($waf_xss) { return 403; }")
            if waf.get("block_path_traversal"):
                lines.append("        if ($waf_path_traversal) { return 403; }")
            if waf.get("geo_allow_countries"):
                lines.append(
                    f"        if ($waf_geo_allowed_{_ident(vhost['name'])} != 1) {{ return 403; }}"
                )
        if backend:
            lines.append(f"        proxy_pass {backend['scheme']}://{backend['host']}:{backend['port']};")
        for hk, hv in (loc.get("proxy_headers") or {}).items():
            lines.append(f"        proxy_set_header {hk} {hv};")
        if loc.get("websocket"):
            lines.append("        proxy_http_version 1.1;")
            lines.append("        proxy_set_header Upgrade $http_upgrade;")
            lines.append("        proxy_set_header Connection \"upgrade\";")
            lines.append("        proxy_read_timeout 3600s;")
        timeouts = loc.get("timeouts") or {}
        if "connect" in timeouts:
            lines.append(f"        proxy_connect_timeout {timeouts['connect']}s;")
        if "send" in timeouts:
            lines.append(f"        proxy_send_timeout {timeouts['send']}s;")
        if "read" in timeouts and not loc.get("websocket"):
            lines.append(f"        proxy_read_timeout {timeouts['read']}s;")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _listen_signature(content: str) -> list[str]:
    """Extract listen directives that require a restart when they change."""
    return sorted(re.findall(r"^\s*listen\s+([^;]+);", content, flags=re.M))


# ----- apply pipeline ---------------------------------------------------

def _apply_all(data: dict) -> None:
    if not VHOST_DIR.exists():
        raise RuntimeError(f"{VHOST_DIR} does not exist; is nginx installed?")
    try:
        Path("/var/www/letsencrypt/.well-known/acme-challenge").mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise RuntimeError(f"failed to prepare ACME webroot: {e}") from e
    backends_by_id = {b["id"]: b for b in data["backends"]}
    desired_files: dict[Path, str] = {
        _vhost_path(v["name"]): _render_vhost(v, backends_by_id)
        for v in data["vhosts"]
    }
    # WAF zone declarations live in a separate file because limit_req_zone
    # must be in nginx http context. If no vhost has rate-limiting enabled,
    # the file is left out of desired_files and the apply pipeline's
    # obsolete-file removal cleans it up.
    zones_content = _render_waf_zones(data["vhosts"])
    if zones_content:
        desired_files[WAF_ZONES_FILE] = zones_content

    # CRITICAL: only consider files that carry our marker. Files like
    # `vhost-server-gui.conf` (dropped by the installer) match the same
    # filename pattern but are NOT ours — we must never delete them.
    existing = _list_marked_files()
    existing_listens: dict[Path, list[str]] = {}
    for p in existing:
        if p.name == WAF_ZONES_FILE.name:
            continue
        try:
            existing_listens[p] = _listen_signature(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            existing_listens[p] = []
    desired_listens = {
        p: _listen_signature(content)
        for p, content in desired_files.items()
        if p.name != WAF_ZONES_FILE.name
    }
    listener_changed = existing_listens != desired_listens
    backups: list[tuple[Path, Path]] = []
    obsolete = existing - set(desired_files.keys())

    try:
        for p in obsolete:
            bak = _backup(p)
            backups.append((p, bak))
            p.unlink()
        for p, content in desired_files.items():
            if p.exists():
                bak = _backup(p)
                backups.append((p, bak))
            p.write_text(content, encoding="utf-8")
            try:
                p.chmod(0o644)
            except OSError:
                pass

        res = sudo_run(["nginx", "-t"])
        if not res.ok:
            raise RuntimeError(f"nginx -t failed:\n{res.stderr}")

        _sync_firewalld_for_vhosts(data["vhosts"])

        action = "restart" if listener_changed else "reload"
        reload_res = sudo_run(["systemctl", action, "nginx"])
        if not reload_res.ok:
            raise RuntimeError(f"nginx {action} failed:\n{reload_res.stderr}")

    except Exception:
        # rollback: restore from backups, drop newly-created files
        original_paths = {p for p, _ in backups}
        for p, bak in backups:
            try:
                if bak.exists():
                    bak.replace(p)
            except OSError as e:
                logger.error("rollback failed for %s: %s", p, e)
        for p in desired_files.keys():
            if p not in original_paths and p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
        raise
    finally:
        for _, bak in backups:
            try:
                if bak.exists():
                    bak.unlink()
            except OSError:
                pass


def _list_marked_files() -> set[Path]:
    """Return only the vhost files that carry our GENERATED_MARKER."""
    if not VHOST_DIR.exists():
        return set()
    out: set[Path] = set()
    for p in VHOST_DIR.glob(f"{VHOST_PREFIX}*{VHOST_SUFFIX}"):
        try:
            with p.open("rb") as f:
                head = f.read(256).decode("utf-8", errors="ignore")
        except OSError:
            continue
        if GENERATED_MARKER in head:
            out.add(p)
    return out


def _backup(p: Path) -> Path:
    bak = p.with_suffix(p.suffix + ".bak")
    bak.write_bytes(p.read_bytes())
    return bak


def _sync_firewalld_for_vhosts(vhosts: list[dict]) -> None:
    """Open firewalld runtime/permanent ports required by enabled vhosts.

    This is intentionally add-only. Removing services automatically would be
    unsafe because unmanaged nginx/server-gui configs may share the same port.
    """
    if not run(["which", "firewall-cmd"]).ok:
        return
    zones = _public_firewalld_zones()
    if not zones:
        return
    ports: set[int] = set()
    for vhost in vhosts:
        if not vhost.get("enabled", True):
            continue
        for listen in vhost.get("listens") or []:
            try:
                ports.add(int(listen.get("port")))
            except (TypeError, ValueError):
                continue
    for zone in zones:
        for port in sorted(ports):
            if port == 80:
                _firewalld_add(zone, "--add-service=http")
            elif port == 443:
                _firewalld_add(zone, "--add-service=https")
            else:
                _firewalld_add(zone, f"--add-port={port}/tcp")


def _public_firewalld_zones() -> list[str]:
    zones = ["public"]
    res = sudo_run(["firewall-cmd", "--get-active-zones"], timeout=10)
    if not res.ok:
        return zones
    for raw in res.stdout.splitlines():
        line = raw.strip()
        if not line or raw.startswith((" ", "\t")):
            continue
        if line in {"public", "external", "japan"} and line not in zones:
            zones.append(line)
    return zones


def _firewalld_add(zone: str, option: str) -> None:
    for permanent in (False, True):
        cmd = ["firewall-cmd", "--zone", zone]
        if permanent:
            cmd.append("--permanent")
        cmd.append(option)
        sudo_run(cmd, timeout=15)


def _remove_vhost_file(name: str) -> None:
    p = _vhost_path(name)
    if p.exists():
        try:
            _backup(p)
            p.unlink()
        except OSError as e:
            logger.error("failed to remove %s: %s", p, e)


def _scan_unmanaged_files() -> list[dict]:
    if not VHOST_DIR.exists():
        return []
    result = []
    for p in sorted(VHOST_DIR.glob("*.conf")):
        if p.name.startswith(VHOST_PREFIX):
            continue
        try:
            stat = p.stat()
            result.append({"name": p.name, "size": stat.st_size})
        except OSError:
            continue
    return result
