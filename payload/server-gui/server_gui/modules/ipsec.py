"""StrongSwan (swanctl) read-only view.

Phase 1 scope:
  - List loaded connections (`swanctl --list-conns`)
  - List active SAs (`swanctl --list-sas`)
  - List config files under /etc/strongswan/swanctl/ and show raw content
  - Initiate / terminate a specific child SA (manual control)

Editing connection definitions, secrets, certificates is deferred to a
later Sprint — the file editor module can still be used in the meantime.
"""
from __future__ import annotations

import json
import logging
import ipaddress
import re
import shlex
import uuid
from pathlib import Path

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import sudo_run
from ..validators import ValidationError, validate_identifier

logger = logging.getLogger(__name__)

bp = Blueprint("ipsec", __name__, url_prefix="/ipsec")

SWANCTL_DIR = Path("/etc/strongswan/swanctl")
CONF_D = SWANCTL_DIR / "conf.d"
MAIN_CONF = SWANCTL_DIR / "swanctl.conf"
MANAGED_FILE = CONF_D / "server-gui.conf"
MODULE_NAME = "ipsec"


def _strip_noise(text: str) -> str:
    """Filter out the harmless strongswan startup warning so it doesn't
    clutter every API response on EL9.

      "plugin 'sqlite': failed to load - sqlite_plugin_create not found
       and no plugin file available"

    This is benign — strongswan ships a default plugin list that includes
    sqlite, but EL9 doesn't ship the sqlite plugin .so. Daemon and swanctl
    keep working without it. We drop the line so error toasts in the UI
    show the actual problem.
    """
    out_lines = [ln for ln in text.splitlines() if "plugin 'sqlite'" not in ln]
    return "\n".join(out_lines).strip()

# Strict allow-lists to keep generated config sane
_PROPOSAL_RE = re.compile(r"^[a-zA-Z0-9_\-,]{1,256}$")
_ADDR_RE = re.compile(r"^[%a-zA-Z0-9_\-./:,]{1,128}$")
_TS_RE = re.compile(r"^[a-zA-Z0-9_\-./:,\s]{1,256}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_\-@.:%/]{1,128}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./]{1,255}$")
_EAP_USER_RE = re.compile(r"^[A-Za-z0-9_\-.@]{1,128}$")
_START_ACTIONS = {"", "none", "trap", "start"}
_DPD_ACTIONS = {"", "none", "clear", "hold", "restart"}
_AUTH_TYPES = {"psk", "eap", "cert"}


def register(app: Flask) -> None:
    app.register_blueprint(bp)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("ipsec.html", active_tab="ipsec")


@bp.route("/api/status", methods=["GET"])
@login_required
def status():
    res = sudo_run(["systemctl", "is-active", "strongswan"])
    return jsonify({"strongswan_active": res.stdout.strip() == "active"})


@bp.route("/api/connections", methods=["GET"])
@login_required
def list_connections():
    """Parse `swanctl --list-conns` block output into structured records."""
    res = sudo_run(["swanctl", "--list-conns"])
    if not res.ok:
        return jsonify({"connections": [], "error": (res.stderr or res.stdout).strip()})
    return jsonify({"connections": _parse_conns(res.stdout)})


@bp.route("/api/sas", methods=["GET"])
@login_required
def list_sas():
    """Active Security Associations (current sessions)."""
    res = sudo_run(["swanctl", "--list-sas"])
    if not res.ok:
        return jsonify({"sas": [], "error": (res.stderr or res.stdout).strip()})
    return jsonify({"sas": _parse_sas(res.stdout), "raw": res.stdout})


@bp.route("/api/files", methods=["GET"])
@login_required
def list_files():
    """List swanctl config files (read-only metadata)."""
    items: list[dict] = []
    if MAIN_CONF.exists():
        items.append(_file_meta(MAIN_CONF))
    if CONF_D.exists():
        for p in sorted(CONF_D.glob("*.conf")):
            items.append(_file_meta(p))
    return jsonify({"files": items})


@bp.route("/api/files/content", methods=["GET"])
@login_required
def file_content():
    """Return the raw contents of a swanctl config file. Path must be within
    /etc/strongswan/swanctl/ for safety.
    """
    path_str = request.args.get("path", "")
    if not path_str:
        return jsonify({"error": "path required"}), 400
    try:
        p = Path(path_str).resolve()
    except OSError as e:
        return jsonify({"error": str(e)}), 400
    try:
        p.relative_to(SWANCTL_DIR.resolve())
    except (ValueError, OSError):
        return jsonify({"error": "path must be under /etc/strongswan/swanctl/"}), 403
    if not p.is_file():
        return jsonify({"error": "not a file"}), 404
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"path": str(p), "content": text, "size": p.stat().st_size})


@bp.route("/api/initiate", methods=["POST"])
@login_required
@csrf_protect
def initiate():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        child = validate_identifier(payload.get("child", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    res = sudo_run(["swanctl", "--initiate", "--child", child])
    return jsonify({"ok": res.ok, "output": _strip_noise(res.stdout + res.stderr)})


@bp.route("/api/terminate", methods=["POST"])
@login_required
@csrf_protect
def terminate():
    payload = request.get_json(force=True, silent=True) or {}
    target = payload.get("ike") or payload.get("child")
    flag = "--ike" if payload.get("ike") else "--child"
    if not target:
        return jsonify({"error": "ike or child required"}), 400
    try:
        target = validate_identifier(target)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    res = sudo_run(["swanctl", "--terminate", flag, target])
    return jsonify({"ok": res.ok, "output": _strip_noise(res.stdout + res.stderr)})


@bp.route("/api/reload", methods=["POST"])
@login_required
@csrf_protect
def reload_creds():
    """swanctl --load-all (re-read conf.d + secrets without restarting strongswan)."""
    res = sudo_run(["swanctl", "--load-all"])
    return jsonify({"ok": res.ok, "output": _strip_noise(res.stdout + res.stderr)})


# ---- managed (writable) connections --------------------------------------

def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default() -> dict:
    return {"connections": []}


@bp.route("/api/managed", methods=["GET"])
@login_required
def list_managed():
    """Connections managed by the GUI. Secrets (PSK / EAP passwords) redacted."""
    _migrate_in_place()
    data = _store().load(MODULE_NAME, _default())
    safe: list[dict] = []
    for c in data.get("connections", []):
        copy = json.loads(json.dumps(c))  # deep copy
        copy["has_psk"] = bool(c.get("psk"))
        copy.pop("psk", None)
        for u in copy.get("eap_users", []) or []:
            if u.get("password"):
                u["password"] = "***"
        safe.append(copy)
    return jsonify({"connections": safe})


def _migrate_in_place() -> None:
    """Upgrade legacy schema entries (auth_type missing, single 'child' field)."""
    changed = False
    data = _store().load(MODULE_NAME, _default())
    for c in data.get("connections", []):
        if "auth_type" not in c:
            c["auth_type"] = "psk"
            changed = True
        if "children" not in c and "child" in c:
            c["children"] = [c.pop("child")]
            changed = True
        elif "children" not in c:
            c["children"] = []
            changed = True
    if changed:
        _store().save(MODULE_NAME, data)


@bp.route("/api/managed", methods=["POST"])
@login_required
@csrf_protect
def add_managed():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        conn = _parse_connection_payload(payload, is_edit=False)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    conn["id"] = uuid.uuid4().hex
    with _store().transaction(MODULE_NAME, _default()) as data:
        if any(c["name"] == conn["name"] for c in data["connections"]):
            return jsonify({"error": f"connection name {conn['name']!r} already exists"}), 409
        data["connections"].append(conn)
        refreshed = list(data["connections"])
    try:
        _apply(refreshed)
    except RuntimeError as e:
        # roll back
        with _store().transaction(MODULE_NAME, _default()) as data:
            data["connections"] = [c for c in data["connections"] if c["id"] != conn["id"]]
        return jsonify({"error": str(e)}), 500
    return jsonify({"id": conn["id"]}), 201


@bp.route("/api/managed/<cid>", methods=["PUT"])
@login_required
@csrf_protect
def update_managed(cid: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        new = _parse_connection_payload(payload, is_edit=True)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    with _store().transaction(MODULE_NAME, _default()) as data:
        idx = next((i for i, c in enumerate(data["connections"]) if c["id"] == cid), None)
        if idx is None:
            return jsonify({"error": "not found"}), 404
        old = data["connections"][idx]
        # Preserve secrets if caller didn't supply them
        if not new.get("psk"):
            new["psk"] = old.get("psk", "")
        # Preserve EAP passwords for users that came back with placeholder
        existing_user_pw = {u["username"]: u.get("password", "")
                            for u in old.get("eap_users", []) or []}
        for u in new.get("eap_users", []):
            if u.get("password") in ("", "***"):
                u["password"] = existing_user_pw.get(u["username"], "")
        if any(c["name"] == new["name"] and c["id"] != cid for c in data["connections"]):
            return jsonify({"error": "name collision"}), 409
        new["id"] = cid
        data["connections"][idx] = new
        refreshed = list(data["connections"])
    try:
        _apply(refreshed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@bp.route("/api/managed/<cid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_managed(cid: str):
    with _store().transaction(MODULE_NAME, _default()) as data:
        before = len(data["connections"])
        data["connections"] = [c for c in data["connections"] if c["id"] != cid]
        if len(data["connections"]) == before:
            return jsonify({"error": "not found"}), 404
        refreshed = list(data["connections"])
    try:
        _apply(refreshed)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


# ---- payload validation --------------------------------------------------

def _parse_connection_payload(raw: dict, is_edit: bool = False) -> dict:
    name = validate_identifier(raw.get("name", ""))
    auth_type = (raw.get("auth_type") or "psk").lower()
    if auth_type not in _AUTH_TYPES:
        raise ValidationError(f"auth_type must be one of {sorted(_AUTH_TYPES)}")

    local_addrs = (raw.get("local_addrs") or "%any").strip() or "%any"
    if not _ADDR_RE.match(local_addrs):
        raise ValidationError("invalid local_addrs")
    remote_addrs = (raw.get("remote_addrs") or "").strip()
    if not remote_addrs:
        raise ValidationError("remote_addrs required")
    if not _ADDR_RE.match(remote_addrs):
        raise ValidationError("invalid remote_addrs")

    version = int(raw.get("version") or 2)
    if version not in (1, 2):
        raise ValidationError("version must be 1 or 2")
    if auth_type == "eap" and version != 2:
        raise ValidationError("EAP roadwarrior requires IKEv2")

    proposals = (raw.get("proposals") or "aes256-sha256-modp2048").strip()
    if not _PROPOSAL_RE.match(proposals):
        raise ValidationError("invalid proposals string")

    # ---- auth-specific fields ----
    local_id = (raw.get("local_id") or "").strip()
    remote_id = (raw.get("remote_id") or "").strip()
    if local_id and not _ID_RE.match(local_id):
        raise ValidationError("invalid local_id")
    if remote_id and not _ID_RE.match(remote_id):
        raise ValidationError("invalid remote_id")

    psk = raw.get("psk") or ""
    if psk and ('"' in psk or '\n' in psk or len(psk) > 256):
        raise ValidationError("psk contains invalid chars or too long")

    # Cert-based fields (shared between cert and eap auth_types)
    server_cert = (raw.get("server_cert") or "").strip()
    server_key = (raw.get("server_key") or "").strip()
    server_id = (raw.get("server_id") or "").strip()
    ca_cert = (raw.get("ca_cert") or "").strip()  # cert-only; optional (default x509ca/)
    pool_addrs = (raw.get("pool_addrs") or "").strip()
    pool_dns_raw = raw.get("pool_dns") or ""
    if isinstance(pool_dns_raw, list):
        pool_dns = [str(s).strip() for s in pool_dns_raw if str(s).strip()]
    else:
        pool_dns = [s.strip() for s in str(pool_dns_raw).split(",") if s.strip()]
    eap_users_raw = raw.get("eap_users") or []
    eap_users: list[dict] = []
    seen_usernames: set = set()
    for u in eap_users_raw:
        if not isinstance(u, dict):
            continue
        username = (u.get("username") or "").strip()
        password = u.get("password") or ""
        if not username:
            continue
        if not _EAP_USER_RE.match(username):
            raise ValidationError(f"invalid EAP username: {username!r}")
        if username in seen_usernames:
            raise ValidationError(f"duplicate EAP username: {username!r}")
        seen_usernames.add(username)
        if password and ('"' in password or '\n' in password or len(password) > 256):
            raise ValidationError(f"invalid EAP password for {username!r}")
        eap_users.append({"username": username, "password": password})

    if auth_type == "psk":
        if not psk and not is_edit:
            raise ValidationError("psk required for psk auth_type (new connection)")
    elif auth_type == "eap":
        if not server_cert or not _PATH_RE.match(server_cert):
            raise ValidationError("server_cert must be an absolute path")
        if not server_key or not _PATH_RE.match(server_key):
            raise ValidationError("server_key must be an absolute path")
        if not server_id or not _ID_RE.match(server_id):
            raise ValidationError("server_id required (must match server cert CN/SAN)")
        if not pool_addrs or not _ADDR_RE.match(pool_addrs):
            raise ValidationError("pool_addrs required (e.g. 10.10.10.0/24)")
        for dns in pool_dns:
            if not _ADDR_RE.match(dns):
                raise ValidationError(f"invalid DNS in pool_dns: {dns!r}")
        if not eap_users:
            raise ValidationError("EAP requires at least one user")
    elif auth_type == "cert":
        # Mutual X.509 (site-to-site). Each side authenticates with its own
        # certificate; CA can be specified explicitly or default to the
        # strongswan x509ca/ directory.
        if not server_cert or not _PATH_RE.match(server_cert):
            raise ValidationError("server_cert must be an absolute path")
        if not server_key or not _PATH_RE.match(server_key):
            raise ValidationError("server_key must be an absolute path")
        if not server_id or not _ID_RE.match(server_id):
            raise ValidationError("server_id required (local cert CN/SAN)")
        if not remote_id or not _ID_RE.match(remote_id):
            raise ValidationError("remote_id required (expected peer cert CN/SAN)")
        if ca_cert and not _PATH_RE.match(ca_cert):
            raise ValidationError("ca_cert must be an absolute path (or leave empty for default x509ca/)")

    # ---- children (multi-SA) ----
    children_raw = raw.get("children")
    if children_raw is None and raw.get("child"):
        children_raw = [raw["child"]]
    if not isinstance(children_raw, list):
        children_raw = []
    children: list[dict] = []
    seen_child_names: set = set()
    for i, ch_raw in enumerate(children_raw):
        if not isinstance(ch_raw, dict):
            continue
        ch_name = validate_identifier(ch_raw.get("name") or f"{name}-child{i + 1}")
        if ch_name in seen_child_names:
            raise ValidationError(f"duplicate child SA name: {ch_name!r}")
        seen_child_names.add(ch_name)
        local_ts = (ch_raw.get("local_ts") or "").strip()
        remote_ts = (ch_raw.get("remote_ts") or "").strip()
        if local_ts and not _TS_RE.match(local_ts):
            raise ValidationError(f"invalid local_ts on {ch_name!r}")
        if remote_ts and not _TS_RE.match(remote_ts):
            raise ValidationError(f"invalid remote_ts on {ch_name!r}")
        esp_proposals = (ch_raw.get("esp_proposals") or "aes256-sha256").strip()
        if not _PROPOSAL_RE.match(esp_proposals):
            raise ValidationError(f"invalid esp_proposals on {ch_name!r}")
        start_action = (ch_raw.get("start_action") or "").strip()
        if start_action not in _START_ACTIONS:
            raise ValidationError(f"start_action on {ch_name!r} must be one of {sorted(_START_ACTIONS)}")
        dpd_action = (ch_raw.get("dpd_action") or "").strip()
        if dpd_action not in _DPD_ACTIONS:
            raise ValidationError(f"dpd_action on {ch_name!r} must be one of {sorted(_DPD_ACTIONS)}")
        children.append({
            "name": ch_name,
            "local_ts": local_ts,
            "remote_ts": remote_ts,
            "esp_proposals": esp_proposals,
            "start_action": start_action,
            "dpd_action": dpd_action,
        })
    if not children:
        # Default child SA so the generated connection is usable
        default_ts = "0.0.0.0/0" if auth_type == "eap" else ""
        children = [{
            "name": f"{name}-child",
            "local_ts": default_ts,
            "remote_ts": "",
            "esp_proposals": "aes256-sha256",
            "start_action": "" if auth_type == "eap" else "trap",
            "dpd_action": "clear" if auth_type == "eap" else "restart",
        }]

    return {
        "name": name,
        "auth_type": auth_type,
        "local_addrs": local_addrs,
        "remote_addrs": remote_addrs,
        "version": version,
        "proposals": proposals,
        "local_id": local_id,
        "remote_id": remote_id,
        "psk": psk,
        "server_cert": server_cert,
        "server_key": server_key,
        "server_id": server_id,
        "ca_cert": ca_cert,
        "pool_addrs": pool_addrs,
        "pool_dns": pool_dns,
        "eap_users": eap_users,
        "children": children,
    }


# ---- rendering + apply --------------------------------------------------

def _render(conns: list[dict]) -> str:
    lines: list[str] = [
        "# Managed by server-gui — do not edit by hand.",
        "# Other files in conf.d are left alone; this file holds GUI-managed connections only.",
        "",
    ]

    # ---- pools section (one per EAP connection) ----
    eap_conns = [c for c in conns if c.get("auth_type") == "eap" and c.get("pool_addrs")]
    if eap_conns:
        lines.append("pools {")
        for c in eap_conns:
            lines.append(f"    {c['name']}-pool {{")
            lines.append(f"        addrs = {c['pool_addrs']}")
            if c.get("pool_dns"):
                lines.append(f"        dns = {','.join(c['pool_dns'])}")
            lines.append("    }")
        lines.append("}")
        lines.append("")

    # ---- connections section ----
    lines.append("connections {")
    for c in conns:
        auth_type = c.get("auth_type", "psk")
        lines.append(f"    {c['name']} {{")
        lines.append(f"        local_addrs = {c['local_addrs']}")
        lines.append(f"        remote_addrs = {c['remote_addrs']}")
        lines.append(f"        version = {c['version']}")
        lines.append(f"        proposals = {c['proposals']}")
        if auth_type == "eap":
            lines.append(f"        pools = {c['name']}-pool")
            lines.append("        send_certreq = no")
            lines.append("        fragmentation = yes")
            lines.append("        local {")
            lines.append("            auth = pubkey")
            lines.append(f"            certs = {c['server_cert']}")
            lines.append(f"            id = {c['server_id']}")
            lines.append("        }")
            lines.append("        remote {")
            lines.append("            auth = eap-mschapv2")
            lines.append("            eap_id = %any")
            lines.append("        }")
        elif auth_type == "cert":
            # Mutual X.509 (site-to-site). Both sides use pubkey auth with
            # their own cert; CA is either explicit (cacerts) or implicit
            # via the strongswan x509ca/ directory.
            lines.append("        local {")
            lines.append("            auth = pubkey")
            lines.append(f"            certs = {c['server_cert']}")
            lines.append(f"            id = {c['server_id']}")
            lines.append("        }")
            lines.append("        remote {")
            lines.append("            auth = pubkey")
            if c.get("ca_cert"):
                lines.append(f"            cacerts = {c['ca_cert']}")
            lines.append(f"            id = {c['remote_id']}")
            lines.append("        }")
        else:  # psk
            lines.append("        local {")
            lines.append("            auth = psk")
            if c.get("local_id"):
                lines.append(f"            id = {c['local_id']}")
            lines.append("        }")
            lines.append("        remote {")
            lines.append("            auth = psk")
            if c.get("remote_id"):
                lines.append(f"            id = {c['remote_id']}")
            lines.append("        }")
        lines.append("        children {")
        for ch in c.get("children", []):
            lines.append(f"            {ch['name']} {{")
            if ch.get("local_ts"):
                lines.append(f"                local_ts = {ch['local_ts']}")
            if ch.get("remote_ts"):
                lines.append(f"                remote_ts = {ch['remote_ts']}")
            lines.append(f"                esp_proposals = {ch['esp_proposals']}")
            if ch.get("start_action"):
                lines.append(f"                start_action = {ch['start_action']}")
            if ch.get("dpd_action"):
                lines.append(f"                dpd_action = {ch['dpd_action']}")
            lines.append("            }")
        lines.append("        }")
        lines.append("    }")
    lines.append("}")
    lines.append("")

    # ---- secrets section ----
    lines.append("secrets {")
    for c in conns:
        auth_type = c.get("auth_type", "psk")
        if auth_type == "psk":
            if c.get("psk"):
                lines.append(f"    ike-{c['name']} {{")
                if c.get("remote_id"):
                    lines.append(f"        id = {c['remote_id']}")
                elif c.get("remote_addrs") and c["remote_addrs"] not in ("%any", ""):
                    lines.append(f"        id = {c['remote_addrs']}")
                secret = c["psk"].replace("\\", "\\\\")
                lines.append(f'        secret = "{secret}"')
                lines.append("    }")
        elif auth_type == "eap":
            if c.get("server_key"):
                lines.append(f"    rsa-{c['name']} {{")
                lines.append(f"        file = {c['server_key']}")
                lines.append("    }")
            for u in c.get("eap_users", []):
                if not u.get("password"):
                    continue
                lines.append(f"    eap-{c['name']}-{u['username']} {{")
                lines.append(f"        id = {u['username']}")
                secret = u["password"].replace("\\", "\\\\")
                lines.append(f'        secret = "{secret}"')
                lines.append("    }")
        elif auth_type == "cert":
            if c.get("server_key"):
                lines.append(f"    rsa-{c['name']} {{")
                lines.append(f"        file = {c['server_key']}")
                lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _apply(conns: list[dict]) -> None:
    """Write the managed file and trigger `swanctl --load-all`. On failure
    restore the previous file from .bak so the daemon keeps the old config.
    """
    content = _render(conns) if conns else ""
    backup: bytes | None = None
    if MANAGED_FILE.exists():
        try:
            backup = MANAGED_FILE.read_bytes()
        except OSError:
            backup = None

    try:
        if not conns:
            # No managed connections — remove the file entirely
            if MANAGED_FILE.exists():
                MANAGED_FILE.unlink()
        else:
            CONF_D.mkdir(parents=True, exist_ok=True)
            tmp = MANAGED_FILE.with_suffix(".conf.new")
            tmp.write_text(content, encoding="utf-8")
            tmp.chmod(0o600)
            tmp.replace(MANAGED_FILE)
    except OSError as e:
        raise RuntimeError(f"failed to write {MANAGED_FILE}: {e}") from e

    res = sudo_run(["swanctl", "--load-all"], timeout=30)
    if not res.ok:
        # Roll back
        if backup is not None:
            try:
                MANAGED_FILE.write_bytes(backup)
                sudo_run(["swanctl", "--load-all"], timeout=30)
            except OSError:
                pass
        elif MANAGED_FILE.exists():
            MANAGED_FILE.unlink(missing_ok=True)
        raise RuntimeError(f"swanctl --load-all failed:\n{_strip_noise(res.stderr or res.stdout)}")

    try:
        _sync_firewalld_for_site_to_site(conns)
    except RuntimeError as e:
        raise RuntimeError(f"firewalld auto configuration failed:\n{e}") from e


def _sync_firewalld_for_site_to_site(conns: list[dict]) -> None:
    """Allow GUI-managed site-to-site IPsec traffic through firewalld."""
    local_remote_pairs: set[tuple[str, str]] = set()
    remote_endpoints: set[str] = set()

    for c in conns:
        if c.get("auth_type") == "eap":
            continue
        remote_endpoints.update(_extract_ipv4_addresses(c.get("remote_addrs", "")))
        for ch in c.get("children", []) or []:
            local_nets = _extract_ipv4_networks(ch.get("local_ts", ""))
            remote_nets = _extract_ipv4_networks(ch.get("remote_ts", ""))
            for local_net in local_nets:
                for remote_net in remote_nets:
                    local_remote_pairs.add((local_net, remote_net))

    if not local_remote_pairs and not remote_endpoints:
        return

    active = sudo_run(["systemctl", "is-active", "firewalld"], timeout=15)
    if not active.ok or active.stdout.strip() != "active":
        raise RuntimeError("firewalld is not active")

    changed = False
    endpoint_zone = _preferred_ipsec_endpoint_zone()
    if endpoint_zone:
        changed |= _firewalld_add(["--zone", endpoint_zone, "--add-service", "ipsec"])
        for endpoint in remote_endpoints:
            changed |= _firewalld_add(["--zone", endpoint_zone, "--add-source", endpoint])

    for local_net, remote_net in sorted(local_remote_pairs):
        changed |= _firewalld_add(["--zone", "trusted", "--add-source", remote_net])
        changed |= _add_direct_rule("ipv4", "filter", "FORWARD", 0, f"-s {local_net} -d {remote_net} -j ACCEPT")
        changed |= _add_direct_rule("ipv4", "filter", "FORWARD", 0, f"-s {remote_net} -d {local_net} -j ACCEPT")
        changed |= _add_direct_rule("ipv4", "nat", "POSTROUTING", 0, f"-d {remote_net} -j ACCEPT")

    if changed:
        reload_res = sudo_run(["firewall-cmd", "--reload"], timeout=30)
        if not reload_res.ok:
            raise RuntimeError(_strip_noise(reload_res.stderr or reload_res.stdout))


def _extract_ipv4_networks(value: str) -> list[str]:
    """Extract IPv4 CIDRs from comma/space separated traffic selectors."""
    out: list[str] = []
    for token in re.split(r"[\s,]+", value or ""):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            out.append(str(net))
    return out


def _extract_ipv4_addresses(value: str) -> list[str]:
    """Extract peer endpoint IPv4 addresses; FQDN/%any values are ignored."""
    out: list[str] = []
    for token in re.split(r"[\s,]+", value or ""):
        token = token.strip()
        if not token or token == "%any":
            continue
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv4Address):
            out.append(str(addr))
    return out


def _preferred_ipsec_endpoint_zone() -> str | None:
    """Use the Japan source zone when present; otherwise use the default zone."""
    zones = sudo_run(["firewall-cmd", "--get-zones"], timeout=15)
    if zones.ok and "japan" in zones.stdout.split():
        return "japan"
    default = sudo_run(["firewall-cmd", "--get-default-zone"], timeout=15)
    if default.ok and default.stdout.strip():
        return default.stdout.strip()
    return None


def _firewalld_add(args: list[str]) -> bool:
    """Run a permanent firewalld add operation and report whether reload is needed."""
    res = sudo_run(["firewall-cmd", "--permanent", *args], timeout=30)
    text = _strip_noise(res.stderr or res.stdout)
    if res.ok:
        return True
    already_enabled = "ALREADY_ENABLED" in text or "already enabled" in text.lower()
    if already_enabled:
        return False
    raise RuntimeError(text)


def _add_direct_rule(ipv: str, table: str, chain: str, priority: int, args: str) -> bool:
    """Add a firewalld direct rule unless the exact rule already exists."""
    line = f"{ipv} {table} {chain} {priority} {args}"
    existing = sudo_run(["firewall-cmd", "--permanent", "--direct", "--get-all-rules"], timeout=30)
    if existing.ok and line in {ln.strip() for ln in existing.stdout.splitlines()}:
        return False
    res = sudo_run([
        "firewall-cmd", "--permanent", "--direct", "--add-rule",
        ipv, table, chain, str(priority), *shlex.split(args),
    ], timeout=30)
    if not res.ok:
        raise RuntimeError(_strip_noise(res.stderr or res.stdout))
    return True


# ---- parsing -----------------------------------------------------------

def _file_meta(p: Path) -> dict:
    try:
        st = p.stat()
        return {"path": str(p), "name": p.name, "size": st.st_size, "mtime": int(st.st_mtime)}
    except OSError:
        return {"path": str(p), "name": p.name, "size": 0, "mtime": 0}


_CONN_HEADER_RE = re.compile(r"^([a-zA-Z0-9_\-]+):\s")


def _parse_conns(text: str) -> list[dict]:
    """`swanctl --list-conns` output is a series of indented blocks. We capture
    the connection name + interesting top-level fields + child SA names.

    Example fragment:
        my_conn: IKEv2, no reauthentication, rekeying every 14400s
          local:  %any
          remote: 203.0.113.5
          local public key authentication:
            id: ...
          my_conn_child: TUNNEL, rekeying every 3600s
            local:  10.0.0.0/24
            remote: 192.168.1.0/24
            AES_CBC_256/HMAC_SHA2_256_128
    """
    conns: list[dict] = []
    current: dict | None = None
    current_child: dict | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        leading = len(line) - len(line.lstrip())
        stripped = line.strip()
        m = _CONN_HEADER_RE.match(line)
        if leading == 0 and m:
            if current:
                if current_child:
                    current["children"].append(current_child)
                    current_child = None
                conns.append(current)
            current = {
                "name": m.group(1),
                "header": stripped[len(m.group(1)) + 1:].strip(),
                "fields": [],
                "children": [],
            }
            continue
        if current is None:
            continue
        # Child header: 2-space indent + "<name>: TUNNEL..." or "...rekeying..."
        if leading == 2 and ":" in stripped and "TUNNEL" in stripped:
            if current_child:
                current["children"].append(current_child)
            name = stripped.split(":", 1)[0].strip()
            current_child = {"name": name, "header": stripped.split(":", 1)[1].strip(), "fields": []}
            continue
        # Inside a child block (indent >= 4) — collect raw lines
        if current_child is not None and leading >= 4:
            current_child["fields"].append(stripped)
            continue
        # Otherwise belongs to the connection itself
        if current_child is not None:
            current["children"].append(current_child)
            current_child = None
        current["fields"].append(stripped)
    if current is not None:
        if current_child is not None:
            current["children"].append(current_child)
        conns.append(current)
    return conns


_SA_HEADER_RE = re.compile(r"^([a-zA-Z0-9_\-]+):\s*#(\d+),\s*(\S+),")


def _parse_sas(text: str) -> list[dict]:
    """`swanctl --list-sas` parsing is similar but with `#N, STATE,` headers."""
    sas: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        leading = len(line) - len(line.lstrip())
        stripped = line.strip()
        m = _SA_HEADER_RE.match(line)
        if leading == 0 and m:
            if current:
                sas.append(current)
            current = {
                "name": m.group(1),
                "id": m.group(2),
                "state": m.group(3),
                "header": stripped,
                "fields": [],
            }
            continue
        if current is None:
            continue
        current["fields"].append(stripped)
    if current is not None:
        sas.append(current)
    return sas
