"""Dynamic DNS update management.

Multiple providers can be registered. A systemd timer
(`server-gui-ddns.timer`) periodically runs `/opt/server-gui/bin/ddns-check`
which checks the current WAN IP and, on change, calls each enabled provider's
update URL.

Storage (/etc/server-gui/ddns.json):
  {
    "check_url": "http://update.ddnsft.com/checkip.php",
    "current_ip": null,
    "last_check": null,
    "providers": [
      {
        "id": "uuid",
        "name": "ddnsft-densmile01",
        "enabled": true,
        "template": "http://update.ddnsft.com/update/update.php?host={account}&dm={domain}&ip={ip}",
        "account": "densmile01",
        "domain": "ddnsft.com",
        "auth_user": "...",
        "auth_pass": "...",
        "last_ip": null,
        "last_status": null,
        "last_update": null
      }
    ]
  }

Update URL placeholders supported in `template`:
  {ip}       current public IP
  {host}     provider.account
  {domain}   provider.domain
  {user}     provider.auth_user  (also sent as Basic Auth username)
  {pass}     provider.auth_pass  (also sent as Basic Auth password)
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import re
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run

logger = logging.getLogger(__name__)

bp = Blueprint("ddns", __name__, url_prefix="/ddns")

MODULE_NAME = "ddns"
# update.ddnsft.com supports HTTPS via Let's Encrypt (SAN includes
# update.ddnsft.com). Cert is verified by urllib's default context.
DEFAULT_CHECK_URL = "https://update.ddnsft.com/checkip.php"
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,63}$")

# Built-in presets. Selecting one auto-fills the provider form. Credentials
# baked in here are *defaults* — the admin can override them via the API once
# the provider entry exists (auth fields are just hidden in the form when
# `hide_auth=True` so the operator doesn't have to retype them every time).
_PRESETS: dict = {
    "ddnsft": {
        "label": "ddnsft.com",
        "template": "https://update.ddnsft.com/update/update.php?host={account}&dm={domain}&ip={ip}",
        "domain": "ddnsft.com",
        "auth_user": "",
        "auth_pass": "",
        "hide_auth": False,
    },
    "dyn": {
        "label": "DynDNS 互換",
        "template": "https://members.dyndns.org/v3/update?hostname={account}.{domain}&myip={ip}",
        "domain": "",
        "auth_user": "",
        "auth_pass": "",
        "hide_auth": False,
    },
    "noip": {
        "label": "No-IP",
        "template": "https://dynupdate.no-ip.com/nic/update?hostname={account}.{domain}&myip={ip}",
        "domain": "",
        "auth_user": "",
        "auth_pass": "",
        "hide_auth": False,
    },
    "duckdns": {
        "label": "Duck DNS",
        "template": "https://www.duckdns.org/update?domains={account}&token={pass}&ip={ip}",
        "domain": "",
        "auth_user": "",
        "auth_pass": "",
        "hide_auth": False,
    },
}


def register(app: Flask) -> None:
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default() -> dict:
    return {
        "check_url": DEFAULT_CHECK_URL,
        "current_ip": None,
        "last_check": None,
        "last_error": None,
        "providers": [],
    }


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("ddns.html", active_tab="ddns")


@bp.route("/api/presets", methods=["GET"])
@login_required
def list_presets():
    """Return preset metadata (without secrets — labels and shape only).

    Use /api/presets/<key> to fetch a specific preset including baked-in
    defaults so the form can populate hidden fields.
    """
    return jsonify({
        "presets": [
            {"key": k, "label": v["label"], "hide_auth": v.get("hide_auth", False)}
            for k, v in _PRESETS.items()
        ]
    })


@bp.route("/api/presets/<key>", methods=["GET"])
@login_required
def get_preset(key: str):
    """Fetch a preset's full values including baked-in credentials.
    The caller is already authenticated so it's safe to return secrets here.
    """
    preset = _PRESETS.get(key)
    if not preset:
        return jsonify({"error": "unknown preset"}), 404
    return jsonify({"key": key, **preset})


@bp.route("/api/state", methods=["GET"])
@login_required
def get_state():
    _migrate_state_in_place()
    data = _store().load(MODULE_NAME, _default())
    # Redact passwords on read
    safe = json.loads(json.dumps(data))
    for p in safe.get("providers", []):
        if p.get("auth_pass"):
            p["auth_pass"] = "***"
    return jsonify(safe)


def _migrate_state_in_place() -> None:
    """One-shot upgrades of persisted state on read.

    Currently:
      - update.ddnsft.com now serves HTTPS (cert via Let's Encrypt). Any
        persisted check_url or provider template still pinned at http
        gets upgraded to https on read.
    """
    needs_save = False
    data = _store().load(MODULE_NAME, _default())
    url = data.get("check_url", "")
    if url.startswith("http://update.ddnsft.com"):
        data["check_url"] = "https://" + url[len("http://"):]
        needs_save = True
    for p in data.get("providers", []):
        tmpl = p.get("template", "")
        if tmpl.startswith("http://update.ddnsft.com"):
            p["template"] = "https://" + tmpl[len("http://"):]
            needs_save = True
    if needs_save:
        _store().save(MODULE_NAME, data)


@bp.route("/api/state", methods=["PUT"])
@login_required
@csrf_protect
def update_state():
    """Update global settings (check_url)."""
    payload = request.get_json(force=True, silent=True) or {}
    with _store().transaction(MODULE_NAME, _default()) as data:
        if "check_url" in payload:
            url = (payload["check_url"] or "").strip()
            if url and not url.startswith(("http://", "https://")):
                return jsonify({"error": "check_url must be http(s)://"}), 400
            data["check_url"] = url or DEFAULT_CHECK_URL
    return jsonify({"ok": True})


@bp.route("/api/providers", methods=["POST"])
@login_required
@csrf_protect
def add_provider():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        new = _parse_provider_payload(payload)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    new["id"] = uuid.uuid4().hex
    new["last_ip"] = None
    new["last_status"] = None
    new["last_update"] = None
    with _store().transaction(MODULE_NAME, _default()) as data:
        if any(p["name"] == new["name"] for p in data["providers"]):
            return jsonify({"error": f"name {new['name']!r} already exists"}), 409
        data["providers"].append(new)
    return jsonify({"id": new["id"]}), 201


@bp.route("/api/providers/<pid>", methods=["PUT"])
@login_required
@csrf_protect
def update_provider(pid: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        new = _parse_provider_payload(payload)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    with _store().transaction(MODULE_NAME, _default()) as data:
        for i, p in enumerate(data["providers"]):
            if p["id"] == pid:
                # Preserve auth_pass if "***" (placeholder from GET)
                if new.get("auth_pass") == "***":
                    new["auth_pass"] = p.get("auth_pass", "")
                if any(o["name"] == new["name"] and o["id"] != pid for o in data["providers"]):
                    return jsonify({"error": "name collision"}), 409
                new["id"] = pid
                new["last_ip"] = p.get("last_ip")
                new["last_status"] = p.get("last_status")
                new["last_update"] = p.get("last_update")
                data["providers"][i] = new
                return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404


@bp.route("/api/providers/<pid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_provider(pid: str):
    with _store().transaction(MODULE_NAME, _default()) as data:
        before = len(data["providers"])
        data["providers"] = [p for p in data["providers"] if p["id"] != pid]
        if len(data["providers"]) == before:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@bp.route("/api/check", methods=["POST"])
@login_required
@csrf_protect
def check_now():
    """Trigger an immediate IP check + (if changed) update all providers.

    This is the same logic as the periodic systemd timer.
    """
    result = _check_and_update()
    return jsonify(result)


@bp.route("/api/providers/<pid>/force-update", methods=["POST"])
@login_required
@csrf_protect
def force_update(pid: str):
    """Re-send the update for a single provider regardless of IP change."""
    data = _store().load(MODULE_NAME, _default())
    provider = next((p for p in data["providers"] if p["id"] == pid), None)
    if not provider:
        return jsonify({"error": "not found"}), 404
    # Use current_ip if known; otherwise query check_url
    ip = data.get("current_ip")
    if not ip:
        try:
            ip = _fetch_current_ip(data.get("check_url", DEFAULT_CHECK_URL))
        except RuntimeError as e:
            return jsonify({"error": f"IP fetch failed: {e}"}), 502
    result = _call_provider(provider, ip)
    with _store().transaction(MODULE_NAME, _default()) as data:
        for i, p in enumerate(data["providers"]):
            if p["id"] == pid:
                data["providers"][i]["last_ip"] = ip
                data["providers"][i]["last_status"] = result["body"][:200]
                data["providers"][i]["last_update"] = _now()
                break
    return jsonify({"ok": result["ok"], "ip": ip, **result})


# ---- helpers -----------------------------------------------------------

def _parse_provider_payload(payload: dict) -> dict:
    name = (payload.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("name must match [A-Za-z0-9_-]{1,63}")
    template = (payload.get("template") or "").strip()
    if not template.startswith(("http://", "https://")):
        raise ValueError("template must be http(s) URL")
    return {
        "name": name,
        "enabled": bool(payload.get("enabled", True)),
        "preset_type": (payload.get("preset_type") or "custom").strip()[:32],
        "template": template,
        "account": (payload.get("account") or "").strip(),
        "domain": (payload.get("domain") or "").strip(),
        "auth_user": (payload.get("auth_user") or "").strip(),
        "auth_pass": payload.get("auth_pass") or "",
    }


def _now() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def _fetch_current_ip(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "server-gui-ddns/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", errors="replace").strip()
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(str(e)) from e


def _render_template(template: str, ip: str, provider: dict) -> str:
    """Substitute placeholders by literal string replace.

    Avoids Python ``str.format`` which (a) errors on unknown placeholders and
    (b) clashes with the reserved word ``pass``. All accepted aliases:

        {ip}       — the public IP just observed
        {account}  — provider.account  (alias: {host})
        {host}     — same as {account}
        {domain}   — provider.domain
        {user}     — provider.auth_user
        {pass}     — provider.auth_pass   (alias: {passwd}, {token})
        {passwd}   — alias for {pass}
        {token}    — alias for {pass}  (Duck DNS convention)
    """
    account = provider.get("account", "")
    auth_pass = provider.get("auth_pass", "")
    subs = {
        "ip": ip,
        "account": account, "host": account,
        "domain": provider.get("domain", ""),
        "user": provider.get("auth_user", ""),
        "pass": auth_pass, "passwd": auth_pass, "token": auth_pass,
    }
    out = template
    for k, v in subs.items():
        # urllib quoting is the caller's responsibility for {ip}/{account};
        # all preset values are simple ASCII tokens so direct replacement is OK.
        out = out.replace("{" + k + "}", str(v))
    return out


def _call_provider(provider: dict, ip: str) -> dict:
    url = _render_template(provider["template"], ip, provider)
    logger.info("ddns request: %s (provider=%s)", url, provider.get("name"))
    req = urllib.request.Request(url, headers={"User-Agent": "server-gui-ddns/1.0"})
    user = provider.get("auth_user")
    pw = provider.get("auth_pass")
    if user:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode("utf-8", errors="replace").strip()
            return {"ok": True, "status": r.status, "body": body, "url": url}
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace").strip()
        except Exception:
            err_body = ""
        return {"ok": False, "status": e.code,
                "body": f"HTTP {e.code} {e.reason}: {err_body}", "url": url}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"ok": False, "status": 0, "body": str(e), "url": url}


def _check_and_update() -> dict:
    """Periodic check: fetch current IP, update providers on change.

    This function is invoked both by the manual /api/check endpoint and by the
    standalone systemd-driven script (see bin/server-gui-ddns).
    """
    data = _store().load(MODULE_NAME, _default())
    url = data.get("check_url") or DEFAULT_CHECK_URL
    try:
        new_ip = _fetch_current_ip(url)
    except RuntimeError as e:
        with _store().transaction(MODULE_NAME, _default()) as data:
            data["last_check"] = _now()
            data["last_error"] = f"check failed: {e}"
        return {"ok": False, "error": f"check failed: {e}"}
    if not new_ip or new_ip == "0.0.0.0":
        with _store().transaction(MODULE_NAME, _default()) as data:
            data["last_check"] = _now()
            data["last_error"] = f"invalid ip from check_url: {new_ip!r}"
        return {"ok": False, "error": f"invalid ip: {new_ip!r}"}

    updates: list[dict] = []
    with _store().transaction(MODULE_NAME, _default()) as data:
        old_ip = data.get("current_ip")
        data["current_ip"] = new_ip
        data["last_check"] = _now()
        data["last_error"] = None
        if old_ip != new_ip:
            for i, p in enumerate(data["providers"]):
                if not p.get("enabled"):
                    continue
                result = _call_provider(p, new_ip)
                data["providers"][i]["last_ip"] = new_ip
                data["providers"][i]["last_status"] = result["body"][:200]
                data["providers"][i]["last_update"] = _now()
                updates.append({
                    "name": p["name"], "ok": result["ok"],
                    "status": result["status"], "body": result["body"][:200],
                })
        else:
            updates = [{"note": "IP unchanged, no updates"}]
    return {"ok": True, "ip": new_ip, "changed": old_ip != new_ip,
            "old_ip": old_ip, "updates": updates}
