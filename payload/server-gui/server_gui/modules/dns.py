"""DNS section of dnsmasq (host records, CNAMEs, upstream forwarders)."""
from __future__ import annotations

import uuid

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..dnsmasq_apply import MODULE_NAME, apply as apply_dnsmasq, default as default_data
from ..validators import ValidationError, validate_hostname, validate_ipv4

bp = Blueprint("dns", __name__, url_prefix="/dns")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("dns.html", active_tab="dns")


@bp.route("/api/records", methods=["GET"])
@login_required
def list_records():
    data = _store().load(MODULE_NAME, default_data())
    return jsonify({"dns": data.get("dns", {})})


# ---- hosts (A records) -------------------------------------------------

@bp.route("/api/hosts", methods=["POST"])
@login_required
@csrf_protect
def add_host():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        domain = validate_hostname(payload.get("domain", ""))
        ip = validate_ipv4(payload.get("ip", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    new_id = uuid.uuid4().hex
    with _store().transaction(MODULE_NAME, default_data()) as data:
        if any(h["domain"] == domain for h in data["dns"]["hosts"]):
            return jsonify({"error": f"domain {domain!r} already registered"}), 409
        data["dns"]["hosts"].append({"id": new_id, "domain": domain, "ip": ip})
    try:
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True, "id": new_id}), 201


@bp.route("/api/hosts/<rid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_host(rid: str):
    with _store().transaction(MODULE_NAME, default_data()) as data:
        before = len(data["dns"]["hosts"])
        data["dns"]["hosts"] = [h for h in data["dns"]["hosts"] if h["id"] != rid]
        if len(data["dns"]["hosts"]) == before:
            return jsonify({"error": "not found"}), 404
    try:
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


# ---- cnames ------------------------------------------------------------

@bp.route("/api/cnames", methods=["POST"])
@login_required
@csrf_protect
def add_cname():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        alias = validate_hostname(payload.get("alias", ""))
        target = validate_hostname(payload.get("target", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    new_id = uuid.uuid4().hex
    with _store().transaction(MODULE_NAME, default_data()) as data:
        data["dns"]["cnames"].append({"id": new_id, "alias": alias, "target": target})
    try:
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True, "id": new_id}), 201


@bp.route("/api/cnames/<rid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_cname(rid: str):
    with _store().transaction(MODULE_NAME, default_data()) as data:
        before = len(data["dns"]["cnames"])
        data["dns"]["cnames"] = [h for h in data["dns"]["cnames"] if h["id"] != rid]
        if len(data["dns"]["cnames"]) == before:
            return jsonify({"error": "not found"}), 404
    try:
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


# ---- upstream forwarders -----------------------------------------------

@bp.route("/api/upstream", methods=["POST"])
@login_required
@csrf_protect
def add_upstream():
    payload = request.get_json(force=True, silent=True) or {}
    server = payload.get("server", "")
    domain = (payload.get("domain") or "").strip()
    try:
        validate_ipv4(server)
        if domain:
            domain = validate_hostname(domain)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    new_id = uuid.uuid4().hex
    with _store().transaction(MODULE_NAME, default_data()) as data:
        data["dns"]["upstream"].append({"id": new_id, "domain": domain, "server": server})
    try:
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True, "id": new_id}), 201


@bp.route("/api/upstream/<rid>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_upstream(rid: str):
    with _store().transaction(MODULE_NAME, default_data()) as data:
        before = len(data["dns"]["upstream"])
        data["dns"]["upstream"] = [h for h in data["dns"]["upstream"] if h["id"] != rid]
        if len(data["dns"]["upstream"]) == before:
            return jsonify({"error": "not found"}), 404
    try:
        apply_dnsmasq(current_app.config["CONFIG_DIR"])
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})
