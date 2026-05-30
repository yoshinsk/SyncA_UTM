"""payload/server-gui/server_gui/modules/sophos_import.py

Sophos SG UTM XML import helper for SyncA UTM.

The module intentionally separates parsing from applying. A Sophos export can
change firewall, NAT, VPN, and reverse-proxy behavior; the first safe step is a
structured import plan that operators can inspect before later applying it to
SyncA UTM subsystems.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required

bp = Blueprint("sophos_import", __name__, url_prefix="/sophos-import")

STORE_DIR = Path("/var/lib/server-gui/sophos-imports")
MAX_XML_BYTES = 16 * 1024 * 1024
SUPPORTED_DESCR = {
    "interface": "network",
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
    "IPsec site-to-site connection": "ipsec",
    "IPsec remote gateway": "ipsec",
    "IPsec policy": "ipsec",
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
        plan = _build_plan(xml_bytes)
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse failed: {e}"}), 400
    return jsonify(plan)


@bp.route("/api/save-plan", methods=["POST"])
@login_required
@csrf_protect
def save_plan():
    xml_bytes = _read_upload()
    if isinstance(xml_bytes, tuple):
        return xml_bytes
    try:
        plan = _build_plan(xml_bytes)
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse failed: {e}"}), 400
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = STORE_DIR / f"sophos-import-plan-{ts}.json"
    path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    path.chmod(0o600)
    return jsonify({"ok": True, "path": str(path), "summary": plan.get("summary", {})})


def _read_upload():
    f = request.files.get("xml")
    if f is None:
        return jsonify({"error": "xml file required"}), 400
    data = f.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        return jsonify({"error": "xml file too large"}), 413
    return data


def _build_plan(xml_bytes: bytes) -> dict:
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(xml_bytes)
        tmp.flush()
        root = ET.parse(tmp.name).getroot()
    header = root.find("header")
    nodes = root.find("nodes")
    objects = _collect_objects(root)
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
        "unsupported_counts": dict(sorted(unsupported_counts.items())),
        "notes": [
            "Remote access settings are intentionally ignored.",
            "Web proxy / webserver protection items are mapped to the Nginx migration target.",
            "This endpoint creates a reviewable import plan; applying the plan should be done per target subsystem.",
        ],
    }


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


def _direct_contents(element: ET.Element) -> list[str]:
    values: list[str] = []
    for content in element.findall("content"):
        text = "".join(content.itertext()).strip()
        if text:
            values.append(text)
    return values


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
