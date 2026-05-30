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
import logging
import re
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required

bp = Blueprint("sophos_import", __name__, url_prefix="/sophos-import")
logger = logging.getLogger(__name__)

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
        secondary = [_resolve_address(index, r) for r in _split_refs(f.get("additional addresses", ""))]
        secondary = [v for v in secondary if v]
        if f.get("username") or f.get("password"):
            mode = "PPPoE"
            form = {
                "WAN type": "PPPoE",
                "Connection name": f.get("name", ""),
                "PPPoE user": f.get("username", ""),
                "PPPoE password": f.get("password", ""),
                "MTU": f.get("maximum transmission unit", ""),
                "External IP": "not required for PPPoE; Sophos reference was " + (primary or "empty"),
            }
        else:
            mode = "Static / LAN"
            form = {
                "Connection name": f.get("name", ""),
                "IPv4 address": primary,
                "Secondary IPv4 addresses": ", ".join(secondary),
                "VLAN tag": f.get("VLAN tag", ""),
                "MTU": f.get("maximum transmission unit", ""),
            }
        rows.append({"ref": ref, "mode": mode, "enabled": f.get("status switch") == "1", "form": form})
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
            "Tunnel name": f.get("name", ""),
            "Enabled": "yes" if f.get("status switch") == "1" else "no",
            "Local interface": _name(index, f.get("interface", "")),
            "Remote gateway": _resolve_host(index, gw.get("remote host address", "")),
            "Local subnets": ", ".join(v for v in local_networks if v),
            "Remote subnets": ", ".join(v for v in remote_networks if v),
            "Pre-shared key": auth.get("preshared key", ""),
            "Local ID": auth.get("VPN ID", ""),
            "IKE encryption": policy.get("IKE SA encryption algorithm", ""),
            "IKE hash": policy.get("IKE SA authentication algorithm", ""),
            "IKE DH group": policy.get("IKE SA Diffie-Hellman group", ""),
            "ESP encryption": policy.get("IPsec SA encryption algorithm", ""),
            "ESP hash": policy.get("IPsec SA authentication algorithm", ""),
            "PFS group": policy.get("IPsec SA PFS Diffie-Hellman group", ""),
            "Auto firewall rule": "yes" if f.get("auto-packetfilter rule switch") == "1" else "no",
        }
        rows.append({"ref": ref, "form": form})
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
        form = {
            "Vhost name": f.get("name", ""),
            "Enabled": "yes" if f.get("status switch") == "1" else "no",
            "Public hostnames": f.get("domain list", ""),
            "Listen scheme": f.get("type", ""),
            "Listen port": f.get("port", ""),
            "Backend name": backend.get("name", ""),
            "Backend URL": f"{backend_scheme}://{backend_host}:{backend_port}" if backend else "",
            "Preserve host header": "yes" if f.get("switch to preserve host header") == "1" else "no",
            "Redirect HTTP to HTTPS": "yes" if f.get("implicit redirection from http to https switch") == "1" else "no",
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
        if "(X509 User Cert)" in name:
            continue
        usage = "Nginx candidate" if name in nginx_domains else "Reference only"
        if "WebAdmin certificate" in name:
            usage = "Skip: WebAdmin/management certificate"
        rows.append({
            "ref": ref,
            "usage": usage,
            "form": {
                "Certificate name": name,
                "Import private key": "yes" if f.get("private key") else "no",
                "Import certificate": "yes" if f.get("certificate") else "no",
            },
        })
    return rows


def _fields(index: dict[str, dict], ref: str) -> dict[str, str]:
    return index.get(ref, {}).get("fields", {})


def _name(index: dict[str, dict], ref: str) -> str:
    return _fields(index, ref).get("name", ref)


def _resolve_address(index: dict[str, dict], ref: str) -> str:
    f = _fields(index, ref)
    addr = f.get("IPv4 address") or f.get("address")
    mask = f.get("IPv4 netmask")
    if addr and mask:
        return f"{addr}/{mask}"
    return addr or ref


def _resolve_network(index: dict[str, dict], ref: str) -> str:
    f = _fields(index, ref)
    addr = f.get("IPv4 address")
    mask = f.get("IPv4 netmask")
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
