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
            "リモートアクセス設定は意図的に除外しています。",
            "Web proxy / Webserver Protection は Nginx リバースプロキシ移行対象として扱います。",
            "この画面では取込前の確認用プランを作成します。実適用は各機能ごとの変換ルール確認後に行います。",
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
        rows.append({"ref": ref, "mode": mode, "enabled": f.get("status switch") == "1", "form": form})
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
