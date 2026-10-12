"""payload/server-gui/server_gui/modules/ai_defense.py - Jev-assisted WAN defense.

The module derives anonymised, aggregated attack evidence from local logs for
currently exposed firewalld ports. It asks Jev to classify each opaque source
summary and, for a suspicious candidate, blocks in the safer direction unless
Jev can clearly rule out malicious intent. Raw log lines, source IP addresses,
and the API key never leave the appliance.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import ipaddress
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run


bp = Blueprint("ai_defense", __name__, url_prefix="/ai-defense")

MODULE_NAME = "ai_defense"
DEFAULT_INTERVAL_HOURS = 8
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 168
MAX_CANDIDATES = 20
MAX_JOURNAL_LINES = 1200
MAX_NGINX_LOG_BYTES = 512 * 1024
MAX_NGINX_LINES = 2000
JEV_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"
JEV_TIMEOUT_SECONDS = 30
JEV_MAX_RESPONSE_BYTES = 512 * 1024
JEV_MAX_REQUEST_BYTES = 64 * 1024
# A candidate remains unblocked only when Jev is both confident that it is
# benign and assigns no malicious probability.  This is intentionally a
# fail-safe policy requested for WAN-facing suspicious access; operators can
# immediately reverse every resulting block from the GUI.
CLEAR_BENIGN_CONFIDENCE_MINIMUM = 0.85
IPSET_V4 = "synca-ai-defense-v4"
IPSET_V6 = "synca-ai-defense-v6"
AI_DEFENSE_SERVICE = "server-gui-ai-defense.service"
AI_DEFENSE_TIMER = "server-gui-ai-defense.timer"
RUNTIME_BINARY = Path("/opt/server-gui/bin/ai-defense-check")
SYSTEMD_DIR = Path("/etc/systemd/system")
PORT_RE = re.compile(r"^(\d{1,5}(?:-\d{1,5})?)/(tcp|udp|sctp|dccp)$", re.IGNORECASE)
SERVICE_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
IP_TOKEN_RE = re.compile(r"(?:\bfrom\s+|\brhost=|\bSRC=)([0-9A-Fa-f:.]+)")
KERNEL_PACKET_RE = re.compile(r"\bSRC=([0-9A-Fa-f:.]+).*?\bDPT=(\d{1,5}).*?\bPROTO=([A-Za-z]+)")
NGINX_LINE_RE = re.compile(r'^([^\s]+)\s+\S+\s+\S+\s+"(?:[A-Z]+)\s+([^\s?]+)[^\"]*"\s+(\d{3})\b')
SUSPICIOUS_HTTP_PATH_RE = re.compile(
    r"/(?:\.env|\.git(?:/|$)|wp-login\.php|xmlrpc\.php|phpmyadmin(?:/|$)|vendor/phpunit|cgi-bin|boaform)",
    re.IGNORECASE,
)


AI_DEFENSE_SERVICE_CONTENT = """[Unit]
Description=server-gui Jev AI defense check
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/server-gui
Environment=SERVER_GUI_CONFIG_DIR=/etc/server-gui
ExecStart=/opt/server-gui/bin/ai-defense-check
StandardOutput=journal
StandardError=journal
"""

AI_DEFENSE_TIMER_CONTENT = """[Unit]
Description=Run server-gui Jev AI defense check periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
"""


class DefenseBusy(RuntimeError):
    """Raised when a scheduled and a manual inspection overlap."""


class JevResponseError(RuntimeError):
    """Raised when a response cannot be verified against the Jev contract."""


def register(app: Flask) -> None:
    """Register the authenticated AI-defense page and its JSON endpoints."""
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    """Return the appliance's protected configuration store."""
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default_state() -> dict[str, Any]:
    """Return the complete persisted schema without exposing any secret value."""
    return {
        "enabled": False,
        "api_key": "",
        "interval_hours": DEFAULT_INTERVAL_HOURS,
        "last_completed_at": None,
        "last_result": None,
        "blocked": [],
    }


def _normalise_state(data: Any) -> dict[str, Any]:
    """Merge an existing config with defaults and discard malformed collections."""
    state = _default_state()
    if not isinstance(data, dict):
        return state
    state.update({key: data.get(key, value) for key, value in state.items()})
    state["enabled"] = bool(state["enabled"])
    state["api_key"] = state["api_key"] if isinstance(state["api_key"], str) else ""
    state["interval_hours"] = _normalise_interval(state["interval_hours"], DEFAULT_INTERVAL_HOURS)
    state["blocked"] = state["blocked"] if isinstance(state["blocked"], list) else []
    return state


def _normalise_interval(value: Any, fallback: int) -> int:
    """Clamp a persisted frequency to the range supported by the hourly timer."""
    try:
        interval = int(value)
    except (TypeError, ValueError):
        return fallback
    return interval if MIN_INTERVAL_HOURS <= interval <= MAX_INTERVAL_HOURS else fallback


@bp.route("/")
@login_required
def page():
    """Render configuration, current exposure, and manually reversible blocks."""
    return render_template("ai_defense.html", active_tab="ai_defense")


@bp.route("/api/status", methods=["GET"])
@login_required
def status():
    """Report configuration without returning the API key or raw log content."""
    state = _normalise_state(_store().load(MODULE_NAME, _default_state()))
    return jsonify({
        **_public_state(state),
        "timer": _timer_status(),
        "exposure": _discover_open_ports(),
    })


@bp.route("/api/settings", methods=["PUT"])
@login_required
@csrf_protect
def save_settings():
    """Save enablement, cadence, and an optional replacement Jev API key."""
    payload = request.get_json(force=True, silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "設定値の形式が正しくありません。"}), 400
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "有効・無効を指定してください。"}), 400
    interval = _normalise_interval(payload.get("interval_hours"), -1)
    if interval == -1:
        return jsonify({"error": "実行間隔は 1 ～ 168 時間で指定してください。"}), 400
    key_value = payload.get("api_key")
    clear_key = payload.get("clear_api_key") is True
    if key_value is not None and not isinstance(key_value, str):
        return jsonify({"error": "API キーの形式が正しくありません。"}), 400
    if isinstance(key_value, str) and len(key_value.strip()) > 512:
        return jsonify({"error": "API キーが長すぎます。"}), 400

    store = _store()
    current = _normalise_state(store.load(MODULE_NAME, _default_state()))
    replacement_key = key_value.strip() if isinstance(key_value, str) else ""
    effective_key = "" if clear_key else (replacement_key or current["api_key"])
    if enabled and not effective_key:
        return jsonify({"error": "有効化するには Jev API キーを入力してください。"}), 400

    with store.transaction(MODULE_NAME, _default_state()) as stored:
        state = _normalise_state(stored)
        state["enabled"] = enabled
        state["interval_hours"] = interval
        if clear_key:
            state["api_key"] = ""
        elif replacement_key:
            state["api_key"] = replacement_key
        stored.clear()
        stored.update(state)

    provision = ensure_runtime_units()
    state = _normalise_state(_store().load(MODULE_NAME, _default_state()))
    return jsonify({**_public_state(state), "timer_provision": provision})


@bp.route("/api/check", methods=["POST"])
@login_required
@csrf_protect
def check_now():
    """Run an enabled Jev inspection now instead of waiting for the timer."""
    try:
        result = run_scheduled_check(current_app.config["CONFIG_DIR"], force=True)
    except DefenseBusy:
        return jsonify({"ok": False, "error": "別の AI 防御確認が実行中です。"}), 409
    if result.get("status") in {"disabled", "api_key_missing"}:
        return jsonify({"ok": False, "error": result["message"]}), 409
    return jsonify(result), (200 if result.get("ok") else 503)


@bp.route("/api/blocked/unblock", methods=["POST"])
@login_required
@csrf_protect
def unblock():
    """Remove one AI-defense source block from permanent and runtime firewalld."""
    payload = request.get_json(force=True, silent=True) or {}
    ip_text = str(payload.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        return jsonify({"error": "IP アドレスの形式が正しくありません。"}), 400
    result = unblock_ip(current_app.config["CONFIG_DIR"], ip_text)
    return jsonify(result), (200 if result.get("ok") else 500)


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    """Project persisted state into the browser-safe representation."""
    blocked = []
    for item in state.get("blocked", []):
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        blocked.append({
            "ip": ip,
            "blocked_at": item.get("blocked_at"),
            "jev_choice": item.get("jev_choice"),
            "confidence": item.get("confidence"),
            "malicious_probability": item.get("malicious_probability"),
            "event_types": item.get("event_types", {}),
            "target_ports": item.get("target_ports", []),
        })
    return {
        "enabled": bool(state.get("enabled")),
        "api_key_configured": bool(state.get("api_key")),
        "interval_hours": state.get("interval_hours", DEFAULT_INTERVAL_HOURS),
        "last_completed_at": state.get("last_completed_at"),
        "last_result": state.get("last_result"),
        "blocked": blocked,
        "privacy": {
            "sent_to_jev": "匿名化した候補ID、イベント種別の件数、対象ポートだけを送信します。",
            "kept_local": "IP アドレス、API キー、元のログ行は装置内に保持します。",
        },
    }


@contextmanager
def _exclusive_defense_lock(config_dir: Path) -> Iterator[None]:
    """Prevent simultaneous timer and UI scans from racing on firewall changes."""
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / ".ai-defense-run.lock"
    with path.open("a+", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DefenseBusy from exc
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def run_scheduled_check(config_dir: Path | str, force: bool = False) -> dict[str, Any]:
    """Run one safe inspection from systemd or the GUI.

    An absent key, disabled feature, no open ports, invalid Jev response, or a
    network failure never produces a block.  This fail-open policy prevents an
    external dependency from changing traffic policy without verified evidence.
    """
    base_dir = Path(config_dir)
    with _exclusive_defense_lock(base_dir):
        store = ConfigStore(base_dir)
        state = _normalise_state(store.load(MODULE_NAME, _default_state()))
        if not state["enabled"]:
            return _skip_result("disabled", "AI 防御は無効です。")
        if not state["api_key"]:
            return _skip_result("api_key_missing", "Jev API キーが設定されていません。")
        if not force and not _is_due(state.get("last_completed_at"), state["interval_hours"]):
            return _skip_result("not_due", "設定した実行間隔まで待機します。")

        exposure = _discover_open_ports()
        completed_at = _now_iso()
        if not exposure["ports"]:
            result = {
                "ok": True,
                "status": "no_open_ports",
                "message": "WAN 側で判定対象となる公開ポートを検出できませんでした。",
                "completed_at": completed_at,
                "open_ports": [],
                "candidate_count": 0,
                "blocked_count": 0,
            }
            _record_check_result(store, result, [])
            return result

        records = _collect_log_events(state["interval_hours"], set(exposure["ports"]))
        candidates = _build_candidates(records, set(exposure["ports"]))
        if not candidates:
            result = {
                "ok": True,
                "status": "no_candidates",
                "message": "判定基準を満たすアクセス記録はありませんでした。",
                "completed_at": completed_at,
                "open_ports": exposure["ports"],
                "candidate_count": 0,
                "blocked_count": 0,
            }
            _record_check_result(store, result, [])
            return result

        state_payload, questions = _build_jev_request(candidates, exposure["ports"], state["interval_hours"])
        try:
            answers = _call_jev(state["api_key"], state_payload, questions)
        except (JevResponseError, urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
            result = {
                "ok": False,
                "status": "jev_unavailable",
                "message": "Jev の判定結果を検証できなかったため、遮断は行いませんでした。",
                "completed_at": completed_at,
                "open_ports": exposure["ports"],
                "candidate_count": len(candidates),
                "blocked_count": 0,
            }
            _record_check_result(store, result, [])
            return result

        blocks: list[dict[str, Any]] = []
        blocked_count = 0
        for candidate in candidates:
            answer = answers.get(candidate["id"], {})
            if not _should_block(candidate, answer):
                continue
            firewall_result = _block_ip(candidate["ip"])
            if not firewall_result["ok"]:
                continue
            blocks.append({
                "ip": candidate["ip"],
                "blocked_at": completed_at,
                "jev_choice": answer["choice"],
                "confidence": answer["confidence"],
                "malicious_probability": answer["probabilities"]["malicious"],
                "event_types": candidate["event_types"],
                "target_ports": candidate["target_ports"],
            })
            blocked_count += 1
        result = {
            "ok": True,
            "status": "completed",
            "message": "AI 防御確認を完了しました。",
            "completed_at": completed_at,
            "open_ports": exposure["ports"],
            "candidate_count": len(candidates),
            "blocked_count": blocked_count,
        }
        _record_check_result(store, result, blocks)
        return result


def _skip_result(status: str, message: str) -> dict[str, Any]:
    """Return a non-error no-op result suitable for timer journald output."""
    return {"ok": True, "status": status, "message": message, "blocked_count": 0, "candidate_count": 0}


def _is_due(last_completed_at: Any, interval_hours: int) -> bool:
    """Decide whether the hourly systemd wake-up has reached its configured cadence."""
    if not isinstance(last_completed_at, str) or not last_completed_at:
        return True
    try:
        previous = dt.datetime.fromisoformat(last_completed_at)
        if previous.tzinfo is None:
            previous = previous.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return True
    return dt.datetime.now(dt.timezone.utc) >= previous.astimezone(dt.timezone.utc) + dt.timedelta(hours=interval_hours)


def _now_iso() -> str:
    """Return a timezone-aware timestamp used for state and block evidence."""
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _record_check_result(store: ConfigStore, result: dict[str, Any], new_blocks: list[dict[str, Any]]) -> None:
    """Persist only compact summaries and successful block metadata, never raw logs."""
    with store.transaction(MODULE_NAME, _default_state()) as stored:
        state = _normalise_state(stored)
        existing = {str(item.get("ip")): item for item in state["blocked"] if isinstance(item, dict)}
        for block in new_blocks:
            existing[block["ip"]] = block
        state["blocked"] = sorted(existing.values(), key=lambda item: str(item.get("blocked_at") or ""), reverse=True)
        state["last_completed_at"] = result.get("completed_at")
        state["last_result"] = {
            "ok": bool(result.get("ok")),
            "status": result.get("status"),
            "message": result.get("message"),
            "completed_at": result.get("completed_at"),
            "open_ports": result.get("open_ports", []),
            "candidate_count": result.get("candidate_count", 0),
            "blocked_count": result.get("blocked_count", 0),
        }
        stored.clear()
        stored.update(state)


def _discover_open_ports() -> dict[str, Any]:
    """List firewalld exposure for the interface selected by the IPv4 default route.

    Service definitions, explicit ports, and forward ports are covered.  Direct
    rules and arbitrary nftables rules are deliberately not guessed, because
    guessing them could make an unrelated local listener look WAN-exposed.
    """
    route = run(["ip", "-j", "route", "get", "1.1.1.1"], timeout=10)
    device = ""
    if route.ok:
        try:
            rows = json.loads(route.stdout)
            device = str(rows[0].get("dev") or "") if isinstance(rows, list) and rows else ""
        except (TypeError, ValueError, IndexError):
            device = ""
    if not re.fullmatch(r"[A-Za-z0-9_.:+-]{1,64}", device or ""):
        return _empty_exposure("WAN の既定インターフェースを特定できませんでした。")
    zone_result = run(["firewall-cmd", f"--get-zone-of-interface={device}"], timeout=10)
    zone = zone_result.stdout.strip() if zone_result.ok else ""
    if not zone:
        default_zone = run(["firewall-cmd", "--get-default-zone"], timeout=10)
        zone = default_zone.stdout.strip() if default_zone.ok else ""
    if not SERVICE_RE.fullmatch(zone or ""):
        return _empty_exposure("WAN 側の firewalld ゾーンを取得できませんでした。", device=device)

    services_result = run(["firewall-cmd", f"--zone={zone}", "--list-services"], timeout=10)
    explicit_result = run(["firewall-cmd", f"--zone={zone}", "--list-ports"], timeout=10)
    forward_result = run(["firewall-cmd", f"--zone={zone}", "--list-forward-ports"], timeout=10)
    services = [service for service in services_result.stdout.split() if SERVICE_RE.fullmatch(service)] if services_result.ok else []
    ports = set(_normalise_port_tokens(explicit_result.stdout.split() if explicit_result.ok else []))
    service_ports: dict[str, list[str]] = {}
    for service in services:
        info = run(["firewall-cmd", f"--service={service}", "--get-ports"], timeout=10)
        parsed = _normalise_port_tokens(info.stdout.split() if info.ok else [])
        service_ports[service] = parsed
        ports.update(parsed)
    forward_ports = _parse_forward_ports(forward_result.stdout if forward_result.ok else "")
    ports.update(forward_ports)
    return {
        "device": device,
        "zone": zone,
        "services": services,
        "service_ports": service_ports,
        "explicit_ports": _normalise_port_tokens(explicit_result.stdout.split() if explicit_result.ok else []),
        "forward_ports": forward_ports,
        "ports": sorted(ports, key=_port_sort_key),
        "limitation": "対象は WAN 既定経路の firewalld ゾーンにあるサービス、明示ポート、ポート転送です。direct ルールや任意の nftables ルールは自動列挙しません。",
    }


def _empty_exposure(error: str, device: str = "") -> dict[str, Any]:
    """Use a stable empty shape when runtime firewall inspection is unavailable."""
    return {
        "device": device,
        "zone": "",
        "services": [],
        "service_ports": {},
        "explicit_ports": [],
        "forward_ports": [],
        "ports": [],
        "error": error,
        "limitation": "対象は WAN 既定経路の firewalld ゾーンにあるサービス、明示ポート、ポート転送です。direct ルールや任意の nftables ルールは自動列挙しません。",
    }


def _normalise_port_tokens(tokens: list[str]) -> list[str]:
    """Validate firewalld port tokens before retaining them as inspection scope."""
    valid = []
    for token in tokens:
        match = PORT_RE.fullmatch(token)
        if not match:
            continue
        start = int(match.group(1).split("-", 1)[0])
        end = int(match.group(1).split("-", 1)[-1])
        if 1 <= start <= end <= 65535:
            valid.append(f"{match.group(1)}/{match.group(2).lower()}")
    return sorted(set(valid), key=_port_sort_key)


def _parse_forward_ports(text: str) -> list[str]:
    """Extract original protocol/port pairs from firewalld forward-port output."""
    matches = re.findall(r"port=(\d{1,5})(?:-\d{1,5})?:proto=(tcp|udp|sctp|dccp)", text, re.IGNORECASE)
    return _normalise_port_tokens([f"{port}/{proto}" for port, proto in matches])


def _port_sort_key(port: str) -> tuple[int, str]:
    """Sort a port/range token numerically while retaining protocol order stability."""
    number, _, protocol = port.partition("/")
    return int(number.split("-", 1)[0]), protocol


def _collect_log_events(interval_hours: int, open_ports: set[str]) -> dict[str, dict[str, Any]]:
    """Aggregate relevant journal and Nginx evidence by public source address.

    IP addresses remain only in this in-memory mapping.  Callers must convert
    it to opaque candidate identifiers before preparing a Jev API request.
    """
    records: dict[str, dict[str, Any]] = {}
    since = (dt.datetime.now() - dt.timedelta(hours=interval_hours)).strftime("%Y-%m-%d %H:%M:%S")
    for unit, category in (("sshd.service", "ssh"), ("server-gui.service", "gui"), ("nginx.service", "nginx")):
        output = _journal_output(unit, since)
        for line in output.splitlines():
            _parse_service_log_line(records, line, category, open_ports)
    kernel = _journal_kernel_output(since)
    for line in kernel.splitlines():
        _parse_kernel_log_line(records, line, open_ports)
    for line in _nginx_access_lines():
        _parse_nginx_access_line(records, line, open_ports)
    return records


def _journal_output(unit: str, since: str) -> str:
    """Read a bounded service journal window without emitting log text elsewhere."""
    result = run(
        ["journalctl", "--no-pager", "--output=short-iso", "--since", since, "-u", unit, "-n", str(MAX_JOURNAL_LINES)],
        timeout=20,
    )
    return result.stdout if result.ok else ""


def _journal_kernel_output(since: str) -> str:
    """Read a bounded kernel journal window for logged firewall packet evidence."""
    result = run(
        ["journalctl", "--no-pager", "--output=short-iso", "--since", since, "-k", "-n", str(MAX_JOURNAL_LINES)],
        timeout=20,
    )
    return result.stdout if result.ok else ""


def _nginx_access_lines() -> list[str]:
    """Read trailing plain-text access logs without retaining or uploading raw lines."""
    lines: list[str] = []
    for path in (Path("/var/log/nginx/access.log"), Path("/var/log/nginx/access.log.1")):
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(size - MAX_NGINX_LOG_BYTES, 0))
                raw = handle.read()
        except OSError:
            continue
        text = raw.decode("utf-8", errors="replace")
        lines.extend(text.splitlines()[-MAX_NGINX_LINES:])
    return lines[-(MAX_NGINX_LINES * 2):]


def _parse_service_log_line(records: dict[str, dict[str, Any]], line: str, category: str, open_ports: set[str]) -> None:
    """Recognise narrow authentication abuse patterns from one journal line."""
    ip = _first_public_ip(line)
    if not ip:
        return
    lowered = line.lower()
    if category == "ssh" and _contains_port(open_ports, "22/tcp"):
        if "invalid user" in lowered:
            _record_event(records, ip, "ssh_invalid_user", "22/tcp")
        if "failed password" in lowered or "authentication failure" in lowered:
            _record_event(records, ip, "ssh_failed_auth", "22/tcp")
    elif category == "gui" and _contains_port(open_ports, "4444/tcp"):
        if "failed login" in lowered:
            _record_event(records, ip, "gui_failed_auth", "4444/tcp")
        if "rate limit hit" in lowered:
            _record_event(records, ip, "gui_rate_limit", "4444/tcp")
    elif category == "nginx" and ("authentication failure" in lowered or "access forbidden" in lowered):
        for port in _web_ports(open_ports):
            _record_event(records, ip, "http_auth_failure", port)


def _parse_kernel_log_line(records: dict[str, dict[str, Any]], line: str, open_ports: set[str]) -> None:
    """Record a kernel-logged packet only when it targets an exposed port."""
    match = KERNEL_PACKET_RE.search(line)
    if not match:
        return
    ip = _public_ip(match.group(1))
    token = f"{match.group(2)}/{match.group(3).lower()}"
    if ip and _contains_port(open_ports, token):
        _record_event(records, ip, "firewall_logged_packet", token)


def _parse_nginx_access_line(records: dict[str, dict[str, Any]], line: str, open_ports: set[str]) -> None:
    """Count exploit-probing paths and repeated HTTP denials from access logs."""
    match = NGINX_LINE_RE.match(line)
    if not match:
        return
    ip = _public_ip(match.group(1))
    if not ip:
        return
    path, status = match.group(2), int(match.group(3))
    ports = _web_ports(open_ports)
    if SUSPICIOUS_HTTP_PATH_RE.search(path):
        for port in ports:
            _record_event(records, ip, "http_suspicious_path", port)
    elif status in {401, 403}:
        for port in ports:
            _record_event(records, ip, "http_auth_failure", port)


def _first_public_ip(text: str) -> str:
    """Extract the first supported source-address field from a daemon log line."""
    match = IP_TOKEN_RE.search(text)
    return _public_ip(match.group(1)) if match else ""


def _public_ip(value: str) -> str:
    """Accept only globally routable addresses; private peers are never candidates."""
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return ""
    return str(parsed) if parsed.is_global else ""


def _record_event(records: dict[str, dict[str, Any]], ip: str, event_type: str, port: str) -> None:
    """Increment one local-only event counter for a validated source and port."""
    item = records.setdefault(ip, {"events": {}, "ports": set()})
    item["events"][event_type] = int(item["events"].get(event_type, 0)) + 1
    item["ports"].add(port)


def _contains_port(open_ports: set[str], token: str) -> bool:
    """Match a concrete port against explicit ports or inclusive firewalld ranges."""
    number, _, protocol = token.partition("/")
    try:
        wanted = int(number)
    except ValueError:
        return False
    for port in open_ports:
        value, _, current_protocol = port.partition("/")
        if current_protocol != protocol:
            continue
        try:
            start, _, end_text = value.partition("-")
            end = int(end_text) if end_text else int(start)
            if int(start) <= wanted <= end:
                return True
        except ValueError:
            continue
    return False


def _web_ports(open_ports: set[str]) -> list[str]:
    """Return only currently exposed standard HTTP, HTTPS, and GUI ports."""
    return [token for token in ("80/tcp", "443/tcp", "4444/tcp") if _contains_port(open_ports, token)]


def _build_candidates(records: dict[str, dict[str, Any]], open_ports: set[str]) -> list[dict[str, Any]]:
    """Apply local relevance thresholds and replace source IPs with opaque IDs."""
    selected: list[dict[str, Any]] = []
    for ip, item in records.items():
        events = {str(key): int(value) for key, value in item.get("events", {}).items() if int(value) > 0}
        total = sum(events.values())
        if not _requires_review(events, total):
            continue
        ports = sorted(set(item.get("ports", set())) & open_ports, key=_port_sort_key)
        if not ports:
            continue
        selected.append({"ip": ip, "event_types": events, "event_total": total, "target_ports": ports})
    selected.sort(key=lambda item: (-item["event_total"], item["ip"]))
    selected = selected[:MAX_CANDIDATES]
    for index, candidate in enumerate(selected, start=1):
        candidate["id"] = f"source-{index:03d}"
    return selected


def _requires_review(events: dict[str, int], total: int) -> bool:
    """Keep Jev requests focused on meaningful credential abuse or exploit probes."""
    return events.get("ssh_invalid_user", 0) >= 1 or events.get("http_suspicious_path", 0) >= 1 or total >= 3


def _build_jev_request(candidates: list[dict[str, Any]], open_ports: list[str], interval_hours: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build a privacy-minimised Jev request with no source address or raw log text."""
    summaries = [
        {
            "id": item["id"],
            "event_counts": item["event_types"],
            "target_ports": item["target_ports"],
            "event_total": item["event_total"],
        }
        for item in candidates
    ]
    state = {
        "task": "Classify anonymized WAN-access evidence from a security appliance.",
        "observation_window_hours": interval_hours,
        "currently_open_ports": open_ports,
        "privacy": "No source IP address, raw log line, account name, request path, or credential is provided.",
        "candidates": summaries,
    }
    questions = [
        {
            "id": item["id"],
            "question": "Classify this anonymized event summary using only the supplied evidence.",
            "criteria": {
                "malicious": "Repeated credential attack, exploit probing, or attack-like scanning is supported by the counters.",
                "benign": "The counters are more consistent with ordinary legitimate use.",
                "insufficient": "The supplied counters do not support a reliable classification.",
            },
            "required": True,
        }
        for item in summaries
    ]
    return state, questions


def _call_jev(api_key: str, state: dict[str, Any], questions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Call the documented System One API and validate every answer before use.

    Only rate-limit and overload responses are retried.  All other failures,
    including malformed JSON and schema drift, are fail-open and cause no
    firewall change.
    """
    body = json.dumps({"model": JEV_MODEL, "state": state, "questions": questions}, separators=(",", ":")).encode("utf-8")
    if len(body) > JEV_MAX_REQUEST_BYTES:
        raise JevResponseError("Jev request exceeds the bounded payload size")
    request_obj = urllib.request.Request(
        JEV_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    last_error: Optional[BaseException] = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request_obj, timeout=JEV_TIMEOUT_SECONDS) as response:
                raw = response.read(JEV_MAX_RESPONSE_BYTES + 1)
            if len(raw) > JEV_MAX_RESPONSE_BYTES:
                raise JevResponseError("Jev response exceeds the bounded size")
            parsed = json.loads(raw.decode("utf-8"))
            return _validate_jev_response(parsed, {question["id"] for question in questions})
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 529} or attempt == 2:
                raise
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt == 2:
                raise
        if attempt < 2:
            time.sleep(0.5 * (2 ** attempt))
    raise last_error if last_error is not None else JevResponseError("Jev call failed")


def _validate_jev_response(response: Any, expected_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Enforce the required model, usage, answer IDs, choices, and probabilities."""
    if not isinstance(response, dict) or not isinstance(response.get("model"), str):
        raise JevResponseError("missing model")
    usage = response.get("usage")
    if not isinstance(usage, dict):
        raise JevResponseError("missing usage")
    for field in ("input_tokens", "output_tokens"):
        if isinstance(usage.get(field), bool) or not isinstance(usage.get(field), int) or usage[field] < 0:
            raise JevResponseError("invalid usage")
    answers = response.get("answers")
    if not isinstance(answers, dict) or set(answers) != expected_ids:
        raise JevResponseError("answer IDs do not match questions")
    allowed = {"malicious", "benign", "insufficient"}
    normalized: dict[str, dict[str, Any]] = {}
    for question_id, answer in answers.items():
        if not isinstance(answer, dict) or answer.get("type") != "choice":
            raise JevResponseError("invalid answer type")
        choice = answer.get("choice")
        confidence = answer.get("confidence")
        probabilities = answer.get("probabilities")
        if choice not in allowed or isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise JevResponseError("invalid answer choice")
        if not 0 <= float(confidence) <= 1 or not isinstance(probabilities, dict) or set(probabilities) != allowed:
            raise JevResponseError("invalid confidence or probability keys")
        clean_probabilities: dict[str, float] = {}
        for key, value in probabilities.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= float(value) <= 1:
                raise JevResponseError("invalid probability")
            clean_probabilities[key] = float(value)
        if abs(sum(clean_probabilities.values()) - 1.0) > 0.001:
            raise JevResponseError("probabilities do not sum to one")
        if clean_probabilities[choice] + 0.001 < max(clean_probabilities.values()):
            raise JevResponseError("selected choice is not most probable")
        normalized[question_id] = {
            "choice": choice,
            "confidence": float(confidence),
            "probabilities": clean_probabilities,
        }
    return normalized


def _should_block(candidate: dict[str, Any], answer: dict[str, Any]) -> bool:
    """Block every suspicious candidate except a clearly benign Jev decision.

    A candidate is already limited to an open port and local signs of abuse.
    For this WAN-facing control, an ``insufficient`` answer, a malicious
    choice, low confidence, or any nonzero malicious probability is handled in
    the safer direction and blocked. API failures never reach this function.
    """
    if not _meets_local_block_guard(candidate.get("event_types", {}), int(candidate.get("event_total", 0))):
        return False
    return not (
        answer.get("choice") == "benign"
        and float(answer.get("confidence", 0)) >= CLEAR_BENIGN_CONFIDENCE_MINIMUM
        and float(answer.get("probabilities", {}).get("malicious", 0)) == 0.0
    )


def _meets_local_block_guard(events: dict[str, Any], total: int) -> bool:
    """Keep automatic blocks scoped to the local evidence needed for review."""
    normalized = {str(key): int(value) for key, value in events.items()}
    return _requires_review(normalized, total)


def _block_ip(ip_text: str) -> dict[str, Any]:
    """Add a verified public address to dedicated runtime and permanent drop ipsets.

    No firewalld reload is used.  The runtime block takes effect immediately;
    the permanent entry makes it survive a normal future firewalld restart.
    """
    try:
        parsed = ipaddress.ip_address(ip_text)
    except ValueError:
        return {"ok": False, "error": "invalid IP"}
    if not parsed.is_global:
        return {"ok": False, "error": "non-global IP"}
    name, family = (IPSET_V4, "inet") if parsed.version == 4 else (IPSET_V6, "inet6")
    if not _drop_zone_is_drop(False) or not _drop_zone_is_drop(True):
        return {"ok": False, "error": "drop zone target is not DROP"}
    for permanent in (True, False):
        if not _ensure_ipset(name, family, permanent):
            return {"ok": False, "error": "AI defense ipset is unavailable"}
        if not _ensure_drop_source(name, permanent):
            return {"ok": False, "error": "AI defense drop source is unavailable"}
    runtime_add = _firewall([f"--ipset={name}", f"--add-entry={parsed}"])
    if not runtime_add.ok and not _entry_already_present(runtime_add):
        return {"ok": False, "error": "runtime block could not be added"}
    permanent_add = _firewall(["--permanent", f"--ipset={name}", f"--add-entry={parsed}"])
    if not permanent_add.ok and not _entry_already_present(permanent_add):
        _firewall([f"--ipset={name}", f"--remove-entry={parsed}"])
        return {"ok": False, "error": "permanent block could not be added"}
    return {"ok": True, "ipset": name}


def unblock_ip(config_dir: Path | str, ip_text: str) -> dict[str, Any]:
    """Remove a recorded block permanently first, then remove its live entry."""
    try:
        parsed = ipaddress.ip_address(ip_text)
    except ValueError:
        return {"ok": False, "error": "IP アドレスの形式が正しくありません。"}
    name = IPSET_V4 if parsed.version == 4 else IPSET_V6
    permanent_remove = _firewall(["--permanent", f"--ipset={name}", f"--remove-entry={parsed}"])
    if not permanent_remove.ok and not _entry_absent(permanent_remove):
        return {"ok": False, "error": "永続設定から遮断を解除できませんでした。"}
    runtime_remove = _firewall([f"--ipset={name}", f"--remove-entry={parsed}"])
    if not runtime_remove.ok and not _entry_absent(runtime_remove):
        return {"ok": False, "error": "現在の遮断を解除できませんでした。"}
    store = ConfigStore(Path(config_dir))
    with store.transaction(MODULE_NAME, _default_state()) as stored:
        state = _normalise_state(stored)
        state["blocked"] = [item for item in state["blocked"] if not isinstance(item, dict) or item.get("ip") != str(parsed)]
        stored.clear()
        stored.update(state)
    return {"ok": True, "ip": str(parsed)}


def _firewall(args: list[str]):
    """Execute a fixed firewalld command without a shell or a reload operation."""
    return run(["firewall-cmd", *args], timeout=20)


def _drop_zone_is_drop(permanent: bool) -> bool:
    """Refuse automatic blocking unless both zone classifications use DROP."""
    args = (["--permanent"] if permanent else []) + ["--zone=drop", "--get-target"]
    result = _firewall(args)
    return result.ok and result.stdout.strip().upper() == "DROP"


def _ensure_ipset(name: str, family: str, permanent: bool) -> bool:
    """Create or verify the dedicated hash:ip set without adopting a foreign set."""
    prefix = ["--permanent"] if permanent else []
    info = _firewall([*prefix, f"--info-ipset={name}"])
    if info.ok:
        return _ipset_info_matches(info.stdout, family)
    created = _firewall([*prefix, f"--new-ipset={name}", "--type=hash:ip", f"--option=family={family}"])
    if not created.ok:
        return False
    verified = _firewall([*prefix, f"--info-ipset={name}"])
    return verified.ok and _ipset_info_matches(verified.stdout, family)


def _ipset_info_matches(output: str, family: str) -> bool:
    """Verify type and family before writing an entry into an existing ipset."""
    compact = re.sub(r"\s+", " ", output.lower())
    return "type: hash:ip" in compact and f"family={family}" in compact


def _ensure_drop_source(name: str, permanent: bool) -> bool:
    """Attach only the module-owned ipset to the drop zone when absent."""
    prefix = ["--permanent"] if permanent else []
    listed = _firewall([*prefix, "--zone=drop", "--list-sources"])
    source = f"ipset:{name}"
    if listed.ok and source in listed.stdout.split():
        return True
    added = _firewall([*prefix, "--zone=drop", f"--add-source={source}"])
    return added.ok or _entry_already_present(added)


def _entry_already_present(result: Any) -> bool:
    """Recognise firewalld's harmless duplicate-entry messages without broad matching."""
    text = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}".upper()
    return "ALREADY_ENABLED" in text or "ALREADY_EXISTS" in text


def _entry_absent(result: Any) -> bool:
    """Recognise an already-removed entry so manual unblock remains idempotent."""
    text = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}".upper()
    return "NOT_ENABLED" in text or "NOT_FOUND" in text or "INVALID_ENTRY" in text


def _timer_status() -> dict[str, Any]:
    """Inspect timer state without starting, stopping, or changing systemd state."""
    enabled = run(["systemctl", "is-enabled", AI_DEFENSE_TIMER], timeout=10)
    active = run(["systemctl", "is-active", AI_DEFENSE_TIMER], timeout=10)
    return {
        "unit": AI_DEFENSE_TIMER,
        "installed": (SYSTEMD_DIR / AI_DEFENSE_TIMER).exists(),
        "enabled": enabled.stdout.strip() in {"enabled", "enabled-runtime"},
        "active": active.stdout.strip() == "active",
    }


def ensure_runtime_units() -> dict[str, Any]:
    """Install the timer when a self-updated appliance already has the new binary.

    ISO installations receive the same units from synca-install.sh.  The binary
    existence guard makes source-tree imports and test environments side-effect
    free while allowing the regular GUI updater to add the timer safely.
    """
    if not RUNTIME_BINARY.is_file():
        return {"ok": False, "available": False, "message": "実行プログラムがまだ配置されていません。"}
    try:
        changed = _write_unit_if_changed(SYSTEMD_DIR / AI_DEFENSE_SERVICE, AI_DEFENSE_SERVICE_CONTENT)
        changed = _write_unit_if_changed(SYSTEMD_DIR / AI_DEFENSE_TIMER, AI_DEFENSE_TIMER_CONTENT) or changed
    except OSError:
        return {"ok": False, "available": False, "message": "systemd timer を準備できませんでした。"}
    if changed:
        reload_result = run(["systemctl", "daemon-reload"], timeout=30)
        if not reload_result.ok:
            return {"ok": False, "available": True, "message": "systemd の再読込に失敗しました。"}
    # Start the timer unit, not the defense service.  A newly updated appliance
    # must not wait for its next reboot before the configured cadence begins.
    enable_result = run(["systemctl", "enable", "--now", AI_DEFENSE_TIMER], timeout=30)
    if not enable_result.ok:
        return {"ok": False, "available": True, "message": "systemd timer を有効化できませんでした。"}
    return {"ok": True, "available": True, "changed": changed}


def _write_unit_if_changed(path: Path, content: str) -> bool:
    """Atomically replace one root-owned unit only when its exact content changed."""
    try:
        if path.read_text(encoding="utf-8") == content:
            return False
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass
        raise
    return True
