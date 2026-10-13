"""payload/server-gui/server_gui/modules/wan_quality.py - WAN quality diagnostics.

This module measures the active IPv4 default route, WAN link counters, packet
loss and RTT against fixed public DNS resolvers, and HTTP upload/download
through Cloudflare's public speed endpoint.  Measurements are manual only so
the appliance never consumes WAN capacity in the background.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import math
import os
import re
import secrets
import socket
import struct
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from flask import Blueprint, Flask, current_app, jsonify, render_template

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run


bp = Blueprint("wan_quality", __name__, url_prefix="/wan-quality")

MODULE_NAME = "wan_quality"
HISTORY_LIMIT = 20
DOWNLOAD_BYTES = 20_000_000
UPLOAD_BYTES = 10_000_000
TRANSFER_CONNECT_TIMEOUT_SECONDS = 10
TRANSFER_MAX_SECONDS = 45
PING_COUNT = 4
PING_TIMEOUT_SECONDS = 2
PING_DEADLINE_SECONDS = PING_COUNT * (PING_TIMEOUT_SECONDS + 1)
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,64}$")

# The endpoints and targets are fixed in source code.  Operators cannot cause
# the appliance to fetch an arbitrary URL or execute ping with arbitrary input.
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=20000000"
UPLOAD_URL = "https://speed.cloudflare.com/__up"
LATENCY_TARGETS = (
    {"name": "Cloudflare DNS", "address": "1.1.1.1"},
    {"name": "Google Public DNS", "address": "8.8.8.8"},
    {"name": "Quad9 DNS", "address": "9.9.9.9"},
)


def register(app: Flask) -> None:
    """Register the authenticated WAN diagnostics page and JSON APIs."""
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    """Open the per-appliance configuration store for compact result history."""
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default_state() -> dict[str, Any]:
    """Return the schema used when this appliance has no prior measurement."""
    return {"history": [], "last_result": None}


@bp.route("/")
@login_required
def page():
    """Render the manual WAN quality diagnostics page."""
    return render_template("wan_quality.html", active_tab="wan_quality")


@bp.route("/api/status", methods=["GET"])
@login_required
def status():
    """Return only retained measurement results; this never starts a probe."""
    data = _store().load(MODULE_NAME, _default_state())
    return jsonify({
        "last_result": data.get("last_result"),
        "history": data.get("history", []),
        "measurement_notice": {
            "download_bytes": DOWNLOAD_BYTES,
            "upload_bytes": UPLOAD_BYTES,
            "latency_targets": list(LATENCY_TARGETS),
        },
    })


@bp.route("/api/run", methods=["POST"])
@login_required
@csrf_protect
def measure():
    """Run one serialised measurement and retain its compact result locally."""
    try:
        result = run_measurement(current_app.config["CONFIG_DIR"])
    except MeasurementBusy:
        return jsonify({"ok": False, "error": "別の WAN 回線品質診断が実行中です。"}), 409
    return jsonify(result), (200 if result.get("ok") else 503)


class MeasurementBusy(RuntimeError):
    """Raised when an operator starts a second measurement before the first ends."""


@contextmanager
def _exclusive_measurement_lock(config_dir: Path) -> Iterator[None]:
    """Hold a non-blocking file lock so concurrent HTTP requests cannot overlap."""
    config_dir.mkdir(parents=True, exist_ok=True)
    lock_path = config_dir / ".wan-quality-run.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MeasurementBusy from exc
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def run_measurement(config_dir: Path | str) -> dict[str, Any]:
    """Measure the current default WAN route and atomically record the result.

    The function has no Flask dependency so a future command-line diagnostic
    can reuse it.  It intentionally records values and generic failure states,
    never exception details that could expose local network configuration.
    """
    base_dir = Path(config_dir)
    with _exclusive_measurement_lock(base_dir):
        route = _default_ipv4_route()
        interface = _interface_snapshot(route.get("device", ""))
        device = route.get("device", "")
        # All probes use the same IPv4 WAN device. With no route, do not send
        # probes through an unrelated interface or an implicit IPv6 route.
        latency = [_ping_target(target, device) for target in LATENCY_TARGETS] if device else []
        download = _measure_http_transfer("download", DOWNLOAD_URL, DOWNLOAD_BYTES, device)
        upload = _measure_http_transfer("upload", UPLOAD_URL, UPLOAD_BYTES, device)
        result = {
            "ok": bool(device and (any(item["ok"] for item in latency) or download["ok"] or upload["ok"])),
            "measured_at": _now_iso(),
            "route": route,
            "interface": interface,
            "latency": latency,
            "download": download,
            "upload": upload,
            "quality": _quality_summary(route, latency, download, upload),
        }
        _save_result(base_dir, result)
        return result


def _save_result(config_dir: Path, result: dict[str, Any]) -> None:
    """Keep a bounded history so diagnostic storage cannot grow indefinitely."""
    store = ConfigStore(config_dir)
    with store.transaction(MODULE_NAME, _default_state()) as data:
        history = list(data.get("history", []))
        history.insert(0, result)
        data["history"] = history[:HISTORY_LIMIT]
        data["last_result"] = result


def _now_iso() -> str:
    """Generate a timezone-aware timestamp for operator-facing diagnostics."""
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _default_ipv4_route() -> dict[str, Any]:
    """Inspect the kernel route selected for a fixed public IPv4 destination."""
    result = run(["ip", "-j", "route", "get", "1.1.1.1"], timeout=10)
    if not result.ok:
        return {"device": "", "gateway": "", "source": "", "error": "IPv4 の既定経路を取得できませんでした。"}
    try:
        rows = json.loads(result.stdout)
        row = rows[0] if isinstance(rows, list) and rows else {}
    except (TypeError, ValueError):
        row = {}
    device = str(row.get("dev") or "")
    if not INTERFACE_RE.match(device):
        device = ""
    return {
        "device": device,
        "gateway": str(row.get("gateway") or ""),
        "source": str(row.get("prefsrc") or row.get("src") or ""),
        "error": "" if device else "IPv4 の既定経路を特定できませんでした。",
    }


def _read_sysfs_text(path: Path) -> Optional[str]:
    """Read one small sysfs value without surfacing host-path errors to the UI."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _read_sysfs_int(path: Path) -> Optional[int]:
    """Convert a sysfs counter to an integer, returning None for unavailable data."""
    value = _read_sysfs_text(path)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _interface_snapshot(device: str) -> dict[str, Any]:
    """Return link state and error counters for a validated route interface."""
    if not device or not INTERFACE_RE.match(device):
        return {"available": False, "device": ""}
    root = Path("/sys/class/net") / device
    if not root.exists():
        return {"available": False, "device": device}
    statistics = root / "statistics"
    return {
        "available": True,
        "device": device,
        "carrier": _read_sysfs_text(root / "carrier"),
        "operstate": _read_sysfs_text(root / "operstate"),
        "mtu": _read_sysfs_int(root / "mtu"),
        "speed_mbps": _read_sysfs_int(root / "speed"),
        "duplex": _read_sysfs_text(root / "duplex"),
        "rx_errors": _read_sysfs_int(statistics / "rx_errors"),
        "tx_errors": _read_sysfs_int(statistics / "tx_errors"),
        "rx_dropped": _read_sysfs_int(statistics / "rx_dropped"),
        "tx_dropped": _read_sysfs_int(statistics / "tx_dropped"),
    }


def _ping_target(target: dict[str, str], device: str) -> dict[str, Any]:
    """Measure one fixed IPv4 target with bounded, locale-independent ping.

    Older deployed ISOs may lack iputils. In that case the service's native
    ICMP implementation performs the same measurement without installing
    packages during a diagnostic request.
    """
    argv = ["env", "LC_ALL=C", "ping", "-4", "-n", "-c", str(PING_COUNT),
            "-W", str(PING_TIMEOUT_SECONDS), "-w", str(PING_DEADLINE_SECONDS)]
    if device and INTERFACE_RE.match(device):
        argv.extend(["-I", device])
    argv.append(target["address"])
    result = run(argv, timeout=PING_DEADLINE_SECONDS + 2)
    if result.returncode == 127:
        parsed = _native_icmp_probe(target["address"], device)
    else:
        parsed = _parse_ping_output(result.stdout)
        parsed["method"] = "ping"
        if not parsed["sent"]:
            parsed["error_code"] = "probe_unavailable"
            parsed["error"] = "遅延測定を実行できませんでした。測定コマンドの権限と設定を確認してください。"
    parsed.update({"name": target["name"], "address": target["address"], "ok": parsed["received"] > 0})
    if not parsed["ok"]:
        parsed.setdefault("error_code", "no_response")
        parsed.setdefault("error", "応答を受信できませんでした。")
    return parsed


def _icmp_checksum(data: bytes) -> int:
    """Compute the Internet checksum for an ICMP echo request."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _icmp_reply_matches(packet: bytes, identifier: int, sequence: int, payload: bytes) -> bool:
    """Accept only a complete IPv4 echo reply for this exact request.

    Raw sockets also receive our requests and unrelated ICMP packets. Check
    the IP header length, reply type, identifier, sequence, and random payload
    so neither an ICMP error nor another process's reply becomes a sample.
    """
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return False
    offset = (packet[0] & 0x0f) * 4
    if offset < 20 or len(packet) < offset + 8:
        return False
    kind, code, _, reply_id, reply_sequence = struct.unpack("!BBHHH", packet[offset:offset + 8])
    return (kind == 0 and code == 0 and reply_id == identifier
            and reply_sequence == sequence and packet[offset + 8:] == payload)


def _native_icmp_probe(address: str, device: str) -> dict[str, Any]:
    """Send four small ICMP probes when the installed image has no ping binary.

    The GUI service runs as root on the appliance. Bind to the measured WAN
    interface and give the complete probe a deadline, including unrelated
    received packets. No firewall, kernel, or package configuration is changed.
    """
    samples: list[float] = []
    sent = 0
    error_code = error = ""
    identifier = os.getpid() & 0xffff
    payload = secrets.token_bytes(24)
    deadline = time.monotonic() + PING_DEADLINE_SECONDS
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as probe:
            if device and INTERFACE_RE.match(device):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode("ascii") + b"\0")
            for sequence in range(1, PING_COUNT + 1):
                if time.monotonic() >= deadline:
                    break
                header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
                checksum = _icmp_checksum(header + payload)
                packet = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence) + payload
                started = time.monotonic()
                probe.sendto(packet, (address, 0))
                sent += 1
                sample_deadline = min(deadline, started + PING_TIMEOUT_SECONDS)
                while time.monotonic() < sample_deadline:
                    probe.settimeout(max(sample_deadline - time.monotonic(), 0.001))
                    try:
                        reply, source = probe.recvfrom(65535)
                    except socket.timeout:
                        break
                    if source[0] == address and _icmp_reply_matches(reply, identifier, sequence, payload):
                        samples.append((time.monotonic() - started) * 1000)
                        break
                if sequence < PING_COUNT:
                    time.sleep(max(0, min(1 - (time.monotonic() - started), deadline - time.monotonic())))
    except PermissionError:
        error_code = "probe_unavailable"
        error = "遅延測定に必要な権限がありません。iputils の導入と GUI サービスの権限を確認してください。"
    except OSError:
        error_code = "probe_error"
        error = "WAN インターフェースから遅延測定を実行できませんでした。"
    average = sum(samples) / len(samples) if samples else None
    result = {
        "sent": sent, "received": len(samples),
        "packet_loss_percent": round((sent - len(samples)) * 100 / sent, 1) if sent else None,
        "min_ms": round(min(samples), 3) if samples else None,
        "avg_ms": round(average, 3) if average is not None else None,
        "max_ms": round(max(samples), 3) if samples else None,
        "mdev_ms": round(math.sqrt(sum((value - average) ** 2 for value in samples) / len(samples)), 3) if samples else None,
        "method": "icmp_socket",
    }
    if error:
        result.update({"error_code": error_code, "error": error})
    return result


def _parse_ping_output(output: str) -> dict[str, Any]:
    """Parse conventional iputils ping output without assuming every summary exists."""
    sent = received = 0
    loss: Optional[float] = None
    match = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)(?:\s+packets)?\s+received.*?(\d+(?:\.\d+)?)%\s+packet loss", output)
    if match:
        sent, received = int(match.group(1)), int(match.group(2))
        loss = float(match.group(3))
    rtt_match = re.search(
        r"(?:rtt|round-trip).*?=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms",
        output,
    )
    values: dict[str, Optional[float]] = {"min_ms": None, "avg_ms": None, "max_ms": None, "mdev_ms": None}
    if rtt_match:
        values = {
            "min_ms": float(rtt_match.group(1)),
            "avg_ms": float(rtt_match.group(2)),
            "max_ms": float(rtt_match.group(3)),
            "mdev_ms": float(rtt_match.group(4)),
        }
    return {
        "sent": sent,
        "received": received,
        "packet_loss_percent": loss,
        **values,
    }


def _measure_http_transfer(direction: str, url: str, byte_count: int, device: str) -> dict[str, Any]:
    """Measure one bounded HTTP transfer and report its effective payload rate.

    curl fixes the address family and WAN interface and imposes a deadline on
    DNS, connection, TLS, and the body transfer together. urllib's per-socket
    timeout could be spent for each unusable IPv6 address and exceed the GUI's
    180-second request timeout. Only complete payloads count as speed results.
    """
    empty = {"ok": False, "bytes": 0, "duration_seconds": 0.0, "mbps": None, "error": ""}
    if not device or not INTERFACE_RE.match(device):
        return {**empty, "error_code": "route_unavailable", "error": "IPv4 の WAN 経路を確認できないため測定できません。"}
    argv = [
        "env", "LC_ALL=C", "curl", "--ipv4", "--silent", "--show-error", "--fail",
        "--noproxy", "*", "--interface", device,
        "--connect-timeout", str(TRANSFER_CONNECT_TIMEOUT_SECONDS),
        "--max-time", str(TRANSFER_MAX_SECONDS), "--max-filesize", str(byte_count),
        "--output", "/dev/null", "--user-agent", "SyncA-UTM-WAN-Quality/1.1",
        "--header", "Cache-Control: no-cache",
        "--write-out", "%{http_code}\t%{size_download}\t%{size_upload}\t%{time_total}",
    ]
    payload = None
    if direction == "upload":
        argv.extend(["--header", "Content-Type: application/octet-stream", "--header", "Expect:", "--data-binary", "@-"])
        payload = "\0" * byte_count
    argv.append(url)
    result = run(argv, timeout=TRANSFER_MAX_SECONDS + 5, stdin=payload)
    try:
        status, downloaded, uploaded, duration = result.stdout.strip().split("\t")
        transferred = int(float(uploaded if direction == "upload" else downloaded))
        elapsed = float(duration)
        if transferred < 0 or not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError
    except (ValueError, OverflowError):
        status, transferred, elapsed = "000", 0, 0.0
    complete = result.ok and status.isdigit() and 200 <= int(status) < 300 and transferred == byte_count and elapsed > 0
    data = {**empty, "ok": complete, "bytes": transferred, "duration_seconds": round(elapsed, 3)}
    if complete:
        data["mbps"] = round((transferred * 8) / elapsed / 1_000_000, 2)
        return data
    # Keep stable, actionable error codes without returning raw command output,
    # URL errors, or local environment details to the browser.
    errors = {
        127: ("probe_unavailable", "転送測定に必要な curl がありません。"),
        5: ("dns_error", "測定先の名前を解決できませんでした。DNS 設定を確認してください。"),
        6: ("dns_error", "測定先の名前を解決できませんでした。DNS 設定を確認してください。"),
        7: ("connection_error", "IPv4 の WAN 経路から測定先へ接続できませんでした。"),
        22: ("http_error", "測定先がエラーを返しました。時間を置いて再測定してください。"),
        28: ("timeout", "転送測定が時間の上限に達しました。"),
        124: ("timeout", "転送測定が時間の上限に達しました。"),
        35: ("tls_error", "測定先との TLS 接続に失敗しました。"),
        45: ("interface_error", "測定用の WAN インターフェースを利用できませんでした。"),
        60: ("certificate_error", "測定先の証明書を確認できませんでした。装置の時刻と CA 証明書を確認してください。"),
    }
    code, message = errors.get(result.returncode, ("incomplete_transfer", "測定データを最後まで転送できませんでした。"))
    return {**data, "error_code": code, "error": message}


def _quality_summary(
    route: dict[str, Any],
    latency: list[dict[str, Any]],
    download: dict[str, Any],
    upload: dict[str, Any],
) -> dict[str, str]:
    """Provide a conservative operational indicator, not an ISP fault verdict."""
    if not route.get("device"):
        return {"state": "unavailable", "label": "既定経路を確認できません", "reason": "IPv4 の既定経路がありません。"}
    responding = [item for item in latency if item.get("ok")]
    if not responding and not download.get("ok") and not upload.get("ok"):
        return {"state": "error", "label": "外部到達を確認できません", "reason": "遅延または転送の測定先へ到達できませんでした。"}
    has_loss = any((item.get("packet_loss_percent") or 0) > 2 for item in responding)
    has_delay = any((item.get("avg_ms") or 0) >= 100 or (item.get("mdev_ms") or 0) >= 20 for item in responding)
    missing_latency = not latency or any(not item.get("ok") for item in latency)
    if has_loss or has_delay or missing_latency or not download.get("ok") or not upload.get("ok"):
        return {"state": "warning", "label": "要確認", "reason": "損失、遅延の増加、または測定できなかった項目がありました。"}
    return {"state": "good", "label": "今回の測定では大きな異常なし", "reason": "固定の参照先に対する一回の測定結果です。"}
