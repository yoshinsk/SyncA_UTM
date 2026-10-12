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
import os
import re
import time
import urllib.error
import urllib.request
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
TRANSFER_TIMEOUT_SECONDS = 60
TRANSFER_MAX_SECONDS = 75
PING_COUNT = 4
PING_TIMEOUT_SECONDS = 2
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
        latency = [_ping_target(target, route.get("device", "")) for target in LATENCY_TARGETS]
        download = _measure_http_transfer("download", DOWNLOAD_URL, DOWNLOAD_BYTES)
        upload = _measure_http_transfer("upload", UPLOAD_URL, UPLOAD_BYTES)
        result = {
            "ok": bool(route.get("device")),
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
    """Ping one fixed target and parse Linux ping loss and RTT summary lines."""
    argv = ["ping", "-4", "-n", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT_SECONDS)]
    if device and INTERFACE_RE.match(device):
        argv.extend(["-I", device])
    argv.append(target["address"])
    result = run(argv, timeout=(PING_COUNT * (PING_TIMEOUT_SECONDS + 1)) + 5)
    parsed = _parse_ping_output(result.stdout)
    parsed.update({"name": target["name"], "address": target["address"], "ok": parsed["received"] > 0})
    if not parsed["ok"]:
        parsed["error"] = "応答を受信できませんでした。"
    return parsed


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


def _measure_http_transfer(direction: str, url: str, byte_count: int) -> dict[str, Any]:
    """Measure one bounded HTTP transfer and report its effective payload rate.

    The byte limit and deadline prevent a slow or unavailable external service
    from occupying a gunicorn worker indefinitely.  The destination is fixed
    by the module constants, not supplied by a browser request.
    """
    started = time.monotonic()
    transferred = 0
    try:
        headers = {"User-Agent": "SyncA-UTM-WAN-Quality/1.0", "Cache-Control": "no-cache"}
        if direction == "upload":
            request = urllib.request.Request(url, data=b"\0" * byte_count, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=TRANSFER_TIMEOUT_SECONDS) as response:
                while response.read(65536):
                    _ensure_transfer_deadline(started)
            transferred = byte_count
        else:
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=TRANSFER_TIMEOUT_SECONDS) as response:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    transferred += len(chunk)
                    _ensure_transfer_deadline(started)
        elapsed = max(time.monotonic() - started, 0.001)
        return {
            "ok": transferred > 0,
            "bytes": transferred,
            "duration_seconds": round(elapsed, 3),
            "mbps": round((transferred * 8) / elapsed / 1_000_000, 2),
            "error": "",
        }
    except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError, OSError):
        return {
            "ok": False,
            "bytes": transferred,
            "duration_seconds": round(max(time.monotonic() - started, 0.0), 3),
            "mbps": None,
            "error": "測定先に接続できないか、測定時間の上限に達しました。",
        }


def _ensure_transfer_deadline(started: float) -> None:
    """Stop a transfer after the module-wide wall-clock budget."""
    if time.monotonic() - started > TRANSFER_MAX_SECONDS:
        raise TimeoutError("WAN transfer deadline exceeded")


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
    if has_loss or has_delay or not download.get("ok") or not upload.get("ok"):
        return {"state": "warning", "label": "要確認", "reason": "損失、遅延の増加、または転送測定の失敗がありました。"}
    return {"state": "good", "label": "今回の測定では大きな異常なし", "reason": "固定の参照先に対する一回の測定結果です。"}
