"""payload/server-gui/server_gui/modules/central_sso.py

SyncA UTM集中管理からの短時間SSOリンクを受け付け、通常アップデート後に
集中管理エージェント用の設定ファイルとsystemdタイマーを補完する。
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import subprocess
import time
from pathlib import Path

from flask import Blueprint, Flask, redirect, request, session

bp = Blueprint("central_sso", __name__, url_prefix="/central-sso")
logger = logging.getLogger(__name__)

CONFIG_PATH = Path("/etc/server-gui/central.json")
CREDS_PATH = Path("/etc/server-gui/credentials.json")
NONCE_DIR = Path("/var/lib/server-gui/central-sso-nonces")
CENTRAL_AGENT_PATH = Path("/opt/server-gui/bin/central-agent")
DEFAULT_CENTRAL_URL = "https://nsksys.com/syncautm/admin"
WINDOW_SECONDS = 300
CENTRAL_UNITS = {
    "synca-central-report.service": """[Unit]
Description=SyncA UTM 集中管理 状態送信
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/server-gui/bin/central-agent --report
StandardOutput=journal
StandardError=journal
""",
    "synca-central-report.timer": """[Unit]
Description=SyncA UTM 集中管理 状態送信タイマー

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
""",
    "synca-central-backup.service": """[Unit]
Description=SyncA UTM 集中管理 バックアップ送信
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/server-gui/bin/central-agent --backup-upload
StandardOutput=journal
StandardError=journal
""",
    "synca-central-backup.timer": """[Unit]
Description=SyncA UTM 集中管理 バックアップ送信タイマー

[Timer]
OnBootSec=10min
OnCalendar=*-*-* 03:20:00
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
""",
}


def register(app: Flask) -> None:
    app.register_blueprint(bp)
    try:
        _ensure_central_runtime()
    except Exception as exc:
        logger.warning("central runtime provisioning failed: %s", exc)


@bp.route("/login")
def login():
    config = _load_json(CONFIG_PATH)
    if not config.get("enabled", False):
        return "central SSO disabled", 403
    device = request.args.get("device", "")
    ts = request.args.get("ts", "")
    nonce = request.args.get("nonce", "")
    sig = request.args.get("sig", "")
    if not _valid_request(config, device, ts, nonce, sig):
        return "invalid central SSO token", 403
    creds = _load_json(CREDS_PATH)
    username = creds.get("username")
    if not username:
        return "local GUI credentials not initialized", 500
    session.clear()
    session["user"] = username
    session["csrf_token"] = secrets.token_urlsafe(32)
    next_url = request.args.get("next") or "/"
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"
    return redirect(next_url)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def _ensure_central_runtime() -> None:
    config = _load_json(CONFIG_PATH)
    changed = False

    if "enabled" not in config:
        config["enabled"] = _env_enabled()
        changed = True
    if not config.get("central_url"):
        config["central_url"] = os.environ.get("SYNCA_CENTRAL_URL", DEFAULT_CENTRAL_URL).strip().rstrip("/")
        changed = True
    for key, default in (
        ("device_id", ""),
        ("api_secret", ""),
        ("sso_secret", ""),
        ("gui_url", os.environ.get("SYNCA_CENTRAL_GUI_URL", "").strip()),
        ("family", os.environ.get("SYNCA_CENTRAL_FAMILY", _os_version_id()).strip()),
    ):
        if key not in config:
            config[key] = default
            changed = True
    if "backup_enabled" not in config:
        config["backup_enabled"] = os.environ.get("SYNCA_CENTRAL_BACKUP_ENABLED", "1") not in ("0", "false", "False", "no", "No")
        changed = True

    enrollment_token = os.environ.get("SYNCA_CENTRAL_ENROLLMENT_TOKEN", "").strip()
    already_enrolled = bool(config.get("device_id") and config.get("api_secret"))
    if enrollment_token and not already_enrolled and config.get("enrollment_token") != enrollment_token:
        config["enrollment_token"] = enrollment_token
        changed = True
    elif "enrollment_token" not in config:
        config["enrollment_token"] = ""
        changed = True

    if changed:
        _save_json(CONFIG_PATH, config)

    units_changed = _write_central_units()
    if units_changed:
        _systemctl("daemon-reload")
    if _can_start_timers(config):
        _systemctl("enable", "--now", "synca-central-report.timer", "synca-central-backup.timer")


def _env_enabled() -> bool:
    return os.environ.get("SYNCA_CENTRAL_ENABLED", "1") not in ("0", "false", "False", "no", "No")


def _os_version_id() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("VERSION_ID="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def _write_central_units() -> bool:
    if not CENTRAL_AGENT_PATH.exists():
        return False
    changed = False
    systemd_dir = Path("/etc/systemd/system")
    systemd_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name, content in CENTRAL_UNITS.items():
        path = systemd_dir / name
        if not path.exists() or path.read_text(encoding="utf-8", errors="replace") != content:
            path.write_text(content, encoding="utf-8")
            path.chmod(0o644)
            changed = True
    return changed


def _can_start_timers(config: dict) -> bool:
    if not config.get("enabled", False):
        return False
    if not config.get("central_url"):
        return False
    if config.get("device_id") and config.get("api_secret"):
        return True
    return bool(config.get("enrollment_token"))


def _systemctl(*args: str) -> None:
    subprocess.run(["systemctl"] + list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _valid_request(config: dict, device: str, ts: str, nonce: str, sig: str) -> bool:
    if device != config.get("device_id"):
        return False
    if not ts.isdigit() or abs(time.time() - int(ts)) > WINDOW_SECONDS:
        return False
    if not nonce or len(nonce) > 128 or "/" in nonce:
        return False
    if not _remember_nonce(nonce):
        return False
    secret = (config.get("sso_secret") or "").encode("utf-8")
    if not secret:
        return False
    message = f"{device}\n{ts}\n{nonce}".encode("utf-8")
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def _remember_nonce(nonce: str) -> bool:
    NONCE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = int(time.time())
    for path in NONCE_DIR.glob("*"):
        try:
            if now - int(path.stat().st_mtime) > WINDOW_SECONDS * 2:
                path.unlink()
        except OSError:
            pass
    marker = NONCE_DIR / nonce
    try:
        fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        return True
    except FileExistsError:
        return False
