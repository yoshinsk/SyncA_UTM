"""Admin module — password change + GitHub-based self-update.

Settings live in /etc/server-gui/admin.json:
    {
      "github_url":      "https://github.com/owner/repo",  # blank = disabled
      "branch":          "main",
      "installed_sha":   "abc1234...",   # set by install.sh or by apply_update
      "last_check_at":   "2026-05-15T...",
      "latest_sha":      "def5678...",
      "latest_message":  "commit subject line",
      "update_available": false,
      "last_apply_at":   "2026-05-15T...",
      "last_apply_ok":   true,
      "last_apply_log":  "..."
    }

Daily check is driven by a systemd timer (server-gui-update-check.timer) that
imports `_run_update_check()` from this module. The same routine backs the
"今すぐ確認" button.

Apply pipeline:
  1. Download <github_url>/archive/refs/heads/<branch>.tar.gz to /tmp
  2. Extract to /tmp/server-gui-update-<sha>/ — must contain a server_gui/
     directory (we reject malformed archives)
  3. Atomically swap /opt/server-gui/server_gui with the new copy:
        mv server_gui server_gui.old.<ts>
        mv server_gui.new server_gui
  4. Update admin.json installed_sha + log
  5. Schedule a systemd-run --no-block systemctl restart so the response
     can return cleanly before the process dies
"""
from __future__ import annotations

import datetime as _dt
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from flask import Blueprint, Flask, current_app, jsonify, render_template, request, session
from werkzeug.security import check_password_hash

from ..auth import csrf_protect, login_required, set_password
from ..config_store import ConfigStore

logger = logging.getLogger(__name__)

bp = Blueprint("admin", __name__, url_prefix="/admin")

MODULE_NAME = "admin"
INSTALL_DIR = Path("/opt/server-gui")
SERVER_GUI_PKG = INSTALL_DIR / "server_gui"
SERVER_GUI_BIN = INSTALL_DIR / "bin"
DEFAULT_GITHUB_URL = "https://github.com/yoshinsk/SyncA_UTM"
DEFAULT_GITHUB_BRANCH = os.environ.get("SYNCA_UPDATE_BRANCH", "main").strip() or "main"

# Match the GitHub URL formats we accept. Allow optional .git suffix and
# optional trailing slash. https only.
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*?)(?:\.git)?/?$"
)
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_PASSWORD_MIN_LEN = 8
_PASSWORD_MAX_LEN = 256
_HTTP_TIMEOUT = 15
_DOWNLOAD_TIMEOUT = 120
_MAX_ARCHIVE_BYTES = 200 * 1024 * 1024  # 200 MiB sanity cap
_COMMAND_TIMEOUT_MAX = 300
_COMMAND_OUTPUT_MAX = 128 * 1024
_COMMAND_AUDIT_LOG = Path("/var/log/server-gui/admin-command.log")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default() -> dict:
    return {
        "github_url": DEFAULT_GITHUB_URL,
        "branch": DEFAULT_GITHUB_BRANCH,
        "installed_sha": "",
        "last_check_at": None,
        "latest_sha": "",
        "latest_message": "",
        "update_available": False,
        "last_apply_at": None,
        "last_apply_ok": None,
        "last_apply_log": "",
    }


def _now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


# ---- views --------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("admin.html", active_tab="admin")


@bp.route("/api/settings", methods=["GET"])
@login_required
def get_settings():
    """Return GitHub config + last-check metadata. Never returns secrets."""
    data = _store().load(MODULE_NAME, _default())
    return jsonify({
        "github_url": data.get("github_url", ""),
        "branch": data.get("branch", "main"),
        "installed_sha": data.get("installed_sha", ""),
        "last_check_at": data.get("last_check_at"),
        "latest_sha": data.get("latest_sha", ""),
        "latest_message": data.get("latest_message", ""),
        "update_available": bool(data.get("update_available")),
        "last_apply_at": data.get("last_apply_at"),
        "last_apply_ok": data.get("last_apply_ok"),
        "last_apply_log": data.get("last_apply_log", ""),
        "username": session.get("user", ""),
    })


@bp.route("/api/command", methods=["POST"])
@login_required
@csrf_protect
def run_admin_command():
    """Run an arbitrary administrator command after password re-authentication."""
    payload = request.get_json(force=True, silent=True) or {}
    password = payload.get("password") or ""
    command = (payload.get("command") or "").strip()
    timeout_raw = payload.get("timeout", 30)

    if not command:
        return jsonify({"error": "command required"}), 400
    if "\x00" in command or len(command) > 4000:
        return jsonify({"error": "invalid command"}), 400
    try:
        timeout = int(timeout_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid timeout"}), 400
    if not (1 <= timeout <= _COMMAND_TIMEOUT_MAX):
        return jsonify({"error": f"timeout must be 1..{_COMMAND_TIMEOUT_MAX} seconds"}), 400
    if not _check_current_password(password):
        return jsonify({"error": "current password is invalid"}), 401

    started = _now_iso()
    user = session.get("user", "")
    logger.warning("admin command requested by %s: %s", user, command)
    try:
        proc = subprocess.run(
            ["sudo", "-n", "/bin/bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        rc = proc.returncode
        stdout = _truncate_output(proc.stdout)
        stderr = _truncate_output(proc.stderr)
    except subprocess.TimeoutExpired as e:
        rc = 124
        stdout = _truncate_output(e.stdout or "")
        stderr = _truncate_output(e.stderr or "")
        stderr = _truncate_output(stderr + "\n[timeout]")

    _write_command_audit({
        "started_at": started,
        "finished_at": _now_iso(),
        "user": user,
        "remote_addr": request.remote_addr or "",
        "returncode": rc,
        "timeout": timeout,
        "command": command,
    })
    return jsonify({"ok": rc == 0, "returncode": rc, "stdout": stdout, "stderr": stderr})


def _check_current_password(password: str) -> bool:
    creds_path = Path(current_app.config["CONFIG_DIR"]) / "credentials.json"
    try:
        creds = json.loads(creds_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False
    return check_password_hash(creds.get("password_hash", ""), password)


def _truncate_output(value: str) -> str:
    if not isinstance(value, str):
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).decode("utf-8", errors="replace")
        else:
            value = str(value)
    if len(value.encode("utf-8", errors="replace")) <= _COMMAND_OUTPUT_MAX:
        return value
    encoded = value.encode("utf-8", errors="replace")[:_COMMAND_OUTPUT_MAX]
    return encoded.decode("utf-8", errors="replace") + "\n[truncated]"


def _write_command_audit(record: dict) -> None:
    try:
        _COMMAND_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _COMMAND_AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        _COMMAND_AUDIT_LOG.chmod(0o600)
    except OSError as e:
        logger.error("failed to write admin command audit log: %s", e)


# ---- password change ----------------------------------------------------

@bp.route("/api/password", methods=["POST"])
@login_required
@csrf_protect
def change_password():
    payload = request.get_json(force=True, silent=True) or {}
    current = payload.get("current_password") or ""
    new = payload.get("new_password") or ""
    confirm = payload.get("confirm_password") or ""

    if not current or not new or not confirm:
        return jsonify({"error": "全てのフィールドを入力してください"}), 400
    if new != confirm:
        return jsonify({"error": "新しいパスワードと確認が一致しません"}), 400
    if len(new) < _PASSWORD_MIN_LEN:
        return jsonify({"error": f"新しいパスワードは{_PASSWORD_MIN_LEN}文字以上必要です"}), 400
    if len(new) > _PASSWORD_MAX_LEN:
        return jsonify({"error": f"パスワードが長すぎます (最大 {_PASSWORD_MAX_LEN} 文字)"}), 400

    creds_path = Path(current_app.config["CONFIG_DIR"]) / "credentials.json"
    try:
        creds = json.loads(creds_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        return jsonify({"error": f"認証情報を読み込めません: {e}"}), 500

    if not check_password_hash(creds.get("password_hash", ""), current):
        return jsonify({"error": "現在のパスワードが正しくありません"}), 401

    try:
        set_password(creds.get("username", "admin"), new,
                     Path(current_app.config["CONFIG_DIR"]))
    except OSError as e:
        return jsonify({"error": f"保存に失敗しました: {e}"}), 500

    logger.info("admin password changed for user=%r", creds.get("username"))
    return jsonify({"ok": True})


# ---- GitHub URL settings ------------------------------------------------

@bp.route("/api/github", methods=["POST"])
@login_required
@csrf_protect
def save_github():
    payload = request.get_json(force=True, silent=True) or {}
    url = (payload.get("github_url") or "").strip()
    branch = (payload.get("branch") or "main").strip() or "main"

    if url and not _GITHUB_URL_RE.match(url):
        return jsonify({
            "error": "GitHub URL は https://github.com/<owner>/<repo> 形式である必要があります"
        }), 400
    if not _BRANCH_RE.match(branch):
        return jsonify({"error": "ブランチ名が無効です"}), 400

    with _store().transaction(MODULE_NAME, _default()) as data:
        data["github_url"] = url
        data["branch"] = branch
        if not url:
            # Clearing the URL — also clear cached check state to avoid stale UI
            data["latest_sha"] = ""
            data["latest_message"] = ""
            data["update_available"] = False
            data["last_check_at"] = None

    return jsonify({"ok": True})


# ---- update check (manual + timer) -------------------------------------

@bp.route("/api/update/check", methods=["POST"])
@login_required
@csrf_protect
def check_update():
    try:
        result = _run_update_check()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


def _run_update_check(config_dir: Optional[Path] = None) -> dict:
    """Hit the GitHub API for the latest commit on the configured branch.

    Updates admin.json in place. Returns the same dict as /api/settings
    so the caller can refresh the UI without a second request.

    Reused by both the HTTP endpoint and the systemd timer entrypoint
    (which passes config_dir explicitly because there's no Flask app context).
    """
    store = ConfigStore(config_dir or current_app.config["CONFIG_DIR"])
    data = store.load(MODULE_NAME, _default())
    url = data.get("github_url", "").strip()
    branch = data.get("branch", "main").strip() or "main"
    if not url:
        raise RuntimeError("GitHub URL が未設定です")
    m = _GITHUB_URL_RE.match(url)
    if not m:
        raise RuntimeError("GitHub URL の形式が不正です")
    owner, repo = m.group(1), m.group(2)

    api = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
    req = urllib.request.Request(api, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "SyncA-UTM-update-check",
    })
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub API: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"GitHub に接続できません: {e.reason}") from e
    try:
        commit = json.loads(body)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"GitHub 応答を JSON として解釈できません: {e}") from e

    latest_sha = commit.get("sha") or ""
    msg = (commit.get("commit") or {}).get("message", "").splitlines()[0] if commit.get("commit") else ""

    with store.transaction(MODULE_NAME, _default()) as data2:
        # Unknown local builds must stay unknown. Fresh ISO installs can carry
        # stale bundled files, so treating an empty installed_sha as "latest"
        # hides the only safe remediation path: applying the GitHub update.
        installed_sha = data2.get("installed_sha") or ""
        data2["installed_sha"] = installed_sha
        data2["latest_sha"] = latest_sha
        data2["latest_message"] = msg
        data2["last_check_at"] = _now_iso()
        data2["update_available"] = (
            bool(latest_sha) and latest_sha != installed_sha
        )

    return {
        "ok": True,
        "installed_sha": data2["installed_sha"],
        "latest_sha": latest_sha,
        "latest_message": msg,
        "update_available": data2["update_available"],
        "last_check_at": data2["last_check_at"],
    }


# ---- apply update (download + replace + restart) ------------------------

@bp.route("/api/update/apply", methods=["POST"])
@login_required
@csrf_protect
def apply_update():
    settings = _store().load(MODULE_NAME, _default())
    url = settings.get("github_url", "").strip()
    branch = settings.get("branch", "main").strip() or "main"
    latest_sha = settings.get("latest_sha", "")
    if not url:
        return jsonify({"error": "GitHub URL が未設定です"}), 400
    if not settings.get("update_available"):
        return jsonify({"error": "更新は利用できません (先に確認してください)"}), 400

    m = _GITHUB_URL_RE.match(url)
    if not m:
        return jsonify({"error": "GitHub URL の形式が不正です"}), 400
    owner, repo = m.group(1), m.group(2)
    tarball = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"

    log_lines: list[str] = []

    def _log(msg: str) -> None:
        log_lines.append(f"{_now_iso()} {msg}")
        logger.info("apply_update: %s", msg)

    _log(f"download {tarball}")
    try:
        with urllib.request.urlopen(tarball, timeout=_DOWNLOAD_TIMEOUT) as resp:
            buf = resp.read(_MAX_ARCHIVE_BYTES + 1)
    except urllib.error.URLError as e:
        return _apply_failure(f"ダウンロード失敗: {e.reason}", log_lines)
    if len(buf) > _MAX_ARCHIVE_BYTES:
        return _apply_failure("アーカイブが大きすぎます", log_lines)
    _log(f"received {len(buf)} bytes")

    # Extract into a temp dir
    extract_root = Path(tempfile.mkdtemp(prefix="server-gui-update-"))
    try:
        with tarfile.open(fileobj=io.BytesIO(buf), mode="r:gz") as tf:
            _safe_extract(tf, extract_root)
        # GitHub archives put everything under a single top-level dir:
        # repo-branch/  →  find it.
        children = list(extract_root.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            return _apply_failure("アーカイブ構造が不正です (top-level dir なし)", log_lines)
        new_root = children[0]
        payload_root = _find_update_payload_root(new_root)
        new_pkg = payload_root / "server_gui"
        if not new_pkg.is_dir():
            return _apply_failure(
                "アーカイブに server_gui/ ディレクトリがありません", log_lines)
        _log(f"extracted {new_root.name}")

        # Atomically swap the package dir
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        old_backup = SERVER_GUI_PKG.with_name(f"server_gui.old.{ts}")
        try:
            if SERVER_GUI_PKG.exists():
                SERVER_GUI_PKG.rename(old_backup)
                _log(f"moved old package to {old_backup}")
            shutil.copytree(new_pkg, SERVER_GUI_PKG)
            _log("installed new package")
            new_bin = payload_root / "bin"
            if new_bin.is_dir():
                bin_backup = SERVER_GUI_BIN.with_name(f"bin.old.{ts}")
                if SERVER_GUI_BIN.exists():
                    SERVER_GUI_BIN.rename(bin_backup)
                    _log(f"moved old bin to {bin_backup}")
                shutil.copytree(new_bin, SERVER_GUI_BIN)
                for path in SERVER_GUI_BIN.iterdir():
                    if path.is_file():
                        path.chmod(path.stat().st_mode | 0o111)
                _log("installed new bin scripts")
        except OSError as e:
            # roll back if we managed to move the old one
            if old_backup.exists() and not SERVER_GUI_PKG.exists():
                try:
                    old_backup.rename(SERVER_GUI_PKG)
                except OSError:
                    pass
            return _apply_failure(f"ファイル置換失敗: {e}", log_lines)

        # Also refresh /opt/server-gui/bin/* and systemd unit files if the
        # update changed them. (Skip for now — keeping minimum-disruption.)

        # Record success + new installed_sha
        with _store().transaction(MODULE_NAME, _default()) as data:
            data["installed_sha"] = latest_sha or data.get("installed_sha", "")
            data["update_available"] = False
            data["last_apply_at"] = _now_iso()
            data["last_apply_ok"] = True
            data["last_apply_log"] = "\n".join(log_lines)

        # Schedule the systemd restart so it survives our process dying.
        # systemd-run --no-block returns immediately; the actual restart
        # happens after we've finished returning the response.
        try:
            subprocess.Popen([
                "sudo", "-n",
                "systemd-run", "--no-block", "--",
                "systemctl", "restart", "server-gui.service",
            ])
            _log("scheduled systemctl restart server-gui.service")
        except OSError as e:
            _log(f"WARNING: could not schedule restart: {e}")

        return jsonify({
            "ok": True,
            "installed_sha": latest_sha,
            "log": "\n".join(log_lines),
            "note": "サービスを再起動しています。10 秒ほど待って画面を再読み込みしてください。",
        })
    finally:
        try:
            shutil.rmtree(extract_root)
        except OSError:
            pass


def _apply_failure(reason: str, log_lines: list[str]):
    log_lines.append(f"{_now_iso()} FAIL: {reason}")
    with _store().transaction(MODULE_NAME, _default()) as data:
        data["last_apply_at"] = _now_iso()
        data["last_apply_ok"] = False
        data["last_apply_log"] = "\n".join(log_lines)
    return jsonify({"error": reason, "log": "\n".join(log_lines)}), 500


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Path-traversal-safe tar extraction.

    Reject any member whose resolved path escapes `dest`. Refuse links and
    devices entirely — we only want regular files + directories from a
    GitHub source archive.
    """
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        if member.islnk() or member.issym() or member.isdev():
            raise RuntimeError(f"unsafe archive member: {member.name}")
        target = (dest / member.name).resolve()
        try:
            target.relative_to(dest_resolved)
        except ValueError:
            raise RuntimeError(f"path-traversal member: {member.name}")
    tf.extractall(dest)


def _find_update_payload_root(extracted_root: Path) -> Path:
    """Return the directory that contains server_gui/ in a GitHub archive."""
    candidates = [
        extracted_root / "payload" / "server-gui",
        extracted_root,
    ]
    for candidate in candidates:
        if (candidate / "server_gui").is_dir():
            return candidate
    return extracted_root
