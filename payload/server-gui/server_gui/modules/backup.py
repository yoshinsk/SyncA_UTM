"""payload/server-gui/server_gui/modules/backup.py

Full-system backup and restore for SyncA UTM managed runtime state.

The archive is intentionally sensitive. It can contain administrator password
hashes, DDNS credentials, WireGuard private keys, IPsec PSKs, certbot account
material, and TLS private keys. The purpose is disaster recovery and ISO parity
validation, not casual export.
"""
from __future__ import annotations

import datetime as _dt
import io
import json
import logging
import os
import platform
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from flask import Blueprint, Flask, jsonify, render_template, request, send_file

from ..auth import csrf_protect, login_required

logger = logging.getLogger(__name__)

bp = Blueprint("backup", __name__, url_prefix="/backup")

BACKUP_STORE = Path("/var/lib/server-gui/backups")
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
ARCHIVE_VERSION = 2
SUPPORTED_ARCHIVE_VERSIONS = {1, 2}

BACKUP_SPECS: tuple[dict, ...] = (
    {"section": "server_gui_config", "paths": ["/etc/server-gui"]},
    {"section": "server_gui_app", "paths": [
        "/opt/server-gui/bin",
        "/opt/server-gui/server_gui",
        "/opt/server-gui/requirements.txt",
    ]},
    {"section": "wireguard_ui", "paths": ["/opt/wireguard"]},
    {"section": "systemd", "globs": [
        "/etc/systemd/system/server-gui*",
        "/etc/systemd/system/wgui*",
        "/etc/systemd/system/multi-user.target.wants/server-gui*",
        "/etc/systemd/system/multi-user.target.wants/wgui*",
        "/etc/systemd/system/timers.target.wants/server-gui*",
    ]},
    {"section": "nginx", "paths": ["/etc/nginx"]},
    {"section": "dnsmasq", "paths": [
        "/etc/dnsmasq.conf",
        "/etc/dnsmasq.d",
        "/var/lib/dnsmasq",
    ]},
    {"section": "wireguard", "paths": ["/etc/wireguard"]},
    {"section": "firewalld", "paths": ["/etc/firewalld"]},
    {"section": "network", "paths": [
        "/etc/NetworkManager/NetworkManager.conf",
        "/etc/NetworkManager/conf.d",
        "/etc/NetworkManager/dispatcher.d",
        "/etc/NetworkManager/system-connections",
        "/etc/sysconfig/network",
        "/etc/sysconfig/network-scripts",
    ]},
    {"section": "fail2ban", "paths": ["/etc/fail2ban"]},
    {"section": "letsencrypt", "paths": ["/etc/letsencrypt"]},
    {"section": "server_gui_state", "paths": [
        "/var/lib/server-gui",
        "/var/log/server-gui",
    ]},
)

EXCLUDE_PREFIXES = (
    "/var/lib/server-gui/backups/",
    "/var/lib/server-gui/pre-restore/",
)
EXCLUDE_NAME_PATTERNS = (
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.pre-v2-*",
    "*.bak",
)

RESTORE_SECTION_PREFIXES = {
    "server_gui_config": ("/etc/server-gui/",),
    "server_gui_app": ("/opt/server-gui/bin/", "/opt/server-gui/server_gui/", "/opt/server-gui/requirements.txt"),
    "wireguard_ui": ("/opt/wireguard/",),
    "systemd": ("/etc/systemd/system/",),
    "nginx": ("/etc/nginx/",),
    "dnsmasq": ("/etc/dnsmasq.conf", "/etc/dnsmasq.d/", "/var/lib/dnsmasq/"),
    "wireguard": ("/etc/wireguard/",),
    "firewalld": ("/etc/firewalld/",),
    "network": ("/etc/NetworkManager/", "/etc/sysconfig/network", "/etc/sysconfig/network-scripts/"),
    "fail2ban": ("/etc/fail2ban/",),
    "letsencrypt": ("/etc/letsencrypt/",),
    "server_gui_state": ("/var/lib/server-gui/", "/var/log/server-gui/"),
}

LEGACY_SECTION_ALIASES = {
    "include_server_gui": ("server_gui_config",),
    "include_nginx": ("nginx",),
    "include_dnsmasq": ("dnsmasq",),
    "include_wireguard": ("wireguard",),
    "include_firewalld": ("firewalld",),
}


def register(app: Flask) -> None:
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def page():
    return render_template("backup.html", active_tab="backup")


@bp.route("/api/list", methods=["GET"])
@login_required
def list_backups():
    BACKUP_STORE.mkdir(parents=True, exist_ok=True)
    items: list[dict] = []
    for p in sorted(BACKUP_STORE.glob("server-gui-*.tar.gz"), reverse=True):
        try:
            st = p.stat()
        except OSError:
            continue
        items.append({"name": p.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    return jsonify({"backups": items, "store": str(BACKUP_STORE)})


@bp.route("/api/create", methods=["POST"])
@login_required
@csrf_protect
def create_backup():
    BACKUP_STORE.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"server-gui-{timestamp}.tar.gz"
    out_path = BACKUP_STORE / name
    files = _collect_files()
    manifest = _build_manifest(files)

    try:
        with tarfile.open(out_path, "w:gz") as tar:
            manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = int(_dt.datetime.now().timestamp())
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(manifest_bytes))
            for item in files:
                src = item["path"]
                if src.exists() or src.is_symlink():
                    tar.add(src, arcname="files" + str(src), recursive=False)
        out_path.chmod(0o600)
    except Exception as e:
        if out_path.exists():
            out_path.unlink(missing_ok=True)
        logger.exception("backup creation failed")
        return jsonify({"ok": False, "error": str(e)}), 500

    st = out_path.stat()
    return jsonify({
        "ok": True,
        "name": name,
        "path": str(out_path),
        "size": st.st_size,
        "file_count": len(files),
        "sections": _section_counts(files),
    })


@bp.route("/api/download/<name>", methods=["GET"])
@login_required
def download_backup(name: str):
    if not _safe_backup_name(name):
        return jsonify({"error": "invalid backup name"}), 400
    p = BACKUP_STORE / name
    if not p.is_file():
        return jsonify({"error": "not found"}), 404
    return send_file(str(p), as_attachment=True, download_name=name, mimetype="application/gzip")


@bp.route("/api/delete/<name>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_backup(name: str):
    if not _safe_backup_name(name):
        return jsonify({"error": "invalid backup name"}), 400
    p = BACKUP_STORE / name
    if not p.is_file():
        return jsonify({"error": "not found"}), 404
    try:
        p.unlink()
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@bp.route("/api/restore", methods=["POST"])
@login_required
@csrf_protect
def restore_backup():
    archive_bytes: Optional[bytes] = None

    if request.content_type and request.content_type.startswith("multipart/"):
        f = request.files.get("archive")
        if f is None:
            return jsonify({"error": "no archive uploaded"}), 400
        archive_bytes = f.read(MAX_UPLOAD_BYTES + 1)
        if len(archive_bytes) > MAX_UPLOAD_BYTES:
            return jsonify({"error": "archive too large"}), 413
        sections = _sections_from_mapping(request.form)
    else:
        payload = request.get_json(force=True, silent=True) or {}
        sections = _sections_from_mapping(payload)
        name = payload.get("name")
        if not name:
            return jsonify({"error": "name required"}), 400
        if not _safe_backup_name(name):
            return jsonify({"error": "invalid backup name"}), 400
        p = BACKUP_STORE / name
        if not p.is_file():
            return jsonify({"error": "backup not found"}), 404
        archive_bytes = p.read_bytes()

    with tempfile.TemporaryDirectory(prefix="server-gui-restore-") as tmpdir:
        staging = Path(tmpdir)
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                _safe_extract(tar, staging)
        except (tarfile.TarError, OSError) as e:
            return jsonify({"error": f"failed to read archive: {e}"}), 400

        manifest_path = staging / "manifest.json"
        if not manifest_path.is_file():
            return jsonify({"error": "manifest.json missing; not a server-gui backup"}), 400
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return jsonify({"error": f"manifest unreadable: {e}"}), 400
        if manifest.get("version") not in SUPPORTED_ARCHIVE_VERSIONS:
            return jsonify({"error": f"unsupported archive version: {manifest.get('version')!r}"}), 400

        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        pre = Path(f"/var/lib/server-gui/pre-restore/{ts}")
        pre.mkdir(parents=True, exist_ok=True)

        applied: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []
        for src in _walk_files(staging / "files"):
            target = Path("/") / src.relative_to(staging / "files")
            if not _restore_section_allowed(target, sections):
                skipped.append(str(target))
                continue
            try:
                _backup_existing(target, pre)
                _restore_one(src, target)
                applied.append(str(target))
            except (OSError, shutil.Error) as e:
                errors.append(f"{target}: {e}")

        return jsonify({
            "ok": not errors,
            "manifest": manifest,
            "applied": applied,
            "skipped": skipped,
            "errors": errors,
            "pre_restore_dir": str(pre),
            "restart_hint": [
                "systemctl daemon-reload",
                "systemctl restart NetworkManager firewalld dnsmasq nginx fail2ban server-gui",
                "systemctl restart wg-quick@wg0 wgui-worker",
            ],
        })


def _safe_backup_name(name: str) -> bool:
    return bool(re.match(r"^server-gui-\d{8}-\d{6}\.tar\.gz$", name))


def _build_manifest(files: list[dict]) -> dict:
    return {
        "version": ARCHIVE_VERSION,
        "created_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "hostname": _read_hostname(),
        "os_release": _read_os_release(),
        "kernel": platform.release(),
        "file_count": len(files),
        "sections": _section_counts(files),
        "warning": "Sensitive archive: contains secrets and private keys.",
    }


def _read_hostname() -> str:
    try:
        return Path("/etc/hostname").read_text(encoding="utf-8").strip()
    except OSError:
        return platform.node()


def _read_os_release() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Unknown"


def _collect_files() -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for spec in BACKUP_SPECS:
        section = spec["section"]
        for raw in spec.get("paths", []):
            _add_path(Path(raw), section, out, seen)
        for pattern in spec.get("globs", []):
            for p in sorted(Path("/").glob(pattern.lstrip("/"))):
                _add_path(p, section, out, seen)
    return out


def _add_path(path: Path, section: str, out: list[dict], seen: set[str]) -> None:
    if _excluded(path) or (not path.exists() and not path.is_symlink()):
        return
    if path.is_file() or path.is_symlink():
        _add_file(path, section, out, seen)
        return
    if path.is_dir():
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames[:] = [d for d in dirnames if not _excluded(Path(dirpath) / d)]
            for filename in filenames:
                _add_file(Path(dirpath) / filename, section, out, seen)


def _add_file(path: Path, section: str, out: list[dict], seen: set[str]) -> None:
    if _excluded(path):
        return
    key = str(path)
    if key in seen:
        return
    seen.add(key)
    out.append({"path": path, "section": section})


def _excluded(path: Path) -> bool:
    s = str(path)
    if any(s == p.rstrip("/") or s.startswith(p) for p in EXCLUDE_PREFIXES):
        return True
    return any(path.match(pattern) or path.name == pattern for pattern in EXCLUDE_NAME_PATTERNS)


def _section_counts(files: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in files:
        section = item["section"]
        counts[section] = counts.get(section, 0) + 1
    return counts


def _walk_files(root: Path):
    if not root.exists():
        return
    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for fn in filenames:
            yield Path(dirpath) / fn


def _restore_section_allowed(target: Path, sections: dict[str, bool]) -> bool:
    s = str(target)
    for section, prefixes in RESTORE_SECTION_PREFIXES.items():
        if any(s == p.rstrip("/") or s.startswith(p) for p in prefixes):
            return sections.get(section, True)
    return False


def _sections_from_mapping(mapping) -> dict[str, bool]:
    sections = {section: True for section in RESTORE_SECTION_PREFIXES}
    for legacy_key, section_names in LEGACY_SECTION_ALIASES.items():
        if legacy_key in mapping:
            enabled = _as_bool(mapping.get(legacy_key), True)
            for section in section_names:
                sections[section] = enabled
    for section in RESTORE_SECTION_PREFIXES:
        key = f"include_{section}"
        if key in mapping:
            sections[section] = _as_bool(mapping.get(key), True)
    return sections


def _as_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _backup_existing(target: Path, pre: Path) -> None:
    if not target.exists() and not target.is_symlink():
        return
    bak = pre / target.relative_to("/")
    bak.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        os.symlink(os.readlink(target), bak)
    elif target.is_file():
        shutil.copy2(target, bak)


def _restore_one(src: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        target.unlink()
    if src.is_symlink():
        os.symlink(os.readlink(src), target)
    else:
        shutil.copy2(src, target)


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        try:
            member_path.relative_to(dest_resolved)
        except ValueError:
            raise tarfile.TarError(f"unsafe path in archive: {member.name}")
        if member.islnk():
            raise tarfile.TarError(f"hard links not allowed: {member.name}")
        if member.issym():
            link = Path(member.linkname)
            if link.is_absolute() or ".." in link.parts:
                raise tarfile.TarError(f"unsafe symlink in archive: {member.name}")
    tar.extractall(dest)
