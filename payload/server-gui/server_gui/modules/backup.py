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
import shlex
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Optional

from flask import Blueprint, Flask, jsonify, render_template, request, send_file

from ..auth import csrf_protect, login_required
from ..shell import sudo_run

logger = logging.getLogger(__name__)

bp = Blueprint("backup", __name__, url_prefix="/backup")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        logger.warning("invalid integer environment variable %s", name)
        return default


BACKUP_STORE = Path("/var/lib/server-gui/backups")
FINALIZE_DIR = Path("/run/server-gui")
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
BACKUP_MAX_COUNT = max(1, _int_env("SYNCA_BACKUP_MAX_COUNT", 10))
BACKUP_MAX_BYTES = max(512 * 1024 * 1024, _int_env("SYNCA_BACKUP_MAX_BYTES", 2 * 1024 * 1024 * 1024))
ARCHIVE_VERSION = 2
SUPPORTED_ARCHIVE_VERSIONS = {1, 2}

BACKUP_SPECS: tuple[dict, ...] = (
    {"section": "system_identity", "paths": ["/etc/hostname"]},
    {"section": "server_gui_config", "paths": ["/etc/server-gui"]},
    {"section": "server_gui_app", "paths": [
        "/opt/server-gui/bin",
        "/opt/server-gui/server_gui",
        "/opt/server-gui/requirements.txt",
    ]},
    {"section": "wireguard_ui", "paths": ["/opt/wireguard"]},
    {"section": "systemd", "globs": [
        "/etc/systemd/system/server-gui*",
        "/etc/systemd/system/synca-central*",
        "/etc/systemd/system/synca-ipv6*",
        "/etc/systemd/system/synca-upnp*",
        "/etc/systemd/system/strongswan*",
        "/etc/systemd/system/wgui*",
        "/etc/systemd/system/multi-user.target.wants/server-gui*",
        "/etc/systemd/system/multi-user.target.wants/strongswan*",
        "/etc/systemd/system/timers.target.wants/synca-central*",
        "/etc/systemd/system/multi-user.target.wants/synca-ipv6*",
        "/etc/systemd/system/multi-user.target.wants/synca-upnp*",
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
    {"section": "strongswan", "paths": [
        "/etc/strongswan/swanctl/conf.d/server-gui.conf",
    ]},
    {"section": "firewalld", "paths": ["/etc/firewalld"]},
    {"section": "ipv6", "paths": [
        "/etc/radvd.conf",
        "/etc/frr",
        "/etc/sysctl.d/99-synca-ipv6.conf",
        "/usr/local/sbin/synca-ipv6-transition",
    ]},
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
    "system_identity": ("/etc/hostname",),
    "server_gui_config": ("/etc/server-gui/",),
    "server_gui_app": ("/opt/server-gui/bin/", "/opt/server-gui/server_gui/", "/opt/server-gui/requirements.txt"),
    "wireguard_ui": ("/opt/wireguard/",),
    "systemd": ("/etc/systemd/system/",),
    "nginx": ("/etc/nginx/",),
    "dnsmasq": ("/etc/dnsmasq.conf", "/etc/dnsmasq.d/", "/var/lib/dnsmasq/"),
    "wireguard": ("/etc/wireguard/",),
    "strongswan": ("/etc/strongswan/swanctl/conf.d/server-gui.conf",),
    "firewalld": ("/etc/firewalld/",),
    "ipv6": ("/etc/radvd.conf", "/etc/frr/", "/etc/sysctl.d/99-synca-ipv6.conf", "/usr/local/sbin/synca-ipv6-transition"),
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
    items = _backup_items()
    public_items = [{k: v for k, v in item.items() if k != "path"} for item in items]
    return jsonify({
        "backups": public_items,
        "store": str(BACKUP_STORE),
        "total_size": sum(item["size"] for item in items),
        "retention": {
            "max_count": BACKUP_MAX_COUNT,
            "max_bytes": BACKUP_MAX_BYTES,
        },
    })


@bp.route("/api/create", methods=["POST"])
@login_required
@csrf_protect
def create_backup():
    try:
        result = create_backup_archive()
    except Exception as e:
        logger.exception("backup creation failed")
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify(result)


def create_backup_archive() -> dict:
    """Create one local backup archive and apply retention pruning.

    This function is used by both the authenticated GUI endpoint and the
    systemd timer helper. Keeping the implementation shared prevents the
    scheduled path from silently drifting away from the manual backup path.
    """
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
    except Exception:
        if out_path.exists():
            out_path.unlink(missing_ok=True)
        raise

    pruned = _prune_old_backups()
    st = out_path.stat()
    return {
        "ok": True,
        "name": name,
        "path": str(out_path),
        "size": st.st_size,
        "file_count": len(files),
        "sections": _section_counts(files),
        "pruned": pruned,
    }


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
        post_restore_apply = _as_bool(request.form.get("post_restore_apply"), True)
    else:
        payload = request.get_json(force=True, silent=True) or {}
        sections = _sections_from_mapping(payload)
        post_restore_apply = _as_bool(payload.get("post_restore_apply"), True)
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
        post_restore: list[str] = []
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
        if not errors and sections.get("system_identity", True):
            try:
                restored_hostname = _restore_hostname_from_manifest(manifest, pre, applied)
                if restored_hostname:
                    applied.append(restored_hostname)
                    post_restore.append(f"restored {restored_hostname} from manifest hostname")
            except OSError as e:
                errors.append(f"/etc/hostname: {e}")
        if not errors and post_restore_apply:
            result = _schedule_post_restore_apply(sections, ts)
            post_restore.append(result)
            if not result.get("ok"):
                errors.append(f"post-restore apply: {result.get('error') or result.get('output') or 'failed'}")

        return jsonify({
            "ok": not errors,
            "manifest": manifest,
            "applied": applied,
            "skipped": skipped,
            "errors": errors,
            "pre_restore_dir": str(pre),
            "post_restore": post_restore,
            "restart_hint": [
                "systemctl daemon-reload",
                "systemctl restart NetworkManager firewalld dnsmasq nginx fail2ban server-gui",
                "systemctl enable --now strongswan && swanctl --load-all",
                "systemctl restart wg-quick@wg0 wgui-worker",
            ],
        })


def _schedule_post_restore_apply(sections: dict[str, bool], ts: str) -> dict:
    script = _post_restore_apply_script(sections, ts)
    if not script:
        return {"ok": True, "skipped": True, "reason": "no post-restore actions selected"}
    FINALIZE_DIR.mkdir(parents=True, exist_ok=True)
    unit = f"server-gui-restore-finalize-{ts}"
    script_path = FINALIZE_DIR / f"{unit}.sh"
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o700)
    res = sudo_run([
        "systemd-run",
        "--unit", unit,
        "--collect",
        "--on-active=3s",
        "/bin/bash",
        str(script_path),
    ], timeout=15)
    return {
        "ok": res.ok,
        "unit": unit,
        "script": str(script_path),
        "output": (res.stdout + res.stderr).strip(),
    }


def _post_restore_apply_script(sections: dict[str, bool], ts: str) -> str:
    lines = [
        "#!/bin/bash",
        "set -u",
        "log=/var/log/server-gui/restore-finalize-" + shlex.quote(ts) + ".log",
        "mkdir -p /var/log/server-gui",
        "exec >>\"$log\" 2>&1",
        "echo \"[restore-finalize] start $(date -Is)\"",
        "unit_exists() { systemctl list-unit-files --no-legend \"$1\" 2>/dev/null | awk '{print $1}' | grep -Fxq \"$1\"; }",
        "enable_now() { unit_exists \"$1\" && systemctl enable --now \"$1\" || true; }",
        "restart_unit() { unit_exists \"$1\" && systemctl restart \"$1\" || true; }",
    ]

    if sections.get("systemd", True):
        lines.append("systemctl daemon-reload || true")
    if sections.get("system_identity", True):
        lines.extend([
            "if [ -s /etc/hostname ]; then",
            "  hn=$(head -n1 /etc/hostname | tr -d '[:space:]')",
            "  [ -n \"$hn\" ] && hostnamectl set-hostname \"$hn\" || true",
            "fi",
        ])
    if sections.get("server_gui_config", True) or sections.get("strongswan", True):
        lines.append(_render_ipsec_regeneration_script())
    if sections.get("systemd", True):
        lines.extend([
            "enable_now nginx.service",
            "enable_now firewalld.service",
            "enable_now dnsmasq.service",
            "enable_now fail2ban.service",
            "enable_now server-gui-ddns.timer",
            "enable_now server-gui-geoip.timer",
            "enable_now server-gui-backup.timer",
            "enable_now server-gui-update-check.timer",
            "enable_now synca-central-report.timer",
            "enable_now synca-central-backup.timer",
        ])
    if sections.get("strongswan", True) or sections.get("server_gui_config", True):
        lines.extend([
            "enable_now strongswan.service",
            "command -v swanctl >/dev/null 2>&1 && swanctl --load-all || true",
        ])
    if sections.get("wireguard", True):
        lines.extend([
            "if [ -s /etc/wireguard/wg0.conf ]; then",
            "  enable_now wg-quick@wg0.service",
            "  restart_unit wg-quick@wg0.service",
            "fi",
        ])
    if sections.get("wireguard_ui", True):
        lines.append("enable_now wgui-worker.service")
    if sections.get("nginx", True):
        lines.append("restart_unit nginx.service")
    if sections.get("dnsmasq", True):
        lines.append("restart_unit dnsmasq.service")
    if sections.get("firewalld", True):
        lines.append("firewall-cmd --reload || restart_unit firewalld.service")
    if sections.get("fail2ban", True):
        lines.append("restart_unit fail2ban.service")
    if sections.get("network", True):
        lines.extend([
            "nmcli connection reload || true",
            "if nmcli -t -f NAME connection show | grep -Fxq br-lan; then nmcli connection up br-lan || true; fi",
            "for con in $(nmcli -t -f NAME connection show | grep '^br-lan-port-' || true); do nmcli connection up \"$con\" || true; done",
        ])
    if sections.get("server_gui_app", True) or sections.get("server_gui_config", True):
        lines.append("restart_unit server-gui.service")
    lines.extend([
        "echo \"[restore-finalize] end $(date -Is)\"",
        "rm -f " + shlex.quote(str(FINALIZE_DIR / f"server-gui-restore-finalize-{ts}.sh")),
    ])
    return "\n".join(lines) + "\n"


def _render_ipsec_regeneration_script() -> str:
    return r"""if [ -s /etc/server-gui/ipsec.json ]; then
  PYTHONPATH=/opt/server-gui /opt/server-gui/venv/bin/python - <<'PY' || true
import json
import os
from pathlib import Path
from server_gui.modules import ipsec

data = json.loads(Path("/etc/server-gui/ipsec.json").read_text(encoding="utf-8"))
conns = data.get("connections", [])
content = ipsec._render(conns) if conns else ""
out = Path("/etc/strongswan/swanctl/conf.d/server-gui.conf")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(content, encoding="utf-8")
os.chmod(out, 0o600)
print(f"rendered strongSwan managed connections={len(conns)}")
PY
fi"""


def _restore_hostname_from_manifest(manifest: dict, pre: Path, applied: list[str]) -> str | None:
    if "/etc/hostname" in applied:
        return None
    hostname = str(manifest.get("hostname") or "").strip()
    if not _valid_restored_hostname(hostname):
        return None
    target = Path("/etc/hostname")
    _backup_existing(target, pre)
    target.write_text(hostname + "\n", encoding="utf-8")
    target.chmod(0o644)
    return str(target)


def _valid_restored_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253 or ".." in hostname:
        return False
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$", hostname))


def _safe_backup_name(name: str) -> bool:
    return bool(re.match(r"^server-gui-\d{8}-\d{6}\.tar\.gz$", name))


def _backup_items() -> list[dict]:
    items: list[dict] = []
    candidates = []
    for p in BACKUP_STORE.glob("server-gui-*.tar.gz"):
        try:
            st = p.stat()
        except OSError:
            continue
        candidates.append((p, st))
    for p, st in sorted(candidates, key=lambda item: item[1].st_mtime, reverse=True):
        items.append({"name": p.name, "size": st.st_size, "mtime": int(st.st_mtime), "path": p})
    return items


def _prune_old_backups() -> list[dict]:
    """Delete oldest archives until local backup retention policy is satisfied."""
    items = _backup_items()
    total = sum(item["size"] for item in items)
    pruned: list[dict] = []
    for index, item in enumerate(items):
        if index < BACKUP_MAX_COUNT and total <= BACKUP_MAX_BYTES:
            continue
        path = item["path"]
        try:
            path.unlink()
        except OSError as e:
            logger.warning("failed to prune backup %s: %s", path, e)
            continue
        total -= item["size"]
        pruned.append({"name": item["name"], "size": item["size"]})
    return pruned


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
        if any(_path_matches_restore_prefix(s, p) for p in prefixes):
            return sections.get(section, True)
    return False


def _path_matches_restore_prefix(path: str, prefix: str) -> bool:
    return path.startswith(prefix) if prefix.endswith("/") else path == prefix


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
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        if member.islnk():
            raise tarfile.TarError(f"hard links not allowed: {member.name}")
        member_path = _archive_member_path(dest, dest_resolved, member.name)
        if member.isdir():
            _prepare_archive_parent(dest, dest_resolved, member_path)
            if member_path.is_symlink():
                raise tarfile.TarError(f"directory conflicts with symlink: {member.name}")
            member_path.mkdir(exist_ok=True)
            _apply_member_metadata(member, member_path)
            continue
        if member.issym():
            _prepare_archive_parent(dest, dest_resolved, member_path)
            if member_path.exists() or member_path.is_symlink():
                if member_path.is_dir() and not member_path.is_symlink():
                    raise tarfile.TarError(f"symlink conflicts with directory: {member.name}")
                member_path.unlink()
            os.symlink(member.linkname, member_path)
            continue
        if member.isfile():
            _prepare_archive_parent(dest, dest_resolved, member_path)
            if member_path.is_dir() and not member_path.is_symlink():
                raise tarfile.TarError(f"file conflicts with directory: {member.name}")
            if member_path.exists() or member_path.is_symlink():
                member_path.unlink()
            src = tar.extractfile(member)
            if src is None:
                raise tarfile.TarError(f"file unreadable: {member.name}")
            with src, member_path.open("wb") as out:
                shutil.copyfileobj(src, out)
            _apply_member_metadata(member, member_path)
            continue
        raise tarfile.TarError(f"unsupported member type: {member.name}")


def _archive_member_path(dest: Path, dest_resolved: Path, name: str) -> Path:
    if not name or "\\" in name:
        raise tarfile.TarError(f"unsafe path in archive: {name}")
    raw = PurePosixPath(name)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise tarfile.TarError(f"unsafe path in archive: {name}")
    member_path = dest.joinpath(*raw.parts)
    try:
        member_path.resolve().relative_to(dest_resolved)
    except ValueError:
        raise tarfile.TarError(f"unsafe path in archive: {name}")
    return member_path


def _prepare_archive_parent(dest: Path, dest_resolved: Path, member_path: Path) -> None:
    try:
        parent_parts = member_path.parent.relative_to(dest).parts
    except ValueError:
        raise tarfile.TarError(f"unsafe path in archive: {member_path}")
    current = dest
    for part in parent_parts:
        current = current / part
        if current.is_symlink():
            raise tarfile.TarError(f"archive path traverses symlink: {member_path}")
        if current.exists():
            if not current.is_dir():
                raise tarfile.TarError(f"archive parent is not a directory: {member_path}")
            continue
        current.mkdir()
    try:
        member_path.parent.resolve().relative_to(dest_resolved)
    except ValueError:
        raise tarfile.TarError(f"unsafe parent in archive: {member_path}")


def _apply_member_metadata(member: tarfile.TarInfo, path: Path) -> None:
    try:
        os.chmod(path, member.mode & 0o7777)
    except OSError:
        logger.debug("failed to apply archive mode to %s", path, exc_info=True)
    try:
        os.utime(path, (member.mtime, member.mtime), follow_symlinks=False)
    except (OSError, NotImplementedError):
        logger.debug("failed to apply archive mtime to %s", path, exc_info=True)
