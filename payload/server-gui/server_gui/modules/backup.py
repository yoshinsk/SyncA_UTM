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

RESTORE_REPLACE_TARGETS = {
    "system_identity": {"paths": ["/etc/hostname"]},
    "server_gui_config": {"paths": ["/etc/server-gui"]},
    "server_gui_app": {"paths": [
        "/opt/server-gui/bin",
        "/opt/server-gui/server_gui",
        "/opt/server-gui/requirements.txt",
    ]},
    "wireguard_ui": {"paths": ["/opt/wireguard"]},
    "systemd": {"globs": [
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
    "nginx": {"paths": ["/etc/nginx"]},
    "dnsmasq": {"paths": [
        "/etc/dnsmasq.conf",
        "/etc/dnsmasq.d",
        "/var/lib/dnsmasq",
    ]},
    "wireguard": {"paths": ["/etc/wireguard"]},
    "strongswan": {"paths": ["/etc/strongswan/swanctl/conf.d/server-gui.conf"]},
    "firewalld": {"paths": ["/etc/firewalld"]},
    "ipv6": {"paths": [
        "/etc/radvd.conf",
        "/etc/frr",
        "/etc/sysctl.d/99-synca-ipv6.conf",
        "/usr/local/sbin/synca-ipv6-transition",
    ]},
    "network": {"paths": [
        "/etc/NetworkManager/NetworkManager.conf",
        "/etc/NetworkManager/conf.d",
        "/etc/NetworkManager/dispatcher.d",
        "/etc/NetworkManager/system-connections",
        "/etc/sysconfig/network",
        "/etc/sysconfig/network-scripts",
    ]},
    "fail2ban": {"paths": ["/etc/fail2ban"]},
    "letsencrypt": {"paths": ["/etc/letsencrypt"]},
    "server_gui_state": {"paths": [
        "/var/lib/server-gui",
        "/var/log/server-gui",
    ]},
}

PRESERVE_DURING_REPLACE = {
    "/var/lib/server-gui": (
        "/var/lib/server-gui/backups",
        "/var/lib/server-gui/pre-restore",
    ),
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
        replaced: list[str] = []
        try:
            replaced = _replace_existing_sections(sections, pre)
        except OSError as e:
            return jsonify({
                "ok": False,
                "manifest": manifest,
                "applied": applied,
                "skipped": skipped,
                "errors": [f"pre-restore replace: {e}"],
                "pre_restore_dir": str(pre),
                "replaced": replaced,
                "post_restore": post_restore,
            }), 500
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
            "replaced": replaced,
            "post_restore": post_restore,
            "restart_hint": [
                "systemctl daemon-reload",
                "systemctl restart NetworkManager firewalld dnsmasq nginx fail2ban server-gui",
                "systemctl enable --now strongswan && swanctl --load-all",
                "systemctl restart wg-quick@wg0 wgui-worker",
            ],
        })


def _replace_existing_sections(sections: dict[str, bool], pre: Path) -> list[str]:
    replaced: list[str] = []
    targets = _selected_replace_targets(sections)
    for target in targets:
        if not target.exists() and not target.is_symlink():
            continue
        if _is_preserved_path(target):
            continue
        _move_existing_for_replace(target, pre, replaced)
    return replaced


def _selected_replace_targets(sections: dict[str, bool]) -> list[Path]:
    targets: dict[str, Path] = {}
    for section, spec in RESTORE_REPLACE_TARGETS.items():
        if not sections.get(section, True):
            continue
        for raw in spec.get("paths", []):
            p = Path(raw)
            targets[str(p)] = p
        for pattern in spec.get("globs", []):
            for p in sorted(Path("/").glob(pattern.lstrip("/"))):
                targets[str(p)] = p
    return sorted(targets.values(), key=lambda p: (len(p.parts), str(p)))


def _move_existing_for_replace(target: Path, pre: Path, replaced: list[str]) -> None:
    preserve = PRESERVE_DURING_REPLACE.get(str(target))
    if preserve and target.is_dir() and not target.is_symlink():
        target.mkdir(parents=True, exist_ok=True)
        for child in sorted(target.iterdir(), key=lambda p: str(p)):
            if _is_preserved_path(child):
                continue
            _move_path_to_pre_restore(child, pre)
            replaced.append(str(child))
        return
    _move_path_to_pre_restore(target, pre)
    replaced.append(str(target))


def _move_path_to_pre_restore(target: Path, pre: Path) -> None:
    bak = _pre_restore_path(pre, target)
    bak.parent.mkdir(parents=True, exist_ok=True)
    if bak.exists() or bak.is_symlink():
        if bak.is_dir() and not bak.is_symlink():
            shutil.rmtree(bak)
        else:
            bak.unlink()
    shutil.move(str(target), str(bak))


def _is_preserved_path(path: Path) -> bool:
    s = str(path)
    for _, prefixes in PRESERVE_DURING_REPLACE.items():
        for prefix in prefixes:
            if s == prefix or s.startswith(prefix.rstrip("/") + "/"):
                return True
    return False


def _pre_restore_path(pre: Path, target: Path) -> Path:
    try:
        rel = target.relative_to("/")
    except ValueError:
        rel = Path(str(target).lstrip("/\\").replace(":", ""))
    return pre / rel


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
            _render_network_profile_adaptation_script(),
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


def _render_network_profile_adaptation_script() -> str:
    return r"""PYTHONPATH=/opt/server-gui /opt/server-gui/venv/bin/python - <<'PY' || true
import configparser
import os
import re
import shutil
import uuid
from pathlib import Path

CONN_DIR = Path("/etc/NetworkManager/system-connections")


def natural_key(value):
    return [int(part) if part.isdigit() else part for part in re.split(r"([0-9]+)", value)]


def nic_sort_key(name):
    device = Path("/sys/class/net") / name / "device"
    try:
        return (str(device.resolve()), natural_key(name))
    except OSError:
        return ("", natural_key(name))


def physical_ethernet_names():
    out = []
    root = Path("/sys/class/net")
    for item in root.iterdir() if root.exists() else []:
        name = item.name
        if name == "lo" or name.startswith(("br", "wg", "tun", "tap", "veth", "docker", "virbr", "ppp", "bond")):
            continue
        if not (item / "device").exists():
            continue
        try:
            if (item / "type").read_text(encoding="ascii").strip() != "1":
                continue
        except OSError:
            continue
        out.append(name)
    return sorted(out, key=nic_sort_key)


def parser_for(path):
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str
    cp.read(path, encoding="utf-8")
    return cp


def connection_value(cp, key, default=""):
    return cp["connection"].get(key, default) if cp.has_section("connection") else default


def ipv4_value(cp, key, default=""):
    return cp["ipv4"].get(key, default) if cp.has_section("ipv4") else default


def set_connection_value(cp, key, value):
    if not cp.has_section("connection"):
        cp.add_section("connection")
    cp["connection"][key] = value


def remove_hardware_binding(cp):
    if cp.has_section("ethernet"):
        for key in ("mac-address", "cloned-mac-address"):
            cp["ethernet"].pop(key, None)


def write_profile(path, cp):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".new")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        cp.write(fh, space_around_delimiters=False)
    os.chmod(tmp, 0o600)
    try:
        shutil.chown(tmp, "root", "root")
    except (LookupError, PermissionError, OSError):
        pass
    tmp.replace(path)


def profile_filename(conn_id):
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", conn_id).strip("-") or "synca-connection"
    return CONN_DIR / f"{safe}.nmconnection"


def is_bridge_port(cp):
    conn_id = connection_value(cp, "id")
    return connection_value(cp, "master") == "br-lan" or conn_id.startswith("br-lan-port-")


def is_lan_source(cp):
    conn_id = connection_value(cp, "id")
    iface = connection_value(cp, "interface-name")
    return bool(iface) and (is_bridge_port(cp) or conn_id == "synca-lan")


def is_wan_source(cp):
    ctype = connection_value(cp, "type")
    conn_id = connection_value(cp, "id")
    iface = connection_value(cp, "interface-name")
    if not iface:
        return False
    if ctype == "pppoe":
        return True
    if ctype != "ethernet" or connection_value(cp, "master"):
        return False
    method = ipv4_value(cp, "method")
    gateway = ipv4_value(cp, "gateway") or ipv4_value(cp, "address1")
    return conn_id.startswith(("synca-wan", "wan", "pppoe-parent")) or (
        connection_value(cp, "autoconnect", "yes") != "no" and method in {"auto", "manual"} and bool(gateway)
    )


def load_profiles():
    profiles = []
    if not CONN_DIR.exists():
        return profiles
    for path in sorted(CONN_DIR.glob("*.nmconnection")):
        try:
            cp = parser_for(path)
        except configparser.Error as exc:
            print(f"skip unreadable profile {path}: {exc}")
            continue
        profiles.append({"path": path, "cp": cp})
    return profiles


def ordered_source_interfaces(profiles):
    roles = {"wan": [], "lan": [], "other": []}
    for item in profiles:
        cp = item["cp"]
        iface = connection_value(cp, "interface-name")
        if not iface or iface in {"lo", "br-lan", "wg0"}:
            continue
        if is_wan_source(cp):
            bucket = roles["wan"]
        elif is_lan_source(cp):
            bucket = roles["lan"]
        else:
            bucket = roles["other"]
        if iface not in roles["wan"] and iface not in roles["lan"] and iface not in roles["other"]:
            bucket.append(iface)
    return (
        sorted(roles["wan"], key=natural_key)
        + sorted(roles["lan"], key=natural_key)
        + sorted(roles["other"], key=natural_key)
    )


def build_mapping(profiles, current):
    source = ordered_source_interfaces(profiles)
    current = list(current)
    mapping = {}
    used = set()
    for iface in source:
        if iface in current and iface not in used:
            mapping[iface] = iface
            used.add(iface)
    remaining = [name for name in current if name not in used]
    for iface in source:
        if iface in mapping:
            continue
        if not remaining:
            break
        mapped = remaining.pop(0)
        mapping[iface] = mapped
        used.add(mapped)
    return mapping


def add_extra_lan_ports(profiles, current, used_dest):
    has_bridge = any(connection_value(item["cp"], "type") == "bridge" and connection_value(item["cp"], "interface-name") == "br-lan" for item in profiles)
    if not has_bridge:
        return
    existing_ports = {connection_value(item["cp"], "interface-name") for item in profiles if is_bridge_port(item["cp"])}
    for iface in current:
        if iface in used_dest or iface in existing_ports:
            continue
        cp = configparser.ConfigParser(interpolation=None)
        cp.optionxform = str
        conn_id = f"br-lan-port-{iface}"
        cp["connection"] = {
            "id": conn_id,
            "uuid": str(uuid.uuid4()),
            "type": "ethernet",
            "interface-name": iface,
            "master": "br-lan",
            "slave-type": "bridge",
            "autoconnect": "yes",
        }
        cp["ethernet"] = {}
        write_profile(profile_filename(conn_id), cp)
        print(f"added LAN bridge port for extra NIC {iface}")


def adapt_profiles():
    current = physical_ethernet_names()
    profiles = load_profiles()
    if not current or not profiles:
        print(f"network profile adaptation skipped current={current} profiles={len(profiles)}")
        return
    mapping = build_mapping(profiles, current)
    used_dest = set(mapping.values())
    print(f"network interface mapping: {mapping}")

    for item in profiles:
        path = item["path"]
        cp = item["cp"]
        ctype = connection_value(cp, "type")
        iface = connection_value(cp, "interface-name")
        if ctype not in {"ethernet", "pppoe"} or not iface or iface in {"lo", "br-lan", "wg0"}:
            continue
        mapped = mapping.get(iface)
        if not mapped:
            if is_bridge_port(cp) or connection_value(cp, "id") == iface:
                path.unlink(missing_ok=True)
                print(f"removed profile for missing NIC {iface}: {path}")
            continue
        remove_hardware_binding(cp)
        set_connection_value(cp, "interface-name", mapped)
        new_path = path
        if is_bridge_port(cp):
            conn_id = f"br-lan-port-{mapped}"
            set_connection_value(cp, "id", conn_id)
            set_connection_value(cp, "master", "br-lan")
            set_connection_value(cp, "slave-type", "bridge")
            set_connection_value(cp, "autoconnect", "yes")
            new_path = profile_filename(conn_id)
        elif connection_value(cp, "id") == iface:
            set_connection_value(cp, "id", mapped)
            new_path = profile_filename(mapped)
        write_profile(new_path, cp)
        if new_path != path:
            path.unlink(missing_ok=True)
            print(f"renamed profile {path.name} -> {new_path.name}")

    profiles = load_profiles()
    add_extra_lan_ports(profiles, current, used_dest)


adapt_profiles()
PY"""


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
    bak = _pre_restore_path(pre, target)
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
