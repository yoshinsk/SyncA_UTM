"""payload/server-gui/server_gui/log_maintenance.py - 日次ローテーションと空き容量に応じたログ削除。"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from .config_store import ConfigStore

MODULE = "log_maintenance"
DEFAULT_MIN_FREE_GB = 10
GB = 1_000_000_000
LOG_ROOT = Path("/var/log")
STATE_DIR = Path("/var/lib/server-gui")
UNIT_DIR = Path("/etc/systemd/system")
SERVICE = "server-gui-log-maintenance.service"
TIMER = "server-gui-log-maintenance.timer"
_ROTATED = re.compile(r"^.+(?:-\d{8}(?:\d{6})?|\.\d+)(?:\.(?:gz|xz|bz2|zst))?$")
_SYSTEM_LOG = re.compile(r"^(?:messages|secure|maillog|cron|spooler|boot\.log|dnf(?:\.rpm)?\.log|hawkey\.log|fail2ban\.log|synca-central-agent\.log)(?:-|\.)")
_JOURNAL = re.compile(r"^[A-Za-z0-9_-]+@[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{16}\.journal$")
SERVICE_TEXT = """# Managed by SyncA UTM: rotate logs and recover free disk space.
[Unit]
Description=SyncA UTM daily log maintenance
After=systemd-journald.service

[Service]
Type=oneshot
ExecStart=/opt/server-gui/bin/log-maintenance run
User=root
Group=root
UMask=0077
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=15min
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
NoNewPrivileges=true
"""
TIMER_TEXT = """# Managed by SyncA UTM: one daily check, including missed checks after boot.
[Unit]
Description=SyncA UTM daily log maintenance timer

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=5min
Persistent=true
Unit=server-gui-log-maintenance.service

[Install]
WantedBy=timers.target
"""


def validate_min_free_gb(value: object) -> int:
    """設定は正の整数GBで受け付け、真偽値・小数・文字列への暗黙変換を避ける。"""
    if type(value) is not int or not 1 <= value <= 1_000_000:
        raise ValueError("確保する空き容量は1〜1000000 GBの整数で指定してください")
    return value


def settings(config_dir: Path | str) -> dict:
    """不正な保存値を黙って採用せず、設定画面と定期処理で同じ検証を使う。"""
    data = ConfigStore(config_dir).load(MODULE, {})
    return {"min_free_gb": validate_min_free_gb(data.get("min_free_gb", DEFAULT_MIN_FREE_GB))}


def _command(argv: list[str]) -> None:
    """固定引数でOSのjournal管理を実行し、失敗を実行結果に残す。"""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode:
        raise RuntimeError(f"{argv[0]}: {proc.stderr.strip()[:500]}")


def install(config_dir: Path | str) -> None:
    """新規導入・旧版からのGUI更新に共通の冪等な導入処理。ここではログを削除しない。"""
    store = ConfigStore(config_dir)
    with store.transaction(MODULE, {}) as data:
        data.setdefault("min_free_gb", DEFAULT_MIN_FREE_GB)
        validate_min_free_gb(data["min_free_gb"])
        changed = False
        UNIT_DIR.mkdir(parents=True, exist_ok=True)
        for name, content in ((SERVICE, SERVICE_TEXT), (TIMER, TIMER_TEXT)):
            path = UNIT_DIR / name
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                tmp = path.with_suffix(path.suffix + ".new")
                tmp.write_text(content, encoding="utf-8")
                tmp.chmod(0o644)
                tmp.replace(path)
                changed = True
        if changed:
            _command(["systemctl", "daemon-reload"])
        _command(["systemctl", "enable", "--now", TIMER])


def status(config_dir: Path | str) -> dict:
    """管理画面には容量・実行結果だけを返し、ログ本文は返さない。"""
    data = settings(config_dir)
    data["free_bytes"] = shutil.disk_usage(LOG_ROOT).free
    data["last_result"] = ConfigStore(STATE_DIR).load(MODULE, None)
    proc = subprocess.run(["systemctl", "is-active", TIMER], capture_output=True,
                          text=True, timeout=5, check=False)
    data["timer_active"] = proc.returncode == 0
    return data


def _open_inodes() -> set[tuple[int, int]]:
    """書き込み中のアーカイブや閲覧中のログを消さないよう、開いたFDを調べる。"""
    result = set()
    for fd in Path("/proc").glob("[0-9]*/fd/*"):
        try:
            info = fd.stat()
            result.add((info.st_dev, info.st_ino))
        except OSError:
            continue
    return result


def _files(root: Path):
    """/var/log配下だけを走査する。シンボリックリンクを辿らず、別マウントも識別する。"""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("ログディレクトリを安全に開けません")
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                yield path, info


def _rotate_application_logs(root: Path, today: dt.date) -> int:
    """毎回追記時に開くGUI/central-agentログだけをrenameし、常駐プロセスのログはOSに任せる。"""
    opened = _open_inodes()
    count = 0
    for path, info in _files(root):
        relative = path.relative_to(root)
        if not ((relative.parent == Path("server-gui") and path.suffix == ".log")
                or relative == Path("synca-central-agent.log")):
            continue
        if not info.st_size or (info.st_dev, info.st_ino) in opened:
            continue
        archive = path.with_name(path.name + "-" + (today - dt.timedelta(days=1)).strftime("%Y%m%d"))
        if archive.exists():
            continue
        # rename後に同名ファイルを別writerが作っても上書きしない。既存の所有者と権限を引き継ぐ。
        path.rename(archive)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IMODE(info.st_mode))
        except FileExistsError:
            pass
        else:
            try:
                os.fchmod(fd, stat.S_IMODE(info.st_mode))
                os.fchown(fd, info.st_uid, info.st_gid)
            finally:
                os.close(fd)
        count += 1
    return count


def _archive_kind(relative: Path) -> str:
    """削除対象を既知のローテーション済みログに限定し、稼働中ログやバックアップを除く。"""
    if (len(relative.parts) == 3 and relative.parts[0] == "journal"
            and re.fullmatch(r"[0-9a-f]{32}", relative.parts[1]) and _JOURNAL.fullmatch(relative.name)):
        return "journal"
    if not _ROTATED.fullmatch(relative.name):
        return ""
    if (relative.parent in (Path("server-gui"), Path("nginx"))
            and re.fullmatch(r".+\.log(?:-\d{8}(?:\d{6})?|\.\d+)(?:\.(?:gz|xz|bz2|zst))?", relative.name)):
        return "text"
    if relative.parent == Path(".") and _SYSTEM_LOG.match(relative.name):
        return "text"
    return ""


def _unlink_archive(root: Path, path: Path, expected: os.stat_result) -> bool:
    """全親ディレクトリをno-followで開き直し、走査後に差し替わったファイルを残す。"""
    parts = path.relative_to(root).parts
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns)
        if current.st_nlink != 1 or identity(current) != identity(expected):
            return False
        os.unlink(parts[-1], dir_fd=directory)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(directory)


def cleanup(root: Path, minimum_bytes: int, now: dt.datetime) -> dict:
    """ファイルシステムごとに古い日を一日分ずつ削除し、目標に届いた時点で止める。"""
    groups = {}
    devices = {root.stat().st_dev: root}
    for path, info in _files(root):
        kind = _archive_kind(path.relative_to(root))
        day = dt.datetime.fromtimestamp(info.st_mtime).date()
        # 当日分しかない別マウントでも、容量不足を結果から落とさない。
        if kind or path.parent.name in ("nginx", "server-gui") or path.suffix == ".journal":
            devices[info.st_dev] = path.parent
        if not kind or day >= now.date():
            continue
        devices[info.st_dev] = path.parent
        groups.setdefault((day, info.st_dev), []).append((path, info, kind))
    filesystems = {dev: {"path": str(path), "before_free_bytes": shutil.disk_usage(path).free}
                   for dev, path in devices.items()}
    result = {"deleted_files": 0, "deleted_bytes": 0, "processed_days": [], "errors": []}
    for (day, dev), entries in sorted(groups.items()):
        if shutil.disk_usage(devices[dev]).free >= minimum_bytes:
            continue
        opened = _open_inodes()
        for path, info, kind in entries:
            if (info.st_dev, info.st_ino) in opened:
                continue
            try:
                # journalctl --rotateで書込みが終了したjournalも、最終更新日でまとめる。
                # vacuum-timeはファイル名の開始時刻も使うため、当日を含む断片を消す恐れがある。
                if _unlink_archive(root, path, info):
                    result["deleted_files"] += 1
                    result["deleted_bytes"] += info.st_blocks * 512
            except OSError as error:
                result["errors"].append(f"{path.name}: {error.strerror}")
        if day.isoformat() not in result["processed_days"]:
            result["processed_days"].append(day.isoformat())
    for dev, item in filesystems.items():
        item["after_free_bytes"] = shutil.disk_usage(devices[dev]).free
        item["minimum_met"] = item["after_free_bytes"] >= minimum_bytes
    result["filesystems"] = list(filesystems.values())
    result["minimum_met"] = all(item["minimum_met"] for item in filesystems.values())
    return result


def run(config_dir: Path | str) -> dict:
    """定期実行を排他し、処理失敗やアーカイブ不足も管理画面へ記録する。"""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with (STATE_DIR / ".log-maintenance.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        now = dt.datetime.now()
        result = {"ran_at": now.isoformat(timespec="seconds"), "errors": []}
        try:
            minimum = settings(config_dir)["min_free_gb"] * GB
            result["min_free_gb"] = minimum // GB
            result["rotated_files"] = _rotate_application_logs(LOG_ROOT, now.date())
            try:
                _command(["journalctl", "--rotate"])
            except (RuntimeError, OSError, subprocess.SubprocessError) as error:
                result["errors"].append(str(error))
            cleaned = cleanup(LOG_ROOT, minimum, dt.datetime.now())
            cleaned["errors"] = result["errors"] + cleaned["errors"]
            result.update(cleaned)
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            result["errors"].append(str(error))
        result["ok"] = not result["errors"] and result.get("minimum_met", False)
        ConfigStore(STATE_DIR).save(MODULE, result)
        return result
