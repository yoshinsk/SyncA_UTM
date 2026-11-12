#!/usr/bin/env python3
"""scripts/test-log-maintenance.py - 架空のログで日次削除、容量判定、管理APIを検証する。"""
import datetime as dt
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))
from flask import Flask
from server_gui import log_maintenance as logs
from server_gui.config_store import ConfigStore
from server_gui.modules import admin

NOW = dt.datetime(2026, 11, 12, 3, 15)


class LogMaintenanceTests(unittest.TestCase):
    """本物の/var/log、systemctl、journalctlには一切触れない。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "logs"
        self.root.mkdir()
        self.config = self.base / "config"
        self.state = self.base / "state"
        self.command = patch.object(logs, "_command").start()
        self.opened = patch.object(logs, "_open_inodes", return_value=set()).start()
        patch.object(logs, "LOG_ROOT", self.root).start()
        patch.object(logs, "STATE_DIR", self.state).start()
        self.free = patch.object(logs.shutil, "disk_usage", return_value=SimpleNamespace(free=0)).start()
        self.addCleanup(patch.stopall)

    def file(self, name, day=10, content=b"fixture log\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        stamp = dt.datetime(2026, 11, day, 12).timestamp()
        os.utime(path, (stamp, stamp))
        return path

    def test_sufficient_space_keeps_all_archives(self):
        path = self.file("server-gui/ddns.log-20261110")
        self.free.return_value.free = 100
        result = logs.cleanup(self.root, 100, NOW)
        self.assertTrue(path.exists())
        self.assertTrue(result["minimum_met"])
        self.assertEqual(result["processed_days"], [])

    def test_oldest_day_is_deleted_as_a_group_then_stops(self):
        oldest = [self.file("nginx/access.log.2", 9), self.file("server-gui/ddns.log-20261109", 9)]
        newer = self.file("nginx/access.log.1", 10)
        self.free.side_effect = lambda _: SimpleNamespace(free=100 if not oldest[0].exists() else 0)
        result = logs.cleanup(self.root, 100, NOW)
        self.assertTrue(all(not path.exists() for path in oldest))
        self.assertTrue(newer.exists())
        self.assertEqual(result["processed_days"], ["2026-11-09"])
        self.assertEqual(result["deleted_files"], 2)

    def test_active_today_unknown_and_linked_files_are_preserved(self):
        keep = [self.file("nginx/access.log", 8), self.file("nginx/error.log.1", 12),
                self.file("backup.tar.gz", 7), self.file("private/config.json.1", 7),
                self.file("server-gui/credentials.log.backup.1", 7)]
        outside = self.base / "outside"
        outside.mkdir()
        target = outside / "ddns.log.1"
        target.write_bytes(b"do not delete")
        (self.root / "server-gui/symlink.log.1").symlink_to(target)
        (self.root / "nginx/external").symlink_to(outside, target_is_directory=True)
        hardlink = self.file("nginx/hardlink.log.1", 8)
        os.link(hardlink, self.base / "hardlink")
        logs.cleanup(self.root, 100, NOW)
        self.assertTrue(all(path.exists() for path in keep))
        self.assertTrue(target.exists())
        self.assertTrue(hardlink.exists())

    def test_open_archive_is_not_deleted(self):
        path = self.file("nginx/access.log.1")
        info = path.stat()
        self.opened.return_value = {(info.st_dev, info.st_ino)}
        result = logs.cleanup(self.root, 100, NOW)
        self.assertTrue(path.exists())
        self.assertFalse(result["minimum_met"])

    def test_changed_file_or_parent_symlink_is_not_unlinked(self):
        path = self.file("nginx/access.log.1")
        before = path.stat()
        path.write_bytes(b"changed while scanning")
        self.assertFalse(logs._unlink_archive(self.root, path, before))
        saved = self.root / "saved"
        path.parent.rename(saved)
        (self.root / "nginx").symlink_to(saved, target_is_directory=True)
        with self.assertRaises(OSError):
            logs._unlink_archive(self.root, path, before)
        self.assertTrue((saved / path.name).exists())

    def test_journal_deletes_only_closed_old_archives_and_preserves_today(self):
        directory = "journal/" + "a" * 32
        suffix = "@" + "b" * 32 + "-" + "0" * 16 + "-" + "1" * 16 + ".journal"
        archive = self.file(directory + "/system" + suffix, 10)
        today = self.file(directory + "/user-1000" + suffix, 12)
        active = self.file(directory + "/system.journal", 8)
        logs.cleanup(self.root, 100, NOW)
        self.command.assert_not_called()
        self.assertTrue(active.exists())
        self.assertTrue(today.exists())
        self.assertFalse(archive.exists())

    def test_cleanup_failure_is_reported(self):
        self.file("nginx/access.log.1")
        with patch.object(logs, "_unlink_archive", side_effect=PermissionError(13, "fixture denied")):
            result = logs.cleanup(self.root, 100, NOW)
        self.assertFalse(result["minimum_met"])
        self.assertIn("fixture denied", result["errors"][0])

    def test_separate_filesystems_are_checked_independently(self):
        path = self.file("nginx/access.log.1")
        info = path.stat()
        fake = SimpleNamespace(st_dev=info.st_dev + 1, st_mtime=info.st_mtime, st_ino=info.st_ino, st_blocks=1)
        self.free.side_effect = lambda p: SimpleNamespace(free=100 if Path(p) == self.root else 0)
        with patch.object(logs, "_files", return_value=[(path, fake)]), patch.object(logs, "_unlink_archive", return_value=True):
            result = logs.cleanup(self.root, 100, NOW)
        self.assertEqual(len(result["filesystems"]), 2)
        self.assertEqual([item["minimum_met"] for item in result["filesystems"]], [True, False])

    def test_mount_with_only_current_logs_still_reports_low_space(self):
        path = self.file("nginx/access.log", 12)
        info = path.stat()
        fake = SimpleNamespace(st_dev=info.st_dev + 1, st_mtime=info.st_mtime)
        self.free.side_effect = lambda p: SimpleNamespace(free=100 if Path(p) == self.root else 0)
        with patch.object(logs, "_files", return_value=[(path, fake)]):
            result = logs.cleanup(self.root, 100, NOW)
        self.assertEqual(len(result["filesystems"]), 2)
        self.assertFalse(result["minimum_met"])
        self.assertEqual(result["deleted_files"], 0)

    def test_application_rotation_is_daily_and_preserves_permissions(self):
        path = self.file("server-gui/admin-command.log")
        path.chmod(0o600)
        nginx = self.file("nginx/access.log")
        self.assertEqual(logs._rotate_application_logs(self.root, NOW.date()), 1)
        archive = path.with_name(path.name + "-20261111")
        self.assertEqual(archive.read_bytes(), b"fixture log\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.write_bytes(b"next event")
        self.assertEqual(logs._rotate_application_logs(self.root, NOW.date()), 0)
        self.assertTrue(nginx.exists())
        self.assertEqual(path.read_bytes(), b"next event")

    def test_open_application_log_is_not_rotated(self):
        path = self.file("server-gui/ddns.log")
        info = path.stat()
        self.opened.return_value = {(info.st_dev, info.st_ino)}
        self.assertEqual(logs._rotate_application_logs(self.root, NOW.date()), 0)
        self.assertTrue(path.exists())

    def test_install_is_idempotent_and_preserves_custom_threshold(self):
        ConfigStore(self.config).save(logs.MODULE, {"min_free_gb": 25})
        with patch.object(logs, "UNIT_DIR", self.base / "units"):
            logs.install(self.config)
            logs.install(self.config)
            self.assertEqual(logs.settings(self.config), {"min_free_gb": 25})
            self.assertIn("Persistent=true", (logs.UNIT_DIR / logs.TIMER).read_text())
            self.assertIn("03:15:00", (logs.UNIT_DIR / logs.TIMER).read_text())
        self.assertEqual(self.command.call_args_list.count(unittest.mock.call(["systemctl", "daemon-reload"])), 1)
        self.assertEqual(self.command.call_args_list.count(unittest.mock.call(["systemctl", "enable", "--now", logs.TIMER])), 2)

    def test_run_defaults_to_decimal_ten_gb_and_records_insufficient_space(self):
        result = logs.run(self.config)
        self.assertEqual(result["min_free_gb"], 10)
        self.assertFalse(result["ok"])
        self.assertFalse(result["minimum_met"])
        self.command.assert_called_once_with(["journalctl", "--rotate"])
        self.assertEqual(ConfigStore(self.state).load(logs.MODULE), result)

    def test_offline_install_enables_without_starting_installer_systemd(self):
        with patch.object(logs, "UNIT_DIR", self.base / "offline-units"):
            logs.install(self.config, start_timer=False)
            self.assertTrue((logs.UNIT_DIR / logs.TIMER).is_file())
        self.command.assert_called_once_with(["systemctl", "--root=/", "enable", logs.TIMER])
        self.assertEqual(logs.settings(self.config), {"min_free_gb": 10})

    def test_invalid_config_stops_deletion_and_records_error(self):
        ConfigStore(self.config).save(logs.MODULE, {"min_free_gb": False})
        path = self.file("nginx/access.log.1")
        result = logs.run(self.config)
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])
        self.assertTrue(path.exists())
        self.command.assert_not_called()

    def test_upgrade_startup_runs_both_provisioners_even_if_one_fails(self):
        from server_gui import dns_defaults
        app = Flask(__name__)
        app.config["CONFIG_DIR"] = Path("/etc/server-gui")
        with patch.object(Path, "is_file", return_value=True), \
                patch.object(logs, "install", side_effect=OSError("fixture readonly")) as install, \
                patch.object(dns_defaults, "initialize") as initialize, \
                self.assertLogs(admin.logger, level="ERROR"):
            admin.register(app)
        install.assert_called_once_with(Path("/etc/server-gui"))
        initialize.assert_called_once_with(Path("/etc/server-gui"))

    def test_log_settings_api_requires_login_and_csrf(self):
        app = Flask(__name__)
        app.config.update(CONFIG_DIR=self.config, SECRET_KEY="fixture-only")
        admin.register(app)
        client = app.test_client()
        self.assertEqual(client.get("/admin/api/log-maintenance").status_code, 401)
        with client.session_transaction() as session:
            session["user"] = "fixture-admin"
            session["csrf_token"] = "fixture-token"
        self.assertEqual(client.post("/admin/api/log-maintenance", json={"min_free_gb": 20}).status_code, 403)
        headers = {"X-CSRF-Token": "fixture-token"}
        for bad in (True, 0, -1, 1.5, "20", 1_000_001, None):
            with self.subTest(value=bad):
                self.assertEqual(client.post("/admin/api/log-maintenance", json={"min_free_gb": bad}, headers=headers).status_code, 400)
        self.assertEqual(client.post("/admin/api/log-maintenance", json=[], headers=headers).status_code, 400)
        self.assertEqual(client.post("/admin/api/log-maintenance", json={"min_free_gb": 20}, headers=headers).status_code, 200)
        self.assertEqual(logs.settings(self.config), {"min_free_gb": 20})
        self.command.assert_not_called()
        with patch.object(logs.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
            response = client.get("/admin/api/log-maintenance")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["min_free_gb"], 20)


if __name__ == "__main__":
    unittest.main()
