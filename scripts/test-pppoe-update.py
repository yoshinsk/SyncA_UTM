"""scripts/test-pppoe-update.py - 新旧GUI更新経路からのPPPoE移行と失敗の扱いを検証する。"""
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))
from flask import Flask
from server_gui import pppoe_reconnect
from server_gui.modules import admin


class PppoeUpdateTests(unittest.TestCase):
    """実サービス・実設定には触れず、旧workerと新版子プロセスの経路を分けて確認する。"""

    def test_new_updater_uses_new_module_in_a_separate_process(self):
        messages = []
        result = SimpleNamespace(returncode=0, stdout='{"ok":true,"pending":1}', stderr="")
        with patch.object(admin.subprocess, "run", return_value=result) as command:
            self.assertTrue(admin._migrate_pppoe_reconnect(messages.append))
        self.assertEqual(command.call_args.args[0], ["sudo", "-n", sys.executable,
                         "-m", "server_gui.pppoe_reconnect", "initialize"])
        self.assertEqual(command.call_args.kwargs["cwd"], admin.INSTALL_DIR)
        self.assertTrue(any("20 seconds" in message for message in messages))

    def test_failed_or_invalid_child_result_is_rejected(self):
        for result in (
                SimpleNamespace(returncode=1, stdout='{"ok":true}', stderr=""),
                SimpleNamespace(returncode=0, stdout='{"ok":false}', stderr=""),
                SimpleNamespace(returncode=0, stdout='{"ok":"false"}', stderr=""),
                SimpleNamespace(returncode=0, stdout='[]', stderr=""),
                SimpleNamespace(returncode=0, stdout="invalid json", stderr="")):
            with self.subTest(result=result):
                with patch.object(admin.subprocess, "run", return_value=result):
                    self.assertFalse(admin._migrate_pppoe_reconnect(lambda _: None))

    def test_child_timeout_is_rejected(self):
        with patch.object(admin.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 90)):
            self.assertFalse(admin._migrate_pppoe_reconnect(lambda _: None))

    def test_old_updater_still_migrates_when_new_gui_worker_starts(self):
        app = Flask(__name__)
        app.config["CONFIG_DIR"] = Path("/etc/server-gui")
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(admin, "SERVER_GUI_BIN", Path(directory)), \
                    patch.object(pppoe_reconnect, "initialize", return_value={"ok": True}) as initialize:
                admin.register(app)
        initialize.assert_called_once_with(Path("/etc/server-gui"))
        self.assertIn("admin", app.blueprints)

    def test_development_config_does_not_touch_host_network(self):
        app = Flask(__name__)
        with tempfile.TemporaryDirectory() as directory:
            app.config["CONFIG_DIR"] = Path(directory)
            with patch.object(pppoe_reconnect, "initialize") as initialize:
                admin.register(app)
        initialize.assert_not_called()

    def test_startup_failure_keeps_management_gui_available(self):
        app = Flask(__name__)
        app.config["CONFIG_DIR"] = Path("/etc/server-gui")
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(admin, "SERVER_GUI_BIN", Path(directory)), \
                    patch.object(pppoe_reconnect, "initialize", side_effect=RuntimeError("fixture migration failure")), \
                    self.assertLogs(admin.logger, level="ERROR"):
                admin.register(app)
        self.assertIn("admin", app.blueprints)

    def test_update_page_discloses_first_migration_connection_interruption(self):
        app = Flask(__name__, template_folder=str(ROOT / "payload/server-gui/server_gui/templates"))
        app.secret_key = "fixture-session-key"
        app.config["CONFIG_DIR"] = Path("/unused-fixture-config")
        app.register_blueprint(admin.bp)
        with app.test_request_context("/admin/"):
            # 実際のbase.htmlのメニュー生成だけを差し替え、管理画面の注意文を描画する。
            from jinja2 import ChoiceLoader, DictLoader
            app.jinja_loader = ChoiceLoader([DictLoader({"base.html": "{% block content %}{% endblock %}"}),
                                             app.jinja_loader])
            from flask import render_template
            html = render_template("admin.html")
        self.assertIn("WAN通信が一時中断", html)
        self.assertIn("対策済みの回線は再接続しません", html)


if __name__ == "__main__":
    unittest.main()
