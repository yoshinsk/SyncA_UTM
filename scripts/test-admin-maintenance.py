"""scripts/test-admin-maintenance.py - 管理者認証とコマンド出力整形の契約を確認する。"""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))

from flask import Flask
from werkzeug.security import generate_password_hash
from server_gui.config_store import ConfigStore
from server_gui.modules import admin


class AdminMaintenanceTests(unittest.TestCase):
    """実サービスを呼ばず、共通化前後の認証結果とUTF-8出力を比較する。"""

    @classmethod
    def setUpClass(cls):
        # テスト専用の架空パスワードを使い、製品のハッシュ設定は変更しない。
        cls.password_hash = generate_password_hash("dummy-password", method="pbkdf2:sha256:1000")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config_dir = Path(self.temp.name)
        self.app = Flask(__name__)
        self.app.config["CONFIG_DIR"] = self.config_dir
        context = self.app.app_context()
        context.push()
        self.addCleanup(context.pop)
        ConfigStore(self.config_dir).save("credentials", {
            "username": "dummy-admin", "password_hash": self.password_hash,
        })

    def test_current_password_matches(self):
        self.assertTrue(admin._check_current_password("dummy-password"))

    def test_wrong_or_empty_password_is_rejected(self):
        for value in ("wrong-password", ""):
            with self.subTest(value=value):
                self.assertFalse(admin._check_current_password(value))

    def test_missing_credentials_are_rejected(self):
        (self.config_dir / "credentials.json").unlink()
        self.assertFalse(admin._check_current_password("dummy-password"))

    def test_invalid_json_is_rejected_without_overwriting_it(self):
        path = self.config_dir / "credentials.json"
        path.write_text("{invalid", encoding="utf-8")
        self.assertFalse(admin._check_current_password("dummy-password"))
        self.assertEqual(path.read_text(encoding="utf-8"), "{invalid")

    def test_output_at_utf8_byte_limit_is_unchanged(self):
        with patch.object(admin, "_COMMAND_OUTPUT_MAX", 5):
            self.assertEqual(admin._truncate_output("日ab"), "日ab")

    def test_ascii_output_over_limit_has_truncation_marker(self):
        with patch.object(admin, "_COMMAND_OUTPUT_MAX", 5):
            self.assertEqual(admin._truncate_output("abcdef"), "abcde\n[truncated]")

    def test_partial_utf8_character_keeps_replacement_behavior(self):
        with patch.object(admin, "_COMMAND_OUTPUT_MAX", 5):
            self.assertEqual(admin._truncate_output("日本語"), "日\ufffd\n[truncated]")

    def test_bytes_and_bytearray_are_decoded(self):
        for value in (b"a\xff", bytearray(b"a\xff")):
            with self.subTest(value=type(value).__name__):
                self.assertEqual(admin._truncate_output(value), "a\ufffd")

    def test_non_text_values_keep_their_string_representation(self):
        self.assertEqual(admin._truncate_output(None), "None")
        self.assertEqual(admin._truncate_output(123), "123")


if __name__ == "__main__":
    unittest.main()
