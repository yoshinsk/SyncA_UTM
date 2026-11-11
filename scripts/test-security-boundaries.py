"""scripts/test-security-boundaries.py - 認証と設定・ログ入力の境界を架空データで検証する。"""
import hashlib
import hmac
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))

from flask import Flask
from server_gui import auth
from server_gui.modules import ai_defense, central_sso, nginx_proxy, sophos_import
from server_gui.validators import ValidationError


class LoginIsolationTests(unittest.TestCase):
    """実サーバーを起動せず、信頼する接続元と試行制限の分離を確認する。"""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "dummy-session-key"
        self.app.register_blueprint(auth.auth_bp)
        self.client = self.app.test_client()
        auth._failures.clear()
        self.addCleanup(auth._failures.clear)
        for name, value in (
            ("_load_credentials", {"username": "dummy-admin", "password_hash": "dummy-hash"}),
            ("check_password_hash", True),
            ("render_template", "dummy login page"),
        ):
            patcher = patch.object(auth, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def login(self, peer, source, username="invalid-user"):
        """転送ヘッダーは架空アドレスのみとし、ネットワークへ送信しない。"""
        return self.client.post("/login", data={"username": username, "password": "dummy"},
                                headers={"X-Real-IP": source, "X-Forwarded-For": source},
                                environ_overrides={"REMOTE_ADDR": peer}).status_code

    def test_proxy_clients_have_separate_attempt_buckets(self):
        for _ in range(5):
            self.assertEqual(self.login("127.0.0.1", "192.0.2.10"), 401)
        self.assertEqual(self.login("127.0.0.1", "198.51.100.20", "dummy-admin"), 302)

    def test_same_proxy_client_stays_rate_limited(self):
        for _ in range(5):
            self.login("127.0.0.1", "192.0.2.10")
        self.assertEqual(self.login("127.0.0.1", "192.0.2.10", "dummy-admin"), 429)

    def test_external_peer_cannot_change_bucket_with_headers(self):
        for suffix in range(1, 6):
            self.login("192.0.2.10", "198.51.100." + str(suffix))
        self.assertEqual(self.login("192.0.2.10", "203.0.113.20", "dummy-admin"), 429)

    def test_invalid_proxy_header_falls_back_to_peer(self):
        for value in ("", "invalid", "192.0.2.10,198.51.100.20"):
            with self.subTest(value=value), self.app.test_request_context(
                    "/login", headers={"X-Real-IP": value}, environ_base={"REMOTE_ADDR": "127.0.0.1"}):
                self.assertEqual(auth._login_client_ip(), "127.0.0.1")

    def test_ipv6_loopback_normalises_valid_source(self):
        with self.app.test_request_context("/login", headers={"X-Real-IP": "2001:db8:0:0::10"},
                                           environ_base={"REMOTE_ADDR": "::1"}):
            self.assertEqual(auth._login_client_ip(), "2001:db8::10")


class SsoStateTests(unittest.TestCase):
    """署名前の副作用を拒否し、正規署名の再利用拒否を維持する。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.nonce_dir = Path(self.temp.name) / "nonces"
        for name, value in (("NONCE_DIR", self.nonce_dir),):
            patcher = patch.object(central_sso, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        clock = patch.object(central_sso.time, "time", return_value=1000.0)
        clock.start()
        self.addCleanup(clock.stop)
        self.config = {"device_id": "dummy-device", "sso_secret": "dummy-secret"}

    def valid(self, nonce="dummy-nonce", ts="1000", sig=None, config=None):
        """架空の署名者とファイル領域だけを使う。"""
        config = self.config if config is None else config
        device = config["device_id"]
        if sig is None:
            message = f"{device}\n{ts}\n{nonce}".encode("utf-8")
            sig = hmac.new(config["sso_secret"].encode(), message, hashlib.sha256).hexdigest()
        return central_sso._valid_request(config, device, ts, nonce, sig)

    def test_invalid_signature_does_not_create_nonce_storage(self):
        self.assertFalse(self.valid(sig="0" * 64))
        self.assertFalse(self.nonce_dir.exists())

    def test_unenrolled_configuration_does_not_create_storage(self):
        self.assertFalse(self.valid(config={"device_id": "", "sso_secret": ""}, sig="0" * 64))
        self.assertFalse(self.nonce_dir.exists())

    def test_valid_signature_succeeds_once(self):
        self.assertTrue(self.valid())
        self.assertFalse(self.valid())
        self.assertEqual(len(list(self.nonce_dir.iterdir())), 1)

    def test_invalid_timestamp_forms_are_rejected(self):
        for value in ("\u00b2", "1" * 100, "not-a-time", "699", "1301"):
            with self.subTest(value=value):
                self.assertFalse(self.valid(ts=value))
        self.assertFalse(self.nonce_dir.exists())

    def test_invalid_signature_forms_are_rejected(self):
        for value in ("", "\u3042" * 64, "f" * 63, "g" * 64):
            with self.subTest(value=value):
                self.assertFalse(self.valid(sig=value))
        self.assertFalse(self.nonce_dir.exists())

    def test_invalid_nonce_forms_are_rejected(self):
        for value in ("", "a/b", "a\x00b", "a" * 129):
            with self.subTest(value=value):
                self.assertFalse(self.valid(nonce=value))
        self.assertFalse(self.nonce_dir.exists())


class GuiLogSourceTests(unittest.TestCase):
    """判定・遮断を動かさず、ログの送信元フィールドだけを確認する。"""

    def parse(self, line, public=True):
        records = {}
        # 文書用アドレスで抽出処理だけを検査する。実際の公開IP判定とは分ける。
        with patch.object(ai_defense, "_public_ip", side_effect=lambda value: value if public else ""):
            ai_defense._parse_service_log_line(records, line, "gui", {"4444/tcp"})
        return records

    def test_peer_is_taken_from_logger_suffix(self):
        records = self.parse("failed login for user='dummy from 198.51.100.20' from 192.0.2.10")
        self.assertEqual(set(records), {"192.0.2.10"})
        self.assertEqual(records["192.0.2.10"]["events"], {"gui_failed_auth": 1})

    def test_existing_rate_limit_format_is_supported(self):
        records = self.parse("2026-11-12 WARNING rate limit hit for 192.0.2.10")
        self.assertEqual(records["192.0.2.10"]["events"], {"gui_rate_limit": 1})

    def test_unknown_log_format_is_not_a_gui_candidate(self):
        self.assertEqual(self.parse("other failed login from 192.0.2.10"), {})

    def test_non_public_peer_remains_excluded(self):
        self.assertEqual(self.parse("failed login for user='dummy' from 192.0.2.10", public=False), {})


class NginxInputTests(unittest.TestCase):
    """単一location引数の制限を通常API・保存値・取込で共通に確認する。"""

    def vhost(self, path):
        return {"name": "dummy", "enabled": True, "server_names": ["dummy.invalid"],
                "listens": [{"port": 18080}], "locations": [{"path": path}]}

    def xml(self, path):
        """最小の架空Sophosオブジェクトを作り、実設定は扱わない。"""
        root = ET.Element("export")
        nodes = ET.SubElement(root, "nodes")
        objects = (
            ("route", "site path route", {"status switch": "1", "name": "dummy", "path": path}),
            ("vhost", "virtual webserver", {"status switch": "1", "name": "dummy",
                                            "domain list": "dummy.invalid", "type": "http"}),
        )
        for ref, description, fields in objects:
            node = ET.SubElement(nodes, ref, {"object": "1"})
            ET.SubElement(node, "descr").text = description
            content = ET.SubElement(node, "content")
            for number, (key, value) in enumerate(fields.items()):
                field = ET.SubElement(content, "f" + str(number))
                ET.SubElement(field, "descr").text = key
                ET.SubElement(field, "content").text = value
        return ET.tostring(root, encoding="utf-8")

    def test_valid_location_paths_keep_their_rendered_value(self):
        for value in ("/", "/api/v1", "/a%20b", "/\u65e5\u672c\u8a9e"):
            with self.subTest(value=value):
                parsed = nginx_proxy._parse_vhost(self.vhost(value))
                self.assertIn("location " + value + " {", nginx_proxy._render_vhost(parsed, {}))

    def test_location_delimiters_are_rejected_at_api_parser(self):
        for value in ("/bad path", "/bad\n", "/bad;", "/bad{", "/bad#", '/bad"', "/bad\\", "/bad\x7f"):
            with self.subTest(value=repr(value)), self.assertRaises(ValidationError):
                nginx_proxy._parse_vhost(self.vhost(value))

    def test_saved_invalid_location_is_rejected_at_renderer(self):
        value = nginx_proxy._parse_vhost(self.vhost("/valid"))
        value["locations"][0]["path"] = "/bad path"
        with self.assertRaises(ValidationError):
            nginx_proxy._render_vhost(value, {})

    def test_invalid_import_is_rejected_before_store_writes(self):
        plan = sophos_import._build_plan(self.xml("/bad path"))
        app = Flask(__name__)
        with tempfile.TemporaryDirectory() as temporary, app.app_context():
            app.config["CONFIG_DIR"] = Path(temporary)
            with self.assertRaises(ValidationError):
                sophos_import._import_plan(plan, "dummy.xml", apply_system=False)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_upload_reports_validation_error_as_bad_request(self):
        app = Flask(__name__)
        app.secret_key = "dummy-key"
        app.register_blueprint(sophos_import.bp)
        client = app.test_client()
        with client.session_transaction() as session:
            session["user"] = "dummy-admin"
            session["csrf_token"] = "dummy-csrf"
        with tempfile.TemporaryDirectory() as temporary:
            app.config["CONFIG_DIR"] = Path(temporary)
            result = client.post("/sophos-import/api/import-upload",
                                 data={"xml": (io.BytesIO(self.xml("/bad path")), "dummy.xml")},
                                 headers={"X-CSRF-Token": "dummy-csrf"})
            self.assertEqual(result.status_code, 400)
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
