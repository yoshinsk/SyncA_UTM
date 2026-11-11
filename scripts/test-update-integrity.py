"""scripts/test-update-integrity.py - GUI更新の確認状態と固定コミット取得を模擬検証する。"""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))

from flask import Flask
from server_gui.config_store import ConfigStore
from server_gui.modules import admin


class UpdateIntegrityTests(unittest.TestCase):
    """通信・サービス再起動・実パッケージ変更をすべてテスト用領域へ分離する。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ConfigStore(self.root / "config")
        self.settings = dict(admin._default(), github_url="https://github.com/dummy/project",
                             branch="main", latest_sha="a" * 40, latest_message="dummy commit",
                             last_check_at="dummy-checked-time", update_available=True,
                             installed_sha="b" * 40)
        self.store.save(admin.MODULE_NAME, self.settings)
        self.app = Flask(__name__)
        self.app.secret_key = "dummy-session-key"
        self.app.config["CONFIG_DIR"] = self.store.base_dir
        self.app.register_blueprint(admin.bp)
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = "dummy-admin"
            session["csrf_token"] = "dummy-csrf"
        patcher = patch.object(admin, "_os_major_version", return_value="9")
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, path, data):
        return self.client.post(path, json=data, headers={"X-CSRF-Token": "dummy-csrf"})

    def assert_check_cleared(self):
        state = self.store.load(admin.MODULE_NAME)
        self.assertEqual(state["latest_sha"], "")
        self.assertEqual(state["latest_message"], "")
        self.assertIsNone(state["last_check_at"])
        self.assertFalse(state["update_available"])
        self.assertEqual(state["installed_sha"], "b" * 40)

    def test_repository_change_requires_a_new_check(self):
        result = self.post("/admin/api/github", {"github_url": "https://github.com/dummy/other", "branch": "main"})
        self.assertEqual(result.status_code, 200)
        self.assert_check_cleared()

    def test_branch_change_requires_a_new_check(self):
        result = self.post("/admin/api/github", {"github_url": self.settings["github_url"], "branch": "feature/test"})
        self.assertEqual(result.status_code, 200)
        self.assert_check_cleared()

    def test_same_source_keeps_the_reviewed_commit(self):
        result = self.post("/admin/api/github", {"github_url": self.settings["github_url"], "branch": "main"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.store.load(admin.MODULE_NAME)["latest_sha"], "a" * 40)
        self.assertTrue(self.store.load(admin.MODULE_NAME)["update_available"])

    def test_clearing_source_clears_the_check(self):
        self.post("/admin/api/github", {"github_url": "", "branch": "main"})
        self.assert_check_cleared()

    def test_invalid_commit_is_rejected_before_downloading(self):
        for value in ("", "../invalid", "a" * 39, ["a" * 40]):
            with self.subTest(value=value):
                self.store.save(admin.MODULE_NAME, dict(self.settings, latest_sha=value))
                with patch.object(admin.urllib.request, "urlopen") as download:
                    result = self.post("/admin/api/update/apply", {})
                self.assertEqual(result.status_code, 400)
                download.assert_not_called()

    def test_download_and_installed_state_use_the_same_commit(self):
        # 構造が正しい最小の架空ソースだけを展開し、実行はしない。
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, content in (("server_gui/__init__.py", b"# dummy package\n"),
                                  ("bin/dummy-helper", b"# dummy helper\n")):
                member = tarfile.TarInfo("dummy-archive/payload/server-gui/" + name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        package = self.root / "runtime/server_gui"
        binary = self.root / "runtime/bin"
        package.mkdir(parents=True)
        binary.mkdir()
        (package / "old.txt").write_text("previous dummy package", encoding="utf-8")
        (binary / "old.txt").write_text("previous dummy bin", encoding="utf-8")
        with patch.object(admin, "SERVER_GUI_PKG", package), \
                patch.object(admin, "SERVER_GUI_BIN", binary), \
                patch.object(admin, "_refresh_dnsmasq_runtime_guard"), \
                patch.object(admin, "_install_cve_mitigation", return_value=True), \
                patch.object(admin.subprocess, "Popen") as restart, \
                patch.object(admin.urllib.request, "urlopen", return_value=io.BytesIO(buffer.getvalue())) as download:
            result = self.post("/admin/api/update/apply", {})
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(download.call_args.args[0], "https://codeload.github.com/dummy/project/tar.gz/" + "a" * 40)
        self.assertEqual(result.json["installed_sha"], "a" * 40)
        self.assertEqual(self.store.load(admin.MODULE_NAME)["installed_sha"], "a" * 40)
        self.assertFalse(self.store.load(admin.MODULE_NAME)["update_available"])
        self.assertTrue((package / "__init__.py").is_file())
        self.assertTrue((binary / "dummy-helper").is_file())
        restart.assert_called_once()


if __name__ == "__main__":
    unittest.main()
