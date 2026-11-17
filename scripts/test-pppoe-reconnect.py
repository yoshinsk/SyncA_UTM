"""scripts/test-pppoe-reconnect.py - GUI更新時のPPPoE移行・一度だけの再接続・障害時再試行を隔離検証する。"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))
from server_gui import pppoe_reconnect as reconnect
from server_gui.config_store import ConfigStore

UUID = "11111111-2222-3333-4444-555555555555"
OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class PppoeReconnectTests(unittest.TestCase):
    """nmcliとsystemdをすべて模擬し、実ネットワークやサービスを変更しない。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name)
        self.store = ConfigStore(self.config)
        self.profiles = {UUID: ["yes", -1, 0, 0]}
        self.active = {UUID}
        self.calls = []
        self.fail_modify = set()
        self.fail_schedule = False
        self.fail_activate = False
        self.timer_active = False
        self.command = patch.object(reconnect, "_command", side_effect=self.run_command).start()
        self.addCleanup(patch.stopall)

    def run_command(self, argv, **kwargs):
        """プロファイル・接続中UUID・予約状態を別々に持ち、保存と再接続を区別する。"""
        self.calls.append(argv)
        if argv[:6] == ["nmcli", "-t", "--escape", "no", "-f", "UUID,TYPE"]:
            return "\n".join(uuid + ":pppoe" for uuid in self.profiles) + "\nnot-pppoe:ethernet"
        if argv == ["nmcli", "-t", "-f", "UUID", "connection", "show", "--active"]:
            return "\n".join(sorted(self.active))
        if argv[:2] == ["nmcli", "-g"]:
            return "\n".join(str(value) for value in self.profiles[argv[-1]])
        if argv[:3] == ["nmcli", "connection", "modify"]:
            uuid = argv[4]
            if uuid in self.fail_modify:
                raise RuntimeError("fixture modify failure")
            # 実設定の変更前に、再開可能な意図の記録が永続化済みかを確認する。
            recorded = self.store.load(reconnect.MODULE)["profiles"][uuid]
            self.assertTrue(recorded["prepared"])
            for key, value in zip(argv[5::2], argv[6::2]):
                self.assertIn(key, reconnect.PROPERTIES[1:])
                self.profiles[uuid][reconnect.PROPERTIES.index(key)] = int(value)
            return ""
        if argv[:2] == ["systemctl", "is-active"]:
            return "active\ninactive" if self.timer_active else "inactive\ninactive"
        if argv[0] == "systemd-run":
            if self.fail_schedule:
                raise RuntimeError("fixture schedule failure")
            self.timer_active = True
            return ""
        if argv[:4] == ["nmcli", "--wait", "60", "connection"]:
            if self.fail_activate:
                raise RuntimeError("fixture activation failure")
            return "Connection successfully activated"
        raise AssertionError(argv)

    def modifications(self):
        """永続設定の変更だけを抽出し、起動時の重複変更を確認する。"""
        return [argv for argv in self.calls if argv[:3] == ["nmcli", "connection", "modify"]]

    def activations(self):
        """実際の再接続要求を抽出し、単なる接続照会を数えない。"""
        return [argv for argv in self.calls if argv[:3] == ["nmcli", "--wait", "60"]]

    def test_legacy_profile_is_saved_then_scheduled_without_inline_disconnect(self):
        result = reconnect.initialize(self.config)
        self.assertTrue(result["ok"])
        self.assertEqual(self.profiles[UUID], ["yes", 0, 10, 6])
        self.assertEqual(result["pending"], 1)
        self.assertEqual(self.activations(), [])
        schedule = next(argv for argv in self.calls if argv[0] == "systemd-run")
        self.assertIn("--on-active=20s", schedule)
        self.assertIn("--property=WorkingDirectory=/opt/server-gui", schedule)
        self.assertIn("server_gui.pppoe_reconnect", schedule)
        self.assertFalse(any("password" in part or "username" in part
                             for argv in self.calls for part in argv))
        self.assertEqual(self.store.path(reconnect.MODULE).stat().st_mode & 0o777, 0o600)

    def test_activation_is_once_only(self):
        reconnect.initialize(self.config)
        self.assertEqual(reconnect.activate(self.config)["reconnected"], 1)
        self.assertEqual(reconnect.activate(self.config)["reconnected"], 0)
        reconnect.initialize(self.config)
        self.assertEqual(len(self.activations()), 1)
        self.assertEqual(len(self.modifications()), 1)

    def test_multiple_gui_workers_change_and_schedule_once(self):
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: reconnect.initialize(self.config), range(2)))
        self.assertTrue(all(result["ok"] for result in results))
        self.assertEqual(len(self.modifications()), 1)
        self.assertEqual(sum(argv[0] == "systemd-run" for argv in self.calls), 1)

    def test_later_operator_changes_are_preserved(self):
        reconnect.initialize(self.config)
        reconnect.activate(self.config)
        self.profiles[UUID] = ["yes", 3, 0, 0]
        reconnect.initialize(self.config)
        self.assertEqual(self.profiles[UUID], ["yes", 3, 0, 0])
        self.assertEqual(len(self.modifications()), 1)

    def test_autoconnect_disabled_profile_is_not_modified_or_restarted(self):
        self.profiles[UUID][0] = "no"
        result = reconnect.initialize(self.config)
        self.assertTrue(result["ok"])
        self.assertEqual(self.profiles[UUID], ["no", -1, 0, 0])
        self.assertEqual(self.modifications(), [])
        self.assertEqual(result["pending"], 0)

    def test_inactive_profile_is_saved_without_forcing_it_up(self):
        self.active.clear()
        result = reconnect.initialize(self.config)
        self.assertEqual(self.profiles[UUID], ["yes", 0, 10, 6])
        self.assertEqual(result["pending"], 0)
        self.assertFalse(any(argv[0] == "systemd-run" for argv in self.calls))
        reconnect.activate(self.config)
        self.assertEqual(self.activations(), [])

    def test_custom_or_partially_disabled_monitor_values_are_preserved(self):
        for interval, failure in ((30, 5), (10, 0), (0, 6)):
            with self.subTest(interval=interval, failure=failure):
                self.store.save(reconnect.MODULE, {"profiles": {}})
                self.profiles[UUID] = ["yes", -1, interval, failure]
                result = reconnect.initialize(self.config)
                self.assertEqual(self.profiles[UUID], ["yes", 0, interval, failure])
                self.assertEqual(result["pending"], 0)

    def test_already_protected_profile_needs_no_reconnect(self):
        self.profiles[UUID] = ["yes", 0, 10, 6]
        result = reconnect.initialize(self.config)
        self.assertEqual(result["updated"], 0)
        self.assertEqual(result["pending"], 0)
        self.assertEqual(self.modifications(), [])

    def test_failed_profile_is_retried_without_rewriting_successful_profile(self):
        self.profiles[OTHER] = ["yes", -1, 0, 0]
        self.fail_modify.add(OTHER)
        self.assertFalse(reconnect.initialize(self.config)["ok"])
        state = self.store.load(reconnect.MODULE)["profiles"]
        self.assertFalse(state[UUID]["prepared"])
        self.assertTrue(state[OTHER]["prepared"])
        self.fail_modify.clear()
        self.assertTrue(reconnect.initialize(self.config)["ok"])
        self.assertEqual(sum(argv[4] == UUID for argv in self.modifications()), 1)
        self.assertEqual(self.profiles[OTHER], ["yes", 0, 10, 6])

    def test_schedule_failure_keeps_pending_for_next_startup(self):
        self.fail_schedule = True
        self.assertFalse(reconnect.initialize(self.config)["ok"])
        self.assertTrue(self.store.load(reconnect.MODULE)["profiles"][UUID]["pending"])
        self.fail_schedule = False
        self.assertTrue(reconnect.initialize(self.config)["ok"])
        self.assertEqual(len(self.modifications()), 1)

    def test_interrupted_save_after_modify_keeps_activation_intent(self):
        self.profiles[UUID] = ["yes", 0, 10, 6]
        self.store.save(reconnect.MODULE, {"profiles": {UUID: {
            "version": 1, "prepared": True, "pending": True,
            "before": dict(zip(reconnect.PROPERTIES, ["yes", -1, 0, 0])),
            "target": dict(zip(reconnect.PROPERTIES, self.profiles[UUID])),
        }}})
        result = reconnect.initialize(self.config)
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["updated"], 0)
        self.assertEqual(reconnect.activate(self.config)["reconnected"], 1)

    def test_operator_edit_before_deferred_activation_is_preserved(self):
        reconnect.initialize(self.config)
        self.profiles[UUID] = ["yes", 0, 30, 3]
        self.assertEqual(reconnect.activate(self.config)["reconnected"], 0)
        self.assertEqual(self.activations(), [])

    def test_manual_disconnect_or_wan_switch_cancels_deferred_activation(self):
        reconnect.initialize(self.config)
        self.active.clear()
        self.assertEqual(reconnect.activate(self.config)["reconnected"], 0)
        self.assertEqual(self.activations(), [])

    def test_disabling_autoconnect_after_scheduling_cancels_activation(self):
        reconnect.initialize(self.config)
        self.profiles[UUID][0] = "no"
        self.assertEqual(reconnect.activate(self.config)["reconnected"], 0)
        self.assertEqual(self.activations(), [])

    def test_failed_activation_is_not_recorded_as_success(self):
        reconnect.initialize(self.config)
        self.fail_activate = True
        result = reconnect.activate(self.config)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reconnected"], 0)
        self.assertTrue(self.store.load(reconnect.MODULE)["profiles"][UUID]["pending"])
        self.assertEqual(self.profiles[UUID], ["yes", 0, 10, 6])

    def test_opt_out_prevents_both_migration_and_pending_activation(self):
        flag = self.config / (reconnect.MODULE + ".disabled")
        flag.touch()
        self.assertTrue(reconnect.initialize(self.config)["disabled"])
        self.assertEqual(self.calls, [])
        flag.unlink()
        reconnect.initialize(self.config)
        self.calls.clear()
        flag.touch()
        self.assertTrue(reconnect.activate(self.config)["disabled"])
        self.assertEqual(self.calls, [])

    def test_no_pppoe_profile_is_a_successful_no_op(self):
        self.profiles.clear()
        result = reconnect.initialize(self.config)
        self.assertTrue(result["ok"])
        self.assertEqual(result["updated"], 0)
        self.assertEqual(self.modifications(), [])

    def test_malformed_properties_do_not_change_profile(self):
        self.profiles[UUID] = ["yes", -1, "unknown", 0]
        self.assertFalse(reconnect.initialize(self.config)["ok"])
        self.assertEqual(self.modifications(), [])

    def test_corrupt_state_is_preserved(self):
        path = self.store.path(reconnect.MODULE)
        path.write_text("{broken", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            reconnect.initialize(self.config)
        self.assertEqual(path.read_text(encoding="utf-8"), "{broken")
        self.assertEqual(self.calls, [])

    def test_invalid_state_shape_is_preserved(self):
        self.store.save(reconnect.MODULE, {"profiles": {UUID: False}})
        with self.assertRaises(ValueError):
            reconnect.initialize(self.config)
        self.assertFalse(self.store.load(reconnect.MODULE)["profiles"][UUID])
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
