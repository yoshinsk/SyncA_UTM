"""scripts/test-upnp-policy.py - 許可LAN内の共有削除とLAN外の拒否を模擬検証する。"""
import ipaddress
from pathlib import Path
import runpy
import struct
import threading
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
SYMBOLS = runpy.run_path(str(ROOT / "payload/server-gui/bin/synca-upnpd"), run_name="upnp_policy_test")


class UpnpPolicyTests(unittest.TestCase):
    """共有削除を維持する製品方針を、実通信・firewall操作なしで保護する。"""

    def setUp(self):
        self.daemon = SYMBOLS["SyncAUpnpDaemon"].__new__(SYMBOLS["SyncAUpnpDaemon"])
        self.daemon.config = {"secure_mode": True}
        self.daemon.allowed_networks = [ipaddress.ip_network("192.0.2.0/24")]
        self.daemon.lock = threading.RLock()
        self.mapping = {"key": "TCP:41001:", "proto": "TCP", "external_port": 41001,
                        "internal_ip": "192.0.2.10", "internal_port": 8080, "client_ip": "192.0.2.10"}
        self.daemon.mappings = {self.mapping["key"]: self.mapping}
        self.daemon.remove_firewall_rules = Mock()
        self.daemon.save_mappings = Mock()

    def assert_shared_delete_completed(self):
        """実装内部の順序ではなく、共有削除の状態と外部操作の対象を照合する。"""
        self.assertEqual(self.daemon.mappings, {})
        self.daemon.remove_firewall_rules.assert_called_once_with(self.mapping)
        self.daemon.save_mappings.assert_called_once()

    def test_allowed_lan_controller_can_delete_shared_soap_mapping(self):
        self.daemon.handle_soap("DeletePortMapping", {
            "NewProtocol": "TCP", "NewExternalPort": "41001",
        }, "192.0.2.20")
        self.assert_shared_delete_completed()

    def test_allowed_lan_controller_can_delete_shared_natpmp_mapping(self):
        request = struct.pack("!BBHHHI", 0, 2, 0, 8080, 41001, 0)
        reply = SYMBOLS["handle_natpmp"](self.daemon, request, "192.0.2.20")
        self.assertEqual(struct.unpack("!H", reply[2:4])[0], 0)
        self.assert_shared_delete_completed()

    def test_outside_lan_cannot_delete_a_mapping(self):
        with self.assertRaises(SYMBOLS["UpnpError"]) as caught:
            self.daemon.delete_mapping("TCP", 41001, "198.51.100.20")
        self.assertEqual(caught.exception.code, 606)
        self.assertEqual(self.daemon.mappings, {self.mapping["key"]: self.mapping})
        self.daemon.remove_firewall_rules.assert_not_called()
        self.daemon.save_mappings.assert_not_called()

    def test_secure_mode_still_limits_forwarding_target(self):
        with self.assertRaises(SYMBOLS["UpnpError"]) as caught:
            self.daemon.assert_client_allowed("192.0.2.20", "192.0.2.10")
        self.assertEqual(caught.exception.code, 606)

    def test_absent_natpmp_mapping_keeps_idempotent_success(self):
        self.daemon.mappings.clear()
        request = struct.pack("!BBHHHI", 0, 2, 0, 8080, 41001, 0)
        reply = SYMBOLS["handle_natpmp"](self.daemon, request, "192.0.2.20")
        self.assertEqual(struct.unpack("!H", reply[2:4])[0], 0)
        self.daemon.remove_firewall_rules.assert_not_called()
        self.daemon.save_mappings.assert_not_called()


if __name__ == "__main__":
    unittest.main()
