#!/usr/bin/env python3
"""scripts/test-dns-defaults.py - DNS初期値の補完と既存設定の保持を隔離して検証する。"""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "payload/server-gui"))
from server_gui import dns_defaults as dns
from server_gui import dnsmasq_apply as model
from server_gui.config_store import ConfigStore


class DnsDefaultsTests(unittest.TestCase):
    """OS操作は全てstubに置き換え、一時JSONだけを書き込む。"""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = ConfigStore(temp.name)
        self.commands = []
        self.responses = {
            ("ip", "-j", "-4", "route", "show", "default"): '[{"dev":"wan0","metric":100}]',
            ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", "wan0"): "fixture-uuid",
            ("nmcli", "-g", "ipv4.dns", "connection", "show", "uuid", "fixture-uuid"): "",
            ("nmcli", "-g", "ipv4.ignore-auto-dns", "connection", "show", "uuid", "fixture-uuid"): "no",
        }
        self.command = patch.object(dns, "_command", side_effect=self.command_result).start()
        self.apply = patch.object(dns, "apply").start()
        self.addCleanup(patch.stopall)

    def command_result(self, argv):
        self.commands.append(argv)
        return self.responses.get(tuple(argv), "")

    def test_missing_model_is_initialized(self):
        dns.initialize(self.store.base_dir)
        data = self.store.load("dnsmasq")
        self.assertEqual([u["server"] for u in data["dns"]["upstream"]], ["1.1.1.3", "1.0.0.3"])
        self.assertEqual(data["dhcp"]["options"][0]["value"], "0.0.0.0,1.1.1.3,1.0.0.3")
        self.apply.assert_called_once()

    def test_explicit_old_defaults_and_dhcp_dns_are_preserved(self):
        data = model.default()
        data["dns"]["upstream"] = [{"server": "1.1.1.1"}, {"server": "1.0.0.1"}]
        data["dhcp"]["options"] = [{"option": "6", "value": "192.0.2.1,192.0.2.53"}]
        self.store.save("dnsmasq", data)
        dns.initialize(self.store.base_dir)
        self.assertEqual(self.store.load("dnsmasq"), data)
        self.apply.assert_not_called()

    def test_explicit_empty_upstream_and_empty_dns_option_are_preserved(self):
        data = model.default()
        data["dns"]["upstream"] = []
        data["dhcp"]["options"] = [{"option": "dns-server", "value": ""}]
        self.store.save("dnsmasq", data)
        dns.initialize(self.store.base_dir)
        self.assertEqual(self.store.load("dnsmasq"), data)
        self.assertNotIn("no-resolv", model.generate(data))

    def test_tagged_dns_is_preserved_alongside_global_fallback(self):
        data = model.default()
        custom = {"option": "dns-server", "value": "192.0.2.53", "tag": "office"}
        data["dhcp"]["options"] = [custom]
        self.store.save("dnsmasq", data)
        dns.initialize(self.store.base_dir)
        self.assertIn(custom, self.store.load("dnsmasq")["dhcp"]["options"])
        generated = model.generate(self.store.load("dnsmasq"))
        self.assertIn("dhcp-option=tag:office,option:dns-server,192.0.2.53", generated)
        self.assertIn("dhcp-option=option:dns-server,0.0.0.0,1.1.1.3,1.0.0.3", generated)

    def test_invalid_json_is_never_replaced(self):
        path = self.store.path("dnsmasq")
        path.write_text("{invalid", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            dns.initialize(self.store.base_dir)
        self.assertEqual(path.read_text(), "{invalid")
        self.command.assert_not_called()

    def test_apply_failure_restores_saved_model(self):
        data = {"dns": {"hosts": [], "cnames": []}, "dhcp": {"options": []}}
        self.store.save("dnsmasq", data)
        self.apply.side_effect = RuntimeError("fixture dnsmasq validation failure")
        with self.assertRaises(RuntimeError):
            dns.initialize(self.store.base_dir)
        self.assertEqual(self.store.load("dnsmasq"), data)
        self.assertFalse(self.store.path("dns_defaults").exists())

    def test_system_dns_changes_only_dns_properties(self):
        self.assertTrue(dns._initialize_system_dns())
        mutations = [args for args in self.commands if "modify" in args]
        self.assertEqual(mutations, [
            ["nmcli", "connection", "modify", "uuid", "fixture-uuid", "ipv4.dns", "1.1.1.3,1.0.0.3", "ipv4.ignore-auto-dns", "yes"],
            ["nmcli", "device", "modify", "wan0", "ipv4.dns", "1.1.1.3,1.0.0.3", "ipv4.ignore-auto-dns", "yes"],
        ])

    def test_apply_failure_does_not_leave_a_previously_missing_model(self):
        self.apply.side_effect = RuntimeError("fixture validation failure")
        with self.assertRaises(RuntimeError):
            dns.initialize(self.store.base_dir)
        self.assertFalse(self.store.path("dnsmasq").exists())

    def test_system_custom_dns_and_explicit_empty_are_preserved(self):
        for existing, ignore in (("192.0.2.53", "no"), ("", "yes")):
            with self.subTest(dns=existing, ignore=ignore):
                self.commands.clear()
                self.responses[("nmcli", "-g", "ipv4.dns", "connection", "show", "uuid", "fixture-uuid")] = existing
                self.responses[("nmcli", "-g", "ipv4.ignore-auto-dns", "connection", "show", "uuid", "fixture-uuid")] = ignore
                self.assertTrue(dns._initialize_system_dns())
                self.assertFalse(any("modify" in args for args in self.commands))

    def test_no_route_defers_system_initialization(self):
        self.responses[("ip", "-j", "-4", "route", "show", "default")] = "[]"
        dns.initialize(self.store.base_dir)
        self.assertFalse(self.store.load("dns_defaults")["system_initialized"])

    def test_runtime_failure_restores_persistent_profile(self):
        def fail_runtime(argv):
            if argv[:3] == ["nmcli", "device", "modify"]:
                raise RuntimeError("fixture failed")
            return self.command_result(argv)
        self.command.side_effect = fail_runtime
        with self.assertRaises(RuntimeError):
            dns._initialize_system_dns()
        self.assertEqual(self.commands[-1], ["nmcli", "connection", "modify", "uuid", "fixture-uuid",
                                             "ipv4.dns", "", "ipv4.ignore-auto-dns", "no"])

    def test_successful_initialization_is_not_repeated_after_manual_edit(self):
        dns.initialize(self.store.base_dir)
        data = self.store.load("dnsmasq")
        data["dns"]["upstream"] = []
        self.store.save("dnsmasq", data)
        self.command.reset_mock()
        self.apply.reset_mock()
        dns.initialize(self.store.base_dir)
        self.command.assert_not_called()
        self.apply.assert_not_called()
        self.assertEqual(self.store.load("dnsmasq"), data)

    def test_firstboot_and_bootstrap_share_defaults_with_lan_ip_first(self):
        for name, lan in (("iso/payload/synca-firstboot.sh", "${lan_ip}"),
                          ("scripts/bootstrap-synca-testhost.sh", "${LAN_IP}")):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn(lan + ",1.1.1.3,1.0.0.3", source)
        firstboot = (ROOT / "iso/payload/synca-firstboot.sh").read_text(encoding="utf-8")
        self.assertIn("${SYNCA_WAN_DNS-1.1.1.3,1.0.0.3}", firstboot)


if __name__ == "__main__":
    unittest.main()
