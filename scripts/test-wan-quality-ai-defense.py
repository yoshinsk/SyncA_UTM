#!/usr/bin/env python3
"""scripts/test-wan-quality-ai-defense.py - Static and pure-logic regression checks.

The test intentionally avoids Flask, firewalld, journald, WAN transfers, and
Jev API calls.  It verifies Python 3.9 syntax, the pure parsers and response
validation logic, installer timer wiring, and the fail-open firewall contract.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WAN_MODULE = ROOT / "payload/server-gui/server_gui/modules/wan_quality.py"
AI_MODULE = ROOT / "payload/server-gui/server_gui/modules/ai_defense.py"
APP_MODULE = ROOT / "payload/server-gui/server_gui/app.py"
ISO_INSTALLER = ROOT / "iso/payload/synca-install.sh"
ISO_FIRSTBOOT = ROOT / "iso/payload/synca-firstboot.sh"


def _source(path: Path) -> str:
    """Read one UTF-8 source file used by the static regression checks."""
    return path.read_text(encoding="utf-8")


def _load_selected_definitions(path: Path, names: set[str]) -> dict[str, Any]:
    """Execute pure selected definitions without importing Flask or Linux-only modules."""
    tree = ast.parse(_source(path), filename=str(path), feature_version=(3, 9))
    selected = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    namespace: dict[str, Any] = {"re": re, "Any": Any, "ipaddress": ipaddress, "json": json}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


class WanQualityTests(unittest.TestCase):
    """Verify WAN output parsing and the conservative summary conditions."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.logic = _load_selected_definitions(WAN_MODULE, {"_parse_ping_output", "_quality_summary"})

    def test_ping_parser_reads_loss_and_rtt(self) -> None:
        output = (
            "4 packets transmitted, 3 received, 25% packet loss, time 3012ms\n"
            "rtt min/avg/max/mdev = 12.100/25.250/43.700/8.400 ms\n"
        )
        parsed = self.logic["_parse_ping_output"](output)
        self.assertEqual(parsed["sent"], 4)
        self.assertEqual(parsed["received"], 3)
        self.assertEqual(parsed["packet_loss_percent"], 25.0)
        self.assertEqual(parsed["avg_ms"], 25.25)
        self.assertEqual(parsed["mdev_ms"], 8.4)

    def test_quality_indicator_does_not_claim_isp_fault(self) -> None:
        quality = self.logic["_quality_summary"](
            {"device": "wan0"},
            [{"ok": True, "packet_loss_percent": 0.0, "avg_ms": 12.0, "mdev_ms": 1.2}],
            {"ok": True},
            {"ok": True},
        )
        self.assertEqual(quality["state"], "good")
        warning = self.logic["_quality_summary"](
            {"device": "wan0"},
            [{"ok": True, "packet_loss_percent": 5.0, "avg_ms": 12.0, "mdev_ms": 1.2}],
            {"ok": True},
            {"ok": True},
        )
        self.assertEqual(warning["state"], "warning")


class AiDefenseTests(unittest.TestCase):
    """Verify anonymisation, strict Jev contract checks, and block thresholds."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.logic = _load_selected_definitions(
            AI_MODULE,
            {
                "JevResponseError",
                "_active_zone_bindings",
                "_build_jev_request",
                "_build_candidates",
                "_contains_port",
                "_discover_open_ports",
                "_drop_zone_is_drop",
                "_empty_exposure",
                "_firewall",
                "_is_terminal_deny_target",
                "_first_public_ip",
                "_merge_zone_exposure",
                "_normalise_port_tokens",
                "_parse_active_zone_bindings",
                "_parse_forward_ports",
                "_parse_zone_target",
                "_port_sort_key",
                "_public_ip",
                "_read_zone_exposure",
                "_runtime_zone_target",
                "_select_exposure_zones",
                "_service_port_tokens",
                "_source_bindings_can_reach_wan",
                "_validate_jev_response",
                "_requires_review",
                "_meets_local_block_guard",
                "_should_block",
            },
        )
        cls.logic["CLEAR_BENIGN_CONFIDENCE_MINIMUM"] = 0.85
        cls.logic["MAX_CANDIDATES"] = 20
        cls.logic["PORT_RE"] = re.compile(r"^(\d{1,5}(?:-\d{1,5})?)/(tcp|udp|sctp|dccp)$", re.IGNORECASE)
        cls.logic["SERVICE_RE"] = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
        cls.logic["IP_TOKEN_RE"] = re.compile(r"(?:\bfrom\s+|\brhost=|\bSRC=|\brate limit hit for\s+)([0-9A-Fa-f:.]+)")
        cls.logic["ipaddress"] = ipaddress

    def test_jev_request_never_contains_source_ip(self) -> None:
        candidates = [{
            "id": "source-001",
            "ip": "8.8.4.4",
            "event_types": {"ssh_invalid_user": 1, "ssh_failed_auth": 3},
            "event_total": 4,
            "target_ports": ["22/tcp"],
        }]
        state, questions = self.logic["_build_jev_request"](candidates, ["22/tcp"], 8)
        serialized = json.dumps({"state": state, "questions": questions})
        self.assertNotIn("8.8.4.4", serialized)
        self.assertIn("source-001", serialized)
        self.assertEqual(set(state["candidates"][0]), {"id", "event_counts", "target_ports", "event_total"})

    def test_jev_response_requires_complete_probability_contract(self) -> None:
        response = {
            "model": "jev-1.13.0",
            "usage": {"input_tokens": 10, "output_tokens": 4},
            "answers": {
                "source-001": {
                    "type": "choice",
                    "choice": "malicious",
                    "confidence": 0.91,
                    "probabilities": {"malicious": 0.93, "benign": 0.02, "insufficient": 0.05},
                }
            },
        }
        answers = self.logic["_validate_jev_response"](response, {"source-001"})
        self.assertEqual(answers["source-001"]["choice"], "malicious")
        invalid = dict(response)
        invalid["usage"] = {"input_tokens": 10}
        with self.assertRaises(self.logic["JevResponseError"]):
            self.logic["_validate_jev_response"](invalid, {"source-001"})

    def test_block_uses_the_safe_direction_for_jev_uncertainty(self) -> None:
        candidate = {"event_types": {"ssh_invalid_user": 1, "ssh_failed_auth": 2}, "event_total": 3}
        answer = {"choice": "malicious", "confidence": 0.86, "probabilities": {"malicious": 0.91}}
        self.assertTrue(self.logic["_should_block"](candidate, answer))
        weak = {"choice": "malicious", "confidence": 0.84, "probabilities": {"malicious": 0.99}}
        self.assertTrue(self.logic["_should_block"](candidate, weak))
        uncertain = {"choice": "insufficient", "confidence": 0.50, "probabilities": {"malicious": 0.10}}
        self.assertTrue(self.logic["_should_block"](candidate, uncertain))
        benign = {"choice": "benign", "confidence": 0.90, "probabilities": {"malicious": 0.0}}
        self.assertFalse(self.logic["_should_block"](candidate, benign))
        self.assertFalse(self.logic["_meets_local_block_guard"]({"ssh_failed_auth": 1}, 1))

    def test_open_port_ranges_remain_in_scope(self) -> None:
        forward = self.logic["_parse_forward_ports"]("port=10000-10100:proto=tcp:toport=443:toaddr=192.0.2.10")
        self.assertEqual(forward, ["10000-10100/tcp"])
        records = {
            "8.8.4.4": {
                "events": {"firewall_logged_packet": 3},
                "ports": {"10042/tcp"},
            }
        }
        candidates = self.logic["_build_candidates"](records, {"10000-10100/tcp"})
        self.assertEqual(candidates[0]["target_ports"], ["10042/tcp"])

    def test_source_bound_allow_zone_contributes_its_open_ports(self) -> None:
        """Source-zone allow lists must not disappear behind an empty WAN zone."""

        class Result:
            def __init__(self, stdout: str, ok: bool = True) -> None:
                self.stdout = stdout
                self.ok = ok

        calls: list[tuple[str, ...]] = []
        responses = {
            ("ip", "-j", "route", "get", "1.1.1.1"): Result('[{"dev": "ens3"}]'),
            ("firewall-cmd", "--get-zone-of-interface=ens3"): Result("public\n"),
            (
                "firewall-cmd",
                "--get-active-zones",
            ): Result(
                "drop\n"
                "  sources: ipset:cn-ipv4\n"
                "japan\n"
                "  sources: ipset:jp-ipv4\n"
                "public\n"
                "  interfaces: ens3\n"
                "trusted\n"
                "  sources: 192.168.1.0/24\n"
            ),
            ("firewall-cmd", "--zone=drop", "--list-all"): Result("drop\n  target: DROP\n"),
            ("firewall-cmd", "--zone=japan", "--list-all"): Result("japan\n  target: default\n"),
            ("firewall-cmd", "--zone=public", "--list-services"): Result(""),
            ("firewall-cmd", "--zone=public", "--list-ports"): Result(""),
            ("firewall-cmd", "--zone=public", "--list-forward-ports"): Result(""),
            ("firewall-cmd", "--zone=japan", "--list-services"): Result("https ssh\n"),
            ("firewall-cmd", "--zone=japan", "--list-ports"): Result("4444/tcp\n"),
            (
                "firewall-cmd",
                "--zone=japan",
                "--list-forward-ports",
            ): Result("port=10000-10100:proto=udp:toport=10000-10100:toaddr=192.0.2.10\n"),
            ("firewall-cmd", "--permanent", "--service=https", "--get-ports"): Result("443/tcp\n"),
            ("firewall-cmd", "--permanent", "--service=ssh", "--get-ports"): Result("22/tcp\n"),
        }

        def fake_run(argv: list[str], timeout: int = 0) -> Result:
            key = tuple(argv)
            calls.append(key)
            return responses.get(key, Result("", ok=False))

        self.logic["run"] = fake_run
        exposure = self.logic["_discover_open_ports"]()
        self.assertEqual(exposure["zone"], "public")
        self.assertEqual([item["name"] for item in exposure["zones"]], ["public", "japan"])
        self.assertEqual(exposure["excluded_zones"], ["drop"])
        self.assertEqual(exposure["ports"], ["22/tcp", "443/tcp", "4444/tcp", "10000-10100/udp"])
        self.assertIn(("firewall-cmd", "--permanent", "--service=ssh", "--get-ports"), calls)

    def test_drop_target_guard_reads_runtime_and_saved_zone_views(self) -> None:
        """The block guard must work on firewalld builds with permanent-only get-target."""

        class Result:
            def __init__(self, stdout: str) -> None:
                self.stdout = stdout
                self.ok = True

        calls: list[tuple[str, ...]] = []

        def fake_run(argv: list[str], timeout: int = 0) -> Result:
            calls.append(tuple(argv))
            return Result("drop\n  target: DROP\n")

        self.logic["run"] = fake_run
        self.assertTrue(self.logic["_drop_zone_is_drop"](False))
        self.assertTrue(self.logic["_drop_zone_is_drop"](True))
        self.assertIn(("firewall-cmd", "--zone=drop", "--list-all"), calls)
        self.assertIn(("firewall-cmd", "--permanent", "--zone=drop", "--list-all"), calls)

    def test_gui_rate_limit_source_is_extracted_locally(self) -> None:
        source = self.logic["_first_public_ip"]("rate limit hit for 8.8.4.4")
        self.assertEqual(source, "8.8.4.4")


class WiringTests(unittest.TestCase):
    """Verify installation and application wiring for both supported EL paths."""

    def test_python39_syntax_and_application_registration(self) -> None:
        for path in (WAN_MODULE, AI_MODULE, APP_MODULE):
            ast.parse(_source(path), filename=str(path), feature_version=(3, 9))
        app_source = _source(APP_MODULE)
        self.assertIn("wan_quality_module.register(app)", app_source)
        self.assertIn("ai_defense_module.register(app)", app_source)

    def test_installer_and_firstboot_enable_the_timer(self) -> None:
        installer = _source(ISO_INSTALLER)
        firstboot = _source(ISO_FIRSTBOOT)
        self.assertIn("server-gui-ai-defense.service", installer)
        self.assertIn("server-gui-ai-defense.timer", installer)
        self.assertIn("OnUnitActiveSec=1h", installer)
        self.assertIn("server-gui-ai-defense.timer", firstboot)

    def test_firewall_path_never_reloads_firewalld(self) -> None:
        source = _source(AI_MODULE)
        self.assertIn("synca-ai-defense-v4", source)
        self.assertIn("synca-ai-defense-v6", source)
        self.assertNotIn('"firewall-cmd", "--reload"', source)
        self.assertIn("CLEAR_BENIGN_CONFIDENCE_MINIMUM = 0.85", source)
        self.assertIn("any nonzero malicious probability", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
