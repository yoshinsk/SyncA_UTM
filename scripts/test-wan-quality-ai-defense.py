#!/usr/bin/env python3
"""scripts/test-wan-quality-ai-defense.py - Static and pure-logic regression checks.

The test intentionally avoids Flask, firewalld, journald, WAN transfers, and
Jev API calls.  It verifies Python 3.9 syntax, the pure parsers and response
validation logic, installer timer wiring, and the fail-open firewall contract.
"""
from __future__ import annotations

import ast
import io
import ipaddress
import json
import math
import re
import socket
import ssl
import struct
import unittest
import urllib.error
import urllib.request
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


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
        cls.logic = _load_selected_definitions(WAN_MODULE, {
            "_parse_ping_output", "_quality_summary", "_ping_target",
            "_measure_http_transfer", "_icmp_checksum", "_icmp_reply_matches",
        })
        cls.logic.update({
            "math": math, "struct": struct,
            "INTERFACE_RE": re.compile(r"^[A-Za-z0-9_.:+-]{1,64}$"),
            "PING_COUNT": 4, "PING_TIMEOUT_SECONDS": 2, "PING_DEADLINE_SECONDS": 12,
            "TRANSFER_CONNECT_TIMEOUT_SECONDS": 10, "TRANSFER_MAX_SECONDS": 45,
        })

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

    def test_missing_latency_is_never_reported_as_good(self) -> None:
        quality = self.logic["_quality_summary"](
            {"device": "wan0"}, [{"ok": False, "sent": 0}], {"ok": True}, {"ok": True},
        )
        self.assertEqual(quality["state"], "warning")

    def test_missing_ping_uses_native_icmp_and_preserves_rtt(self) -> None:
        commands = []

        def missing_ping(argv, **kwargs):
            commands.append(argv)
            return SimpleNamespace(returncode=127, ok=False, stdout="", stderr="ping not found")

        self.logic["run"] = missing_ping
        self.logic["_native_icmp_probe"] = lambda address, device: {
            "sent": 4, "received": 4, "avg_ms": 3.5, "packet_loss_percent": 0.0,
            "method": "icmp_socket",
        }
        result = self.logic["_ping_target"]({"name": "test", "address": "1.1.1.1"}, "wan0")
        self.assertTrue(result["ok"])
        self.assertEqual(result["avg_ms"], 3.5)
        self.assertEqual(commands[0][:4], ["env", "LC_ALL=C", "ping", "-4"])
        self.assertIn("wan0", commands[0])

    def test_icmp_reply_does_not_accept_other_requests_or_error_packets(self) -> None:
        payload = b"test-probe-token"
        ip_header = bytes([0x45]) + b"\0" * 19
        echo_reply = struct.pack("!BBHHH", 0, 0, 0, 321, 2) + payload
        matches = self.logic["_icmp_reply_matches"]
        self.assertTrue(matches(ip_header + echo_reply, 321, 2, payload))
        self.assertFalse(matches(ip_header + echo_reply, 322, 2, payload))
        self.assertFalse(matches(ip_header + echo_reply, 321, 3, payload))
        self.assertFalse(matches(ip_header + echo_reply, 321, 2, b"different"))
        self.assertFalse(matches(ip_header + struct.pack("!BBHHH", 3, 0, 0, 321, 2) + payload, 321, 2, payload))
        self.assertFalse(matches(ip_header[:10], 321, 2, payload))
        # Validate checksum closure for an odd-length echo request, not just
        # the sum of the helper's own intermediate values.
        data = struct.pack("!BBHHH", 8, 0, 0, 321, 2) + b"odd"
        checksum = self.logic["_icmp_checksum"](data)
        complete = struct.pack("!BBHHH", 8, 0, checksum, 321, 2) + b"odd"
        self.assertEqual(self.logic["_icmp_checksum"](complete), 0)

    def test_transfer_binds_ipv4_wan_with_a_total_deadline(self) -> None:
        calls = []

        def transfer(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(ok=True, returncode=0, stdout="200\t20000000\t0\t2.000", stderr="")

        self.logic["run"] = transfer
        result = self.logic["_measure_http_transfer"]("download", "https://speed.cloudflare.com/__down?bytes=20000000", 20_000_000, "wan0")
        self.assertTrue(result["ok"])
        self.assertEqual(result["mbps"], 80.0)
        argv, options = calls[0]
        self.assertIn("--ipv4", argv)
        self.assertEqual(argv[argv.index("--interface") + 1], "wan0")
        self.assertEqual(argv[argv.index("--max-time") + 1], "45")
        self.assertEqual(options["timeout"], 50)

    def test_incomplete_timeout_http_error_and_absent_route_are_not_speed_results(self) -> None:
        for returncode, output, error_code in (
            (0, "200\t1000\t0\t2.000", "incomplete_transfer"),
            (28, "000\t0\t0\t45.000", "timeout"),
            (22, "503\t0\t0\t0.020", "http_error"),
            (0, "200\t20000000\t0\tnan", "incomplete_transfer"),
        ):
            with self.subTest(returncode=returncode, output=output):
                self.logic["run"] = lambda argv, **kwargs: SimpleNamespace(
                    ok=returncode == 0, returncode=returncode, stdout=output, stderr="",
                )
                result = self.logic["_measure_http_transfer"]("download", "https://speed.cloudflare.com/__down", 20_000_000, "wan0")
                self.assertFalse(result["ok"])
                self.assertIsNone(result["mbps"])
                self.assertEqual(result["error_code"], error_code)
        # Missing routes must not invoke an unbound transfer on another NIC.
        self.logic["run"] = lambda *args, **kwargs: self.fail("unexpected WAN transfer")
        self.assertEqual(self.logic["_measure_http_transfer"]("download", "https://speed.cloudflare.com/__down", 20_000_000, "")["error_code"], "route_unavailable")

    def test_upload_measures_only_the_confirmed_payload(self) -> None:
        def upload(argv, **kwargs):
            self.assertEqual(kwargs["stdin"], "\0" * 1_000)
            return SimpleNamespace(ok=True, returncode=0, stdout="200\t0\t1000\t1.000", stderr="")

        self.logic["run"] = upload
        result = self.logic["_measure_http_transfer"]("upload", "https://speed.cloudflare.com/__up", 1_000, "wan0")
        self.assertTrue(result["ok"])
        self.assertEqual(result["bytes"], 1_000)

    def test_iso_requires_iputils_for_new_installations(self) -> None:
        for path in (ROOT / "iso/package-lists/synca-rpms.txt", ROOT / "iso/kickstart/synca-utm.ks"):
            self.assertIn("iputils", _source(path).splitlines(), str(path))


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
                "_call_jev",
                "_jev_failure_details",
                "_build_candidates",
                "_block_ip",
                "_direct_block_rules",
                "_direct_kernel_rule_present",
                "_ensure_drop_source",
                "_ensure_ipset",
                "_entry_absent",
                "_entry_already_present",
                "_ipset_info_matches",
                "_update_direct_block",
                "unblock_ip",
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
                "run_scheduled_check",
            },
        )
        cls.logic["CLEAR_BENIGN_CONFIDENCE_MINIMUM"] = 0.85
        cls.logic["MAX_CANDIDATES"] = 20
        cls.logic["PORT_RE"] = re.compile(r"^(\d{1,5}(?:-\d{1,5})?)/(tcp|udp|sctp|dccp)$", re.IGNORECASE)
        cls.logic["SERVICE_RE"] = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
        cls.logic["IP_TOKEN_RE"] = re.compile(r"(?:\bfrom\s+|\brhost=|\bSRC=|\brate limit hit for\s+)([0-9A-Fa-f:.]+)")
        cls.logic["ipaddress"] = ipaddress
        cls.logic.update({
            "urllib": urllib, "socket": socket, "ssl": ssl,
            "Path": Path, "MODULE_NAME": "ai_defense",
            "JEV_URL": "https://api.typesafe.ai/v1/systemone", "JEV_MODEL": "jev-latest",
            "JEV_TIMEOUT_SECONDS": 30, "JEV_MAX_RESPONSE_BYTES": 512 * 1024,
            "JEV_MAX_REQUEST_BYTES": 64 * 1024,
            "IPSET_V4": "synca-ai-defense-v4", "IPSET_V6": "synca-ai-defense-v6",
            "DIRECT_BLOCK_COMMENT": "synca-ai-defense", "DIRECT_BLOCK_PRIORITY": "-32768",
        })

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
        self.assertIsInstance(questions, dict)
        self.assertEqual(set(questions), {"source-001"})
        self.assertEqual(set(questions["source-001"]), {"type", "instructions", "criteria"})
        self.assertEqual(questions["source-001"]["type"], "choice")

    def test_each_jev_question_is_bound_to_its_own_candidate(self) -> None:
        candidates = [
            {"id": "source-001", "ip": "8.8.4.4", "event_types": {"ssh_failed_auth": 3}, "event_total": 3, "target_ports": ["22/tcp"]},
            {"id": "source-002", "ip": "1.1.1.1", "event_types": {"http_suspicious_path": 1}, "event_total": 1, "target_ports": ["443/tcp"]},
        ]
        state, questions = self.logic["_build_jev_request"](candidates, ["22/tcp", "443/tcp"], 8)
        self.assertEqual(set(questions), {"source-001", "source-002"})
        self.assertIn("`candidates[0]`", questions["source-001"]["instructions"])
        self.assertIn("`candidates[1]`", questions["source-002"]["instructions"])
        self.assertNotIn("8.8.4.4", json.dumps({"state": state, "questions": questions}))

    def test_jev_transport_sends_the_v1_contract_and_retries_only_overload(self) -> None:
        response = {
            "model": "jev-1.13.0", "usage": {"input_tokens": 10, "output_tokens": 4},
            "answers": {"source-001": {"type": "choice", "choice": "malicious", "confidence": 0.9,
                        "probabilities": {"malicious": 1.0, "benign": 0.0, "insufficient": 0.0}}},
        }
        question = {"source-001": {"type": "choice", "instructions": "test", "criteria": {
            "malicious": "attack", "benign": "normal", "insufficient": "unknown",
        }}}
        sleeps = []
        self.logic["time"] = SimpleNamespace(sleep=sleeps.append)
        overload = urllib.error.HTTPError("https://api.typesafe.ai/v1/systemone", 529, "overload", {}, io.BytesIO(b""))
        with patch("urllib.request.urlopen", side_effect=[overload, io.BytesIO(json.dumps(response).encode())]) as opened:
            answer = self.logic["_call_jev"]("unit-test-key", {}, question)
            self.assertEqual(answer["source-001"]["choice"], "malicious")
            self.assertEqual(opened.call_count, 2)
            self.assertEqual(sleeps, [0.5])
            body = json.loads(opened.call_args.args[0].data)
            self.assertEqual(body["questions"], question)
        for failure in (urllib.error.HTTPError("https://api.typesafe.ai/v1/systemone", 422, "bad question", {}, io.BytesIO(b"")),
                        urllib.error.URLError("connection unavailable")):
            with patch("urllib.request.urlopen", side_effect=failure) as opened:
                with self.assertRaises(type(failure)):
                    self.logic["_call_jev"]("unit-test-key", {}, question)
                self.assertEqual(opened.call_count, 1)
        with patch("urllib.request.urlopen", return_value=io.BytesIO(b"not JSON")):
            with self.assertRaises(self.logic["JevResponseError"]):
                self.logic["_call_jev"]("unit-test-key", {}, question)

    def test_jev_failure_details_do_not_echo_provider_data_or_secrets(self) -> None:
        secret = "provider-secret-that-must-not-be-returned"
        for status, category in ((401, "authentication"), (422, "request_format"), (429, "rate_limit"), (529, "provider_error")):
            with self.subTest(status=status):
                error = urllib.error.HTTPError("https://api.typesafe.ai/" + secret, status, secret, {}, io.BytesIO(secret.encode()))
                details = self.logic["_jev_failure_details"](error)
                self.assertEqual(details["error_category"], category)
                self.assertEqual(details["upstream_http_status"], status)
                self.assertNotIn(secret, json.dumps(details))
        for reason, category in ((TimeoutError("private"), "timeout"), (socket.gaierror("private"), "dns"),
                                 (ssl.SSLError("private"), "tls")):
            self.assertEqual(self.logic["_jev_failure_details"](urllib.error.URLError(reason))["error_category"], category)

    def test_jev_failure_records_diagnostic_without_blocking(self) -> None:
        namespace = dict(self.logic)
        state = {"enabled": True, "api_key": "unit-test-key", "interval_hours": 8}
        saved = []
        namespace.update({
            "ConfigStore": lambda directory: SimpleNamespace(load=lambda *args: state),
            "_default_state": lambda: {}, "_normalise_state": lambda value: value,
            "_exclusive_defense_lock": lambda directory: nullcontext(),
            "_discover_open_ports": lambda: {"ports": ["22/tcp"]},
            "_collect_log_events": lambda *args: {},
            "_build_candidates": lambda *args: [{"id": "source-001", "ip": "8.8.4.4", "event_types": {"ssh_failed_auth": 3},
                                                "event_total": 3, "target_ports": ["22/tcp"]}],
            "_now_iso": lambda: "2026-10-14T00:00:00+09:00",
            "_record_check_result": lambda store, result, blocks: saved.append((result, blocks)),
            "_block_ip": lambda *args: self.fail("an API error must not change firewall rules"),
            "logger": SimpleNamespace(warning=lambda *args: None),
        })

        def unavailable(*args):
            raise urllib.error.HTTPError("https://api.typesafe.ai/v1/systemone", 422, "validation", {}, io.BytesIO(b""))

        namespace["_call_jev"] = unavailable
        # Rebind the selected function to isolated globals so this operational
        # regression cannot affect the other parser or firewall fixtures.
        import types
        check = types.FunctionType(self.logic["run_scheduled_check"].__code__, namespace)
        result = check("/unused", True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_category"], "request_format")
        self.assertEqual(saved[0][1], [])
        namespace["_call_jev"] = lambda *args: {"source-001": {
            "choice": "malicious", "confidence": 1.0,
            "probabilities": {"malicious": 1.0, "benign": 0.0, "insufficient": 0.0},
        }}
        namespace["_block_ip"] = lambda *args: {"ok": False, "error": "runtime block could not be added"}
        failed_block = check("/unused", True)
        self.assertFalse(failed_block["ok"])
        self.assertEqual(failed_block["status"], "block_failed")
        self.assertEqual(failed_block["blocked_failed_count"], 1)
        self.assertEqual(failed_block["blocked_count"], 0)

    def _firewall_fixture(self, runtime_loaded: bool = False, failure_chain: str = ""):
        """Model permanent-only ipset creation and independently tracked rules."""
        state = {"saved": set(), "runtime": set(), "rules": set(), "kernel_rules": set(),
                 "calls": [], "loaded": runtime_loaded, "kernel_available": True}

        def result(ok=True, stdout="", code=None, stderr=""):
            return SimpleNamespace(ok=ok, stdout=stdout, stderr=stderr,
                                   returncode=(0 if ok else 1) if code is None else code)

        def firewall(args):
            state["calls"].append(tuple(args))
            permanent = "--permanent" in args
            if "--list-all" in args:
                return result(stdout="drop\n target: DROP\n")
            if any(arg.startswith("--info-ipset=") for arg in args):
                return result(stdout="type: hash:ip\n options: family=inet\n") if permanent or state["loaded"] else result(False, code=136, stderr="INVALID_IPSET")
            if any(arg.startswith("--new-ipset=") for arg in args):
                self.assertTrue(permanent, "runtime ipset creation is unsupported")
                return result()
            if "--list-sources" in args:
                return result(stdout="ipset:synca-ai-defense-v4")
            if "--direct" in args:
                rule = tuple(args[2:])
                if args[1] == "--query-rule":
                    return result(rule in state["rules"])
                if args[1] == "--add-rule":
                    if rule[2] == failure_chain:
                        return result(False, code=13, stderr="COMMAND_FAILED")
                    state["rules"].add(rule)
                    if state["kernel_available"]:
                        state["kernel_rules"].add(rule)
                elif args[1] == "--remove-rule":
                    state["rules"].discard(rule)
                    state["kernel_rules"].discard(rule)
                return result()
            entries = state["saved"] if permanent else state["runtime"]
            for action in ("query", "add", "remove"):
                argument = next((arg for arg in args if arg.startswith(f"--{action}-entry=")), None)
                if argument:
                    ip = argument.split("=", 1)[1]
                    if action == "query":
                        return result(ip in entries)
                    if action == "add":
                        entries.add(ip)
                    else:
                        entries.discard(ip)
                    return result()
            self.fail("unexpected firewall operation: " + repr(args))

        def kernel(argv, **kwargs):
            state["calls"].append(tuple(argv))
            self.assertIn(argv[0], {"iptables", "ip6tables"})
            self.assertEqual(argv[1:6], ["-w", "2", "-t", "filter", "-C"])
            family = "ipv4" if argv[0] == "iptables" else "ipv6"
            rule = (family, "filter", argv[6], "-32768", *argv[7:])
            return result(rule in state["kernel_rules"])

        return state, firewall, kernel

    def test_missing_runtime_ipset_uses_verified_direct_drop_without_reload(self) -> None:
        state, firewall, kernel = self._firewall_fixture()
        with patch.dict(self.logic, {"_firewall": firewall, "run": kernel}):
            result = self.logic["_block_ip"]("8.8.4.4")
            self.assertTrue(result["ok"])
            self.assertEqual(result["runtime_method"], "direct")
            self.assertEqual(state["saved"], {"8.8.4.4"})
            self.assertEqual(len(state["rules"]), 2)
            self.assertEqual({rule[2] for rule in state["rules"]}, {"INPUT", "FORWARD"})
            self.assertTrue(all("synca-ai-defense" in rule and rule[-1] == "DROP" for rule in state["rules"]))
            self.assertEqual(state["rules"], state["kernel_rules"])
            self.assertFalse(any("--reload" in command for command in state["calls"]))
            self.assertFalse(any(any(arg.startswith("--new-ipset=") for arg in command) for command in state["calls"]))

    def test_loaded_runtime_ipset_uses_the_normal_set_path(self) -> None:
        state, firewall, kernel = self._firewall_fixture(runtime_loaded=True)
        with patch.dict(self.logic, {"_firewall": firewall, "run": kernel}):
            result = self.logic["_block_ip"]("8.8.4.4")
        self.assertTrue(result["ok"])
        self.assertEqual(result["runtime_method"], "ipset")
        self.assertEqual(state["saved"], {"8.8.4.4"})
        self.assertEqual(state["runtime"], {"8.8.4.4"})
        self.assertEqual(state["rules"], set())

    def test_failed_fallback_rolls_back_only_new_bans(self) -> None:
        state, firewall, kernel = self._firewall_fixture(failure_chain="FORWARD")
        with patch.dict(self.logic, {"_firewall": firewall, "run": kernel}):
            self.assertFalse(self.logic["_block_ip"]("8.8.4.4")["ok"])
            self.assertEqual(state["saved"], set())
            self.assertEqual(state["rules"], set())
            state["saved"].add("8.8.4.4")
            old_rule = tuple(self.logic["_direct_block_rules"]("8.8.4.4")[0])
            state["rules"].add(old_rule)
            state["kernel_rules"].add(old_rule)
            self.assertFalse(self.logic["_block_ip"]("8.8.4.4")["ok"])
            self.assertEqual(state["saved"], {"8.8.4.4"})
            self.assertEqual(state["rules"], {old_rule})

    def test_manual_unblock_cleans_both_paths_after_a_later_reload(self) -> None:
        state, firewall, kernel = self._firewall_fixture()
        config = {"blocked": [{"ip": "8.8.4.4", "runtime_method": "direct"}]}
        store = SimpleNamespace(transaction=lambda *args: nullcontext(config))
        with patch.dict(self.logic, {"_firewall": firewall, "run": kernel, "ConfigStore": lambda *args: store,
                                    "_default_state": lambda: {}, "_normalise_state": lambda value: dict(value)}):
            self.assertTrue(self.logic["_block_ip"]("8.8.4.4")["ok"])
            # FlushAllOnReload=no may retain the owned direct rules while the
            # saved set becomes loaded; manual unblock must clean both paths.
            state["loaded"] = True
            state["runtime"].update(state["saved"])
            unrelated = ("ipv4", "filter", "INPUT", "0", "-s", "8.8.4.4", "-j", "DROP")
            state["rules"].add(unrelated)
            result = self.logic["unblock_ip"]("/unused", "8.8.4.4")
        self.assertTrue(result["ok"])
        self.assertEqual(state["saved"], set())
        self.assertEqual(state["runtime"], set())
        self.assertEqual(state["rules"], {unrelated})
        self.assertEqual(config["blocked"], [])
        self.assertTrue(all(rule[0] == "ipv6" for rule in self.logic["_direct_block_rules"]("2001:4860:4860::8888")))

    def test_registered_rule_without_kernel_drop_is_a_block_failure(self) -> None:
        state, firewall, kernel = self._firewall_fixture()
        state["kernel_available"] = False
        with patch.dict(self.logic, {"_firewall": firewall, "run": kernel}):
            self.assertFalse(self.logic["_block_ip"]("8.8.4.4")["ok"])
        self.assertEqual(state["saved"], set())
        self.assertEqual(state["rules"], set())

    def test_kernel_verification_checks_iptables_chain_links_and_command_errors(self) -> None:
        rule = self.logic["_direct_block_rules"]("8.8.4.4")[0]
        calls = []

        def kernel(argv, **kwargs):
            calls.append(argv)
            present = argv[6] == "INPUT_direct" or argv[7:] == ["-j", "INPUT_direct"]
            return SimpleNamespace(ok=present, returncode=0 if present else 1)

        with patch.dict(self.logic, {"run": kernel}):
            self.assertTrue(self.logic["_direct_kernel_rule_present"](rule))
        self.assertEqual(calls[-1][-3:], ["INPUT", "-j", "INPUT_direct"])
        for returncode in (124, 127, 4):
            with patch.dict(self.logic, {"run": lambda *args, **kwargs: SimpleNamespace(ok=False, returncode=returncode)}):
                self.assertIsNone(self.logic["_direct_kernel_rule_present"](rule))

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
