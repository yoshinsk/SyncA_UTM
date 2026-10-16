#!/usr/bin/env python3
"""scripts/test-dnsmasq-upstream.py - Check managed DNS upstream isolation.

Run the production generator without Flask or Linux service dependencies.
No network access, configuration writes, or service commands are performed.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[1] / "payload/server-gui/server_gui/dnsmasq_apply.py"


def namespace() -> dict:
    """Load the actual generator while stubbing its unused runtime imports."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE), feature_version=(3, 9))
    tree.body = [
        node for node in tree.body
        if not (isinstance(node, ast.ImportFrom) and node.level)
    ]
    # Empty DHCP data never needs these dependencies. Any accidental use must
    # fail immediately rather than touch a host configuration or run a command.
    env = {"ValidationError": ValueError}
    for name in ("ConfigStore", "sudo_run", "validate_dhcp_range"):
        env[name] = Mock(side_effect=AssertionError(f"unexpected runtime call: {name}"))
    exec(compile(tree, str(SOURCE), "exec"), env)
    return env


class DnsmasqUpstreamTests(unittest.TestCase):
    """Keep explicit default DNS isolated and preserve conditional DNS fallback."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.logic = namespace()

    def setUp(self) -> None:
        self.data = self.logic["default"]()

    def render(self, upstream: list[dict]) -> list[str]:
        """Return generated directives for one managed upstream list."""
        self.data["dns"]["upstream"] = upstream
        return self.logic["generate"](self.data).splitlines()

    def test_default_upstream_is_isolated(self) -> None:
        lines = self.logic["generate"](self.data).splitlines()
        self.assertEqual(lines.count("no-resolv"), 1)
        self.assertIn("server=1.1.1.1", lines)
        self.assertIn("server=1.0.0.1", lines)

    def test_missing_upstream_uses_isolated_defaults(self) -> None:
        del self.data["dns"]["upstream"]
        lines = self.logic["generate"](self.data).splitlines()
        self.assertIn("no-resolv", lines)
        self.assertIn("server=1.1.1.1", lines)
        self.assertIn("server=1.0.0.1", lines)

    def test_none_upstream_uses_isolated_defaults(self) -> None:
        self.data["dns"]["upstream"] = None
        lines = self.logic["generate"](self.data).splitlines()
        self.assertIn("no-resolv", lines)
        self.assertIn("server=1.1.1.1", lines)

    def test_explicit_empty_list_preserves_os_fallback(self) -> None:
        lines = self.render([])
        self.assertNotIn("no-resolv", lines)
        self.assertFalse(any(line.startswith("server=") for line in lines))

    def test_domain_only_upstream_preserves_os_fallback(self) -> None:
        lines = self.render([{"domain": "internal.example", "server": "192.0.2.53"}])
        self.assertNotIn("no-resolv", lines)
        self.assertIn("server=/internal.example/192.0.2.53", lines)

    def test_blank_default_server_preserves_os_fallback(self) -> None:
        for server in ("", " ", "\t\n"):
            with self.subTest(server=repr(server)):
                lines = self.render([{"domain": "", "server": server}])
                self.assertNotIn("no-resolv", lines)
                self.assertFalse(any(line.startswith("server=") for line in lines))

    def test_whitespace_default_domain_and_server_are_normalized(self) -> None:
        lines = self.render([{"domain": " \t", "server": " 1.1.1.1 "}])
        self.assertIn("no-resolv", lines)
        self.assertIn("server=1.1.1.1", lines)

    def test_missing_domain_is_a_default_upstream(self) -> None:
        lines = self.render([{"server": "1.1.1.1"}])
        self.assertIn("no-resolv", lines)
        self.assertIn("server=1.1.1.1", lines)

    def test_global_and_domain_rules_coexist(self) -> None:
        lines = self.render([
            {"domain": "", "server": "1.1.1.1"},
            {"domain": "internal.example", "server": "192.0.2.53"},
            {"domain": "", "server": "1.0.0.1"},
        ])
        self.assertEqual(lines.count("no-resolv"), 1)
        self.assertIn("server=1.1.1.1", lines)
        self.assertIn("server=/internal.example/192.0.2.53", lines)
        self.assertIn("server=1.0.0.1", lines)

    def test_domain_rule_with_blank_default_does_not_disable_fallback(self) -> None:
        lines = self.render([
            {"domain": "", "server": " "},
            {"domain": " internal.example ", "server": " 192.0.2.53 "},
        ])
        self.assertNotIn("no-resolv", lines)
        self.assertIn("server=/internal.example/192.0.2.53", lines)


if __name__ == "__main__":
    unittest.main()
