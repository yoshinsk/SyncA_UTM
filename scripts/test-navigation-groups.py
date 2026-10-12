#!/usr/bin/env python3
"""scripts/test-navigation-groups.py - Verify grouped SyncA UTM navigation.

Renders the shared base template in an isolated Flask application. The test
checks that the desktop sidebar and hamburger menu share the requested group
and link order without invoking appliance services or touching configuration.
"""
from __future__ import annotations

import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

from flask import Blueprint, Flask, render_template_string, session


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "payload" / "server-gui" / "server_gui" / "templates"
STATIC_DIR = ROOT / "payload" / "server-gui" / "server_gui" / "static"

# The expected order mirrors the operator-facing navigation specification.
# Keep labels and paths together so a renamed or moved item fails the test.
EXPECTED_GROUPS = [
    ("TOP", [("ダッシュボード", "/test/dashboard")]),
    ("Network", [
        ("ネットワーク", "/test/network"),
        ("DHCP", "/test/dhcp"),
        ("DNS", "/test/dns"),
        ("IPv6", "/test/ipv6"),
        ("UPnP", "/test/upnp"),
    ]),
    ("Check", [("WAN品質", "/test/wan-quality")]),
    ("Defense", [
        ("国別IP", "/test/geoip"),
        ("Firewall", "/test/firewall"),
        ("fail2ban", "/test/fail2ban"),
        ("AI防御", "/test/ai-defense"),
    ]),
    ("VPN", [("IPsec", "/test/ipsec"), ("WireGuard", "/test/wireguard")]),
    ("Publish", [
        ("DDNS", "/test/ddns"),
        ("Nginx", "/test/nginx"),
        ("証明書", "/test/certs"),
    ]),
    ("Manage", [
        ("管理", "/test/admin"),
        ("バックアップ", "/test/backup"),
        ("Sophos取込", "/test/sophos-import"),
    ]),
]

ENDPOINTS = [
    ("system", "dashboard", "dashboard"),
    ("network", "page", "network"),
    ("wan_quality", "page", "wan-quality"),
    ("ddns", "page", "ddns"),
    ("firewall", "page", "firewall"),
    ("fail2ban", "page", "fail2ban"),
    ("ai_defense", "page", "ai-defense"),
    ("geoip", "page", "geoip"),
    ("dns", "page", "dns"),
    ("dhcp", "page", "dhcp"),
    ("ipv6", "page", "ipv6"),
    ("upnp", "page", "upnp"),
    ("ipsec", "page", "ipsec"),
    ("wireguard", "page", "wireguard"),
    ("nginx_proxy", "page", "nginx"),
    ("certs", "page", "certs"),
    ("backup", "page", "backup"),
    ("sophos_import", "page", "sophos-import"),
    ("admin", "page", "admin"),
]


class NavigationParser(HTMLParser):
    """Extract one rendered navigation list without relying on external parsers."""

    def __init__(self, navigation_label: str) -> None:
        super().__init__(convert_charrefs=True)
        self.navigation_label = navigation_label
        self.navigation_depth = 0
        self.groups: list[dict[str, object]] = []
        self.current_group: dict[str, object] | None = None
        self.reading_group_title = False
        self.current_link: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "nav" and attributes.get("aria-label") == self.navigation_label:
            self.navigation_depth = 1
            return
        if not self.navigation_depth:
            return
        if tag == "nav":
            self.navigation_depth += 1
            return

        classes = set((attributes.get("class") or "").split())
        if tag == "div" and "app-nav-group" in classes:
            self.current_group = {"label": "", "links": []}
            self.groups.append(self.current_group)
        elif tag == "div" and "app-nav-group-title" in classes:
            self.reading_group_title = True
        elif tag == "a" and "app-nav-link" in classes:
            # The group remains active until the next app-nav-group begins,
            # which follows the template's one-group-at-a-time structure.
            self.current_link = {"label": "", "href": attributes.get("href") or ""}

    def handle_endtag(self, tag: str) -> None:
        if not self.navigation_depth:
            return
        if tag == "a" and self.current_link is not None and self.current_group is not None:
            links = self.current_group["links"]
            assert isinstance(links, list)
            links.append((" ".join(self.current_link["label"].split()), self.current_link["href"]))
            self.current_link = None
        elif tag == "div" and self.reading_group_title:
            self.reading_group_title = False
        elif tag == "nav":
            self.navigation_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.navigation_depth:
            return
        if self.reading_group_title and self.current_group is not None:
            self.current_group["label"] = str(self.current_group["label"]) + data
        if self.current_link is not None:
            self.current_link["label"] += data

    def result(self) -> list[tuple[str, list[tuple[str, str]]]]:
        """Return normalized labels and links in their rendered order."""
        parsed: list[tuple[str, list[tuple[str, str]]]] = []
        for group in self.groups:
            label = " ".join(str(group["label"]).split())
            links = group["links"]
            assert isinstance(links, list)
            parsed.append((label, links))
        return parsed


def build_test_app() -> Flask:
    """Create only the endpoints required to render the shared base template."""
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR), static_folder=str(STATIC_DIR))
    app.config.update(SECRET_KEY="navigation-test-secret", TESTING=True)

    for blueprint_name, endpoint_name, path_segment in ENDPOINTS:
        blueprint = Blueprint(blueprint_name, __name__)
        # Every navigation link receives a distinct stable route. The view is
        # intentionally inert because this test validates template structure.
        blueprint.add_url_rule(f"/test/{path_segment}", endpoint=endpoint_name, view_func=lambda: "ok")
        app.register_blueprint(blueprint)

    auth = Blueprint("auth", __name__)
    auth.add_url_rule("/test/logout", endpoint="logout", view_func=lambda: "ok", methods=["POST"])
    app.register_blueprint(auth)
    return app


class NavigationGroupsTest(unittest.TestCase):
    """Confirm that desktop and mobile menus retain identical grouping."""

    def test_desktop_and_mobile_navigation_match_specification(self) -> None:
        app = build_test_app()
        with app.test_request_context("/test/render"):
            session["user"] = "navigation-test"
            session["csrf_token"] = "navigation-test-token"
            document = render_template_string(
                '{% extends "base.html" %}{% block content %}<p>test</p>{% endblock %}',
                active_tab="ai_defense",
            )

        # Macro definitions must not add bytes before the doctype, which could
        # otherwise put browsers into an unexpected document rendering mode.
        self.assertTrue(document.startswith("<!DOCTYPE html>"))

        for navigation_label in ("main navigation", "mobile navigation"):
            parser = NavigationParser(navigation_label)
            parser.feed(document)
            parser.close()
            self.assertEqual(parser.result(), EXPECTED_GROUPS, navigation_label)

        # The current page is announced once in each navigation surface.
        self.assertEqual(document.count('aria-current="page"'), 2)


if __name__ == "__main__":
    unittest.main()
