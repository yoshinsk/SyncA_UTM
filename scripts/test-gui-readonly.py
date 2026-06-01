#!/usr/bin/env python3
"""scripts/test-gui-readonly.py - Run read-only SyncA UTM GUI smoke tests."""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


BASE_URL = os.environ.get("SYNCA_GUI_URL", "https://127.0.0.1:4444").rstrip("/")
USERNAME = os.environ.get("SYNCA_GUI_USER", "admin")
PASSWORD = os.environ.get("SYNCA_GUI_PASS", "")

PAGES = [
    "/system/",
    "/network/",
    "/ddns/",
    "/firewall/",
    "/fail2ban/",
    "/geoip/",
    "/dns/",
    "/dhcp/",
    "/ipsec/",
    "/wg/",
    "/nginx/",
    "/certs/",
    "/backup/",
    "/admin/",
    "/sophos-import/",
]

API_GETS = [
    "/system/api/status",
    "/network/api/devices",
    "/network/api/wan",
    "/network/api/pppoe/mss-clamp/status",
    "/ddns/api/presets",
    "/ddns/api/state",
    "/firewall/api/zones",
    "/firewall/api/services-available",
    "/firewall/api/ipsets",
    "/firewall/api/direct-rules",
    "/fail2ban/api/status",
    "/fail2ban/api/jail-local",
    "/fail2ban/api/jails",
    "/geoip/api/countries",
    "/geoip/api/ipsets/discover",
    "/dns/api/records",
    "/dhcp/api/config",
    "/dhcp/api/existing",
    "/dhcp/api/leases",
    "/ipsec/api/status",
    "/ipsec/api/connections",
    "/ipsec/api/sas",
    "/ipsec/api/files",
    "/ipsec/api/managed",
    "/wg/api/interfaces",
    "/nginx/api/backends",
    "/nginx/api/vhosts",
    "/nginx/api/test",
    "/nginx/api/waf-status",
    "/certs/api/certificates",
    "/backup/api/list",
    "/admin/api/settings",
    "/sophos-import/api/plans",
]


def build_opener() -> urllib.request.OpenerDirector:
    """Create an opener with cookies and relaxed TLS for appliance testing."""
    context = ssl._create_unverified_context()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()),
        urllib.request.HTTPSHandler(context=context),
    )


def request(
    opener: urllib.request.OpenerDirector,
    path: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes]:
    """Run one HTTP request and return status, content type, and body."""
    url = BASE_URL + path
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=30) as res:
            return res.status, res.headers.get("Content-Type", ""), res.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def main() -> int:
    """Authenticate and verify all read-only pages and API endpoints."""
    if not PASSWORD:
        print("SYNCA_GUI_PASS is required", file=sys.stderr)
        return 2

    opener = build_opener()
    login_body = urllib.parse.urlencode({"username": USERNAME, "password": PASSWORD}).encode()
    status, _ctype, body = request(
        opener,
        "/login",
        data=login_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status not in (200, 302):
        print(json.dumps({"kind": "login", "status": status, "body": body[:200].decode("utf-8", "replace")}, ensure_ascii=False))
        return 1

    failures: list[dict[str, object]] = []
    results: list[dict[str, object]] = []

    for path in PAGES:
        status, ctype, body = request(opener, path)
        ok = status == 200 and b"<html" in body[:1000].lower()
        results.append({"kind": "page", "path": path, "status": status, "bytes": len(body), "ok": ok})
        if not ok:
            failures.append(results[-1])

    for path in API_GETS:
        status, ctype, body = request(opener, path)
        json_ok = False
        if "json" in ctype.lower():
            try:
                json.loads(body.decode("utf-8"))
                json_ok = True
            except json.JSONDecodeError:
                json_ok = False
        ok = status == 200 and json_ok
        results.append({"kind": "api", "path": path, "status": status, "content_type": ctype, "bytes": len(body), "ok": ok})
        if not ok:
            failures.append(results[-1])

    print(json.dumps({"base_url": BASE_URL, "ok": not failures, "results": results, "failures": failures}, ensure_ascii=False, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
