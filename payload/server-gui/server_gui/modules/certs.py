"""Certificate discovery + metadata.

Read-only in Phase 1:
  - Scans /etc/letsencrypt/live/*/ for Let's Encrypt certs
  - Parses each cert with openssl to extract CN, SANs, dates, issuer
  - Exposes them as a list for the nginx vhost form to populate a dropdown

Phase 2 (separate Sprint) will add:
  - certbot integration (acquire / renew)
  - Custom path scanning (configurable)
  - Renewal scheduling status
"""
from __future__ import annotations

import datetime as _dt
import logging
import re
from pathlib import Path
from typing import Optional
import json

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..shell import sudo_run
from ..validators import ValidationError, validate_hostname

logger = logging.getLogger(__name__)

bp = Blueprint("certs", __name__, url_prefix="/certs")

LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")
GUI_NGINX_CONF = Path("/etc/nginx/conf.d/vhost-server-gui.conf")

# Hook scripts dropped by the SyncA UTM installer. They stop nginx + open
# port 80/443 in the firewall before certbot runs, then close+restart after.
# We pass them via --pre-hook / --post-hook for INITIAL issuance so first-
# time standalone obtains succeed end-to-end from the GUI. Renewals invoke
# them automatically because they also live under /etc/letsencrypt/
# renewal-hooks/pre/ and post/.
LE_HOOK_PRE  = Path("/etc/letsencrypt/renewal-hooks/pre/00-syncautm.sh")
LE_HOOK_POST = Path("/etc/letsencrypt/renewal-hooks/post/00-syncautm.sh")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("certs.html", active_tab="certs")


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


@bp.route("/api/issue", methods=["POST"])
@login_required
@csrf_protect
def issue_certificate():
    """Issue a Let's Encrypt cert via certbot.

    method=standalone (default): certbot binds port 80 itself. Requires that
        port 80 is reachable from the public internet (open in firewall +
        no other service on 80). nginx must NOT be holding port 80.
    method=webroot: serves the ACME challenge from /var/www/letsencrypt via
        the existing nginx vhost on port 80. Caller must have a vhost
        listening on 80 that maps /.well-known/acme-challenge to that webroot.
    """
    payload = request.get_json(force=True, silent=True) or {}
    fqdns_raw = payload.get("fqdns") or payload.get("fqdn") or ""
    if isinstance(fqdns_raw, str):
        fqdns = [s.strip() for s in fqdns_raw.replace(",", " ").split() if s.strip()]
    else:
        fqdns = [str(s).strip() for s in fqdns_raw if str(s).strip()]
    if not fqdns:
        return jsonify({"error": "fqdn(s) required"}), 400
    try:
        fqdns = [validate_hostname(f) for f in fqdns]
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    email = (payload.get("email") or "").strip()
    if not EMAIL_RE.match(email):
        return jsonify({"error": "valid email required"}), 400

    method = payload.get("method", "standalone")
    if method not in ("standalone", "webroot"):
        return jsonify({"error": "method must be 'standalone' or 'webroot'"}), 400

    cmd = [
        "certbot", "certonly",
        "--non-interactive", "--agree-tos",
        "--email", email,
    ]
    if payload.get("staging"):
        cmd.append("--staging")
    if method == "standalone":
        hook_result = _ensure_letsencrypt_hooks()
        if not hook_result.get("ok"):
            return jsonify({"error": hook_result.get("error", "failed to install Let's Encrypt hooks")}), 500
        cmd.append("--standalone")
        # Use the installer's pre/post hooks if available — they stop nginx
        # and open 80/443 in the firewall during the brief validation window.
        # Without them, standalone issuance from a fresh install fails because
        # firewalld is "default DROP" on the WAN zone.
        cmd.extend(["--pre-hook", str(LE_HOOK_PRE), "--post-hook", str(LE_HOOK_POST)])
    else:
        webroot = payload.get("webroot") or "/var/www/letsencrypt"
        cmd.extend(["--webroot", "--webroot-path", webroot])
    for f in fqdns:
        cmd.extend(["-d", f])

    res = sudo_run(cmd, timeout=180)
    applied = None
    if res.ok and bool(payload.get("apply_to_gui", True)):
        applied = _apply_gui_certificate(fqdns[0])
    return jsonify({
        "ok": res.ok,
        "command": " ".join(cmd),
        "stdout": res.stdout,
        "stderr": res.stderr,
        "applied_to_gui": applied,
    })


@bp.route("/api/renew", methods=["POST"])
@login_required
@csrf_protect
def renew_certificate():
    """Renew an existing cert (or all). Body: {name?: str, dry_run?: bool, force?: bool}"""
    payload = request.get_json(force=True, silent=True) or {}
    name = payload.get("name")
    dry_run = bool(payload.get("dry_run", False))
    force = bool(payload.get("force", False))

    hook_result = _ensure_letsencrypt_hooks()
    if not hook_result.get("ok"):
        return jsonify({"error": hook_result.get("error", "failed to install Let's Encrypt hooks")}), 500

    cmd = ["certbot", "renew", "--non-interactive"]
    if dry_run:
        cmd.append("--dry-run")
    if force:
        cmd.append("--force-renewal")
    if name:
        # Validate certificate name: same charset as filenames Let's Encrypt creates
        if not re.match(r"^[A-Za-z0-9._\-]{1,253}$", name):
            return jsonify({"error": "invalid certificate name"}), 400
        cmd.extend(["--cert-name", name])
    res = sudo_run(cmd, timeout=180)
    return jsonify({
        "ok": res.ok,
        "command": " ".join(cmd),
        "stdout": res.stdout,
        "stderr": res.stderr,
    })


@bp.route("/api/certificates", methods=["GET"])
@login_required
def list_certificates():
    """Discover and parse available certificates."""
    certs: list[dict] = []
    if LETSENCRYPT_LIVE.exists():
        # Skip the symlink-traversal "README" file inside live/
        for d in sorted(LETSENCRYPT_LIVE.iterdir()):
            if not d.is_dir():
                continue
            fullchain = d / "fullchain.pem"
            privkey = d / "privkey.pem"
            if not (fullchain.exists() and privkey.exists()):
                continue
            info = _parse_cert(fullchain)
            entry = {
                "source": "letsencrypt",
                "name": d.name,
                "cert_path": str(fullchain),
                "key_path": str(privkey),
                "subject": None,
                "issuer": None,
                "not_before": None,
                "not_after": None,
                "sans": [],
                "days_remaining": None,
            }
            if info:
                entry.update(info)
            certs.append(entry)
    return jsonify({"certificates": certs})


def _ensure_letsencrypt_hooks() -> dict:
    """Install certbot hooks that temporarily release nginx port 80."""
    script = r'''
from pathlib import Path

pre = Path("/etc/letsencrypt/renewal-hooks/pre/00-syncautm.sh")
post = Path("/etc/letsencrypt/renewal-hooks/post/00-syncautm.sh")
pre.parent.mkdir(parents=True, exist_ok=True)
post.parent.mkdir(parents=True, exist_ok=True)
pre.write_text("""#!/usr/bin/env bash
set -euo pipefail
if systemctl is-active --quiet firewalld; then
    firewall-cmd --zone=public --add-service=http || true
    firewall-cmd --zone=public --add-service=https || true
fi
systemctl stop nginx.service || true
""", encoding="utf-8")
post.write_text("""#!/usr/bin/env bash
set -euo pipefail
systemctl start nginx.service || true
if systemctl is-active --quiet firewalld; then
    firewall-cmd --zone=public --remove-service=http || true
    firewall-cmd --zone=public --remove-service=https || true
fi
""", encoding="utf-8")
pre.chmod(0o755)
post.chmod(0o755)
'''
    res = sudo_run(["python3", "-c", script])
    if not res.ok:
        return {"ok": False, "error": res.stderr or res.stdout}
    return {"ok": True}


@bp.route("/api/apply-gui", methods=["POST"])
@login_required
@csrf_protect
def apply_gui_certificate():
    """Use an existing Let's Encrypt certificate for the SyncA UTM GUI vhost."""
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or payload.get("fqdn") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    try:
        name = validate_hostname(name)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    result = _apply_gui_certificate(name)
    return jsonify(result), 200 if result.get("ok") else 500


# ---- parsing -----------------------------------------------------------

def _parse_cert(path: Path) -> Optional[dict]:
    """Run openssl to extract human-readable cert info."""
    res = sudo_run([
        "openssl", "x509", "-in", str(path), "-noout",
        "-subject", "-issuer", "-startdate", "-enddate",
    ])
    if not res.ok:
        logger.warning("openssl failed for %s: %s", path, res.stderr.strip())
        return None

    info: dict = {
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "sans": [],
        "days_remaining": None,
    }
    for line in res.stdout.splitlines():
        if line.startswith("subject="):
            info["subject"] = _extract_cn(line.split("=", 1)[1])
        elif line.startswith("issuer="):
            info["issuer"] = _extract_cn(line.split("=", 1)[1])
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[1].strip()

    san_res = sudo_run([
        "openssl", "x509", "-in", str(path), "-noout", "-ext", "subjectAltName",
    ])
    if san_res.ok:
        info["sans"] = _extract_sans(san_res.stdout)

    if info["not_after"]:
        days = _days_until(info["not_after"])
        if days is not None:
            info["days_remaining"] = days

    return info


def _apply_gui_certificate(name: str) -> dict:
    """Point the GUI nginx vhost at /etc/letsencrypt/live/<name>/ cert files."""
    live_dir = LETSENCRYPT_LIVE / name
    cert = live_dir / "fullchain.pem"
    key = live_dir / "privkey.pem"
    if not cert.exists() or not key.exists():
        return {"ok": False, "error": f"certificate files not found for {name}"}
    script = r'''
import json
import re
import sys
from pathlib import Path

payload = json.load(sys.stdin)
conf = Path(payload["conf"])
cert = payload["cert"]
key = payload["key"]
if not conf.exists():
    raise SystemExit(f"{conf} does not exist")
text = conf.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"^\s*ssl_certificate\s+[^;]+;", f"    ssl_certificate {cert};", text, flags=re.M)
text = re.sub(r"^\s*ssl_certificate_key\s+[^;]+;", f"    ssl_certificate_key {key};", text, flags=re.M)
conf.write_text(text, encoding="utf-8")
'''
    res = sudo_run(
        ["python3", "-c", script],
        stdin=json.dumps({"conf": str(GUI_NGINX_CONF), "cert": str(cert), "key": str(key)}),
    )
    if not res.ok:
        return {"ok": False, "error": res.stderr or res.stdout}
    test = sudo_run(["nginx", "-t"])
    if not test.ok:
        return {"ok": False, "error": test.stderr or test.stdout}
    reload_res = sudo_run(["systemctl", "reload", "nginx"])
    return {
        "ok": reload_res.ok,
        "cert_path": str(cert),
        "key_path": str(key),
        "output": (test.stdout + test.stderr + reload_res.stdout + reload_res.stderr).strip(),
    }


def _extract_cn(rdn_string: str) -> str:
    """Extract the CN= value from an openssl RDN string.

    Handles both `C=US, O=Foo, CN=example.com` and `CN = example.com` styles.
    """
    parts = [p.strip() for p in rdn_string.split(",")]
    for p in parts:
        if "=" not in p:
            continue
        key, val = p.split("=", 1)
        if key.strip() == "CN":
            return val.strip()
    return rdn_string.strip()


def _extract_sans(text: str) -> list[str]:
    """Pull DNS:names out of openssl -ext subjectAltName output."""
    names: list[str] = []
    for line in text.splitlines():
        for tok in line.split(","):
            tok = tok.strip()
            if tok.startswith("DNS:"):
                names.append(tok[4:].strip())
    return names


_OPENSSL_DATE_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT$"
)
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _days_until(date_str: str) -> Optional[int]:
    """Parse an openssl date like 'Aug 12 14:30:00 2026 GMT' → days from now (UTC)."""
    m = _OPENSSL_DATE_RE.match(date_str.strip())
    if not m:
        return None
    month, day, hh, mm, ss, year = m.groups()
    month_num = _MONTHS.get(month)
    if month_num is None:
        return None
    try:
        dt = _dt.datetime(int(year), month_num, int(day), int(hh), int(mm), int(ss), tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    now = _dt.datetime.now(_dt.timezone.utc)
    return (dt - now).days
