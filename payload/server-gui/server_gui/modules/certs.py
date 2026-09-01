"""payload/server-gui/server_gui/modules/certs.py - Manage TLS certificates.

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
import os
import re
from pathlib import Path
from typing import Optional
import json

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..shell import sudo_run
from ..validators import ValidationError, validate_hostname, validate_ipv4

logger = logging.getLogger(__name__)

bp = Blueprint("certs", __name__, url_prefix="/certs")

LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")
GUI_NGINX_CONF = Path("/etc/nginx/conf.d/vhost-server-gui.conf")
ACME_NGINX_CONF = Path("/etc/nginx/conf.d/00-synca-acme.conf")
ACME_WEBROOT = Path("/var/www/letsencrypt")
CENTRAL_CONFIG = Path("/etc/server-gui/central.json")

# Hook scripts dropped by the SyncA UTM installer. They temporarily open
# HTTP in firewalld for ACME HTTP-01, reload nginx after successful renewal,
# and stay quiet so certbot does not fail when a GUI request times out.
LE_HOOK_PRE  = Path("/etc/letsencrypt/renewal-hooks/pre/00-syncautm.sh")
LE_HOOK_POST = Path("/etc/letsencrypt/renewal-hooks/post/00-syncautm.sh")
LE_HOOK_DEPLOY = Path("/etc/letsencrypt/renewal-hooks/deploy/00-syncautm-reload-nginx.sh")
CERTBOT_RUNTIME_HELPER = Path("/opt/server-gui/bin/synca-certbot-runtime")


def register(app: Flask) -> None:
    app.register_blueprint(bp)
    try:
        _ensure_certbot_runtime()
    except Exception as exc:
        logger.warning("certbot runtime provisioning failed: %s", exc)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("certs.html", active_tab="certs")


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
CERT_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")


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

    method = payload.get("method", "webroot")
    if method not in ("standalone", "webroot"):
        return jsonify({"error": "method must be 'standalone' or 'webroot'"}), 400
    requested_method = method
    method_warning = None
    if method == "standalone":
        method = "webroot"
        method_warning = (
            "standalone は nginx を一時停止するため GUI 通信が切断されます。"
            "GUI からの取得では webroot を使用しました。"
        )

    cmd = [
        "certbot", "certonly",
        "--non-interactive", "--agree-tos",
        "--email", email,
    ]
    if payload.get("staging"):
        cmd.append("--staging")
    try:
        listen_ip = _optional_listen_ip(payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

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
        acme_result = _ensure_acme_http_vhost(fqdns, listen_ip)
        if not acme_result.get("ok"):
            return jsonify({"error": acme_result.get("error", "failed to prepare ACME HTTP vhost")}), 500
        hook_result = _ensure_letsencrypt_hooks()
        if not hook_result.get("ok"):
            return jsonify({"error": hook_result.get("error", "failed to install Let's Encrypt hooks")}), 500
        webroot = payload.get("webroot") or str(ACME_WEBROOT)
        cmd.extend(["--webroot", "--webroot-path", webroot])
    for f in fqdns:
        cmd.extend(["-d", f])

    firewall_state = _open_http_for_acme(listen_ip)
    try:
        res = sudo_run(cmd, timeout=180)
    finally:
        _close_http_for_acme(firewall_state)
        if method == "webroot":
            _ensure_acme_http_vhost()
    applied = None
    if res.ok and bool(payload.get("apply_to_gui", False)):
        applied = _apply_gui_certificate(fqdns[0])
    return jsonify({
        "ok": res.ok,
        "requested_method": requested_method,
        "effective_method": method,
        "listen_ip": listen_ip,
        "warning": method_warning,
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
    acme_result = _ensure_acme_http_vhost()
    if not acme_result.get("ok"):
        return jsonify({"error": acme_result.get("error", "failed to prepare ACME HTTP vhost")}), 500

    cmd = ["certbot", "renew", "--non-interactive", "--no-random-sleep-on-renew"]
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


@bp.route("/api/reissue-production", methods=["POST"])
@login_required
@csrf_protect
def reissue_production_certificate():
    """Replace an existing staging certificate with a production certificate."""
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not CERT_NAME_RE.match(name):
        return jsonify({"error": "invalid certificate name"}), 400
    email = (payload.get("email") or "").strip()
    if not EMAIL_RE.match(email):
        return jsonify({"error": "valid email required"}), 400

    fqdns = _certificate_domains(name)
    if not fqdns:
        return jsonify({"error": "certificate domains could not be determined"}), 400

    method = payload.get("method", "webroot")
    if method not in ("standalone", "webroot"):
        return jsonify({"error": "method must be 'standalone' or 'webroot'"}), 400
    requested_method = method
    method_warning = None
    if method == "standalone":
        method = "webroot"
        method_warning = (
            "standalone は nginx を一時停止するため GUI 通信が切断されます。"
            "GUI からの本番再取得では webroot を使用しました。"
        )

    cmd = [
        "certbot", "certonly",
        "--non-interactive", "--agree-tos",
        "--force-renewal", "--cert-name", name,
        "--email", email,
    ]
    try:
        listen_ip = _optional_listen_ip(payload)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    if method == "webroot":
        acme_result = _ensure_acme_http_vhost(fqdns, listen_ip)
        if not acme_result.get("ok"):
            return jsonify({"error": acme_result.get("error", "failed to prepare ACME HTTP vhost")}), 500
        hook_result = _ensure_letsencrypt_hooks()
        if not hook_result.get("ok"):
            return jsonify({"error": hook_result.get("error", "failed to install Let's Encrypt hooks")}), 500
        webroot = payload.get("webroot") or str(ACME_WEBROOT)
        cmd.extend(["--webroot", "--webroot-path", webroot])
    else:
        hook_result = _ensure_letsencrypt_hooks()
        if not hook_result.get("ok"):
            return jsonify({"error": hook_result.get("error", "failed to install Let's Encrypt hooks")}), 500
        cmd.extend(["--standalone", "--pre-hook", str(LE_HOOK_PRE), "--post-hook", str(LE_HOOK_POST)])
    for fqdn in fqdns:
        cmd.extend(["-d", fqdn])

    firewall_state = _open_http_for_acme(listen_ip)
    try:
        res = sudo_run(cmd, timeout=180)
    finally:
        _close_http_for_acme(firewall_state)
        if method == "webroot":
            _ensure_acme_http_vhost()
    applied = None
    if res.ok and bool(payload.get("apply_to_gui", False)):
        applied = _apply_gui_certificate(name)
    return jsonify({
        "ok": res.ok,
        "requested_method": requested_method,
        "effective_method": method,
        "listen_ip": listen_ip,
        "warning": method_warning,
        "command": " ".join(cmd),
        "stdout": res.stdout,
        "stderr": res.stderr,
        "applied_to_gui": applied,
    })


@bp.route("/api/delete", methods=["POST"])
@login_required
@csrf_protect
def delete_certificate():
    """Delete an existing certbot certificate by name."""
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not CERT_NAME_RE.match(name):
        return jsonify({"error": "invalid certificate name"}), 400
    res = sudo_run(["certbot", "delete", "--cert-name", name, "--non-interactive"], timeout=60)
    return jsonify({
        "ok": res.ok,
        "command": f"certbot delete --cert-name {name} --non-interactive",
        "stdout": res.stdout,
        "stderr": res.stderr,
    })


@bp.route("/api/certificates", methods=["GET"])
@login_required
def list_certificates():
    """Discover and parse available certificates."""
    certs: list[dict] = []
    gui_cert = _current_gui_certificate()
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
                "used_by_gui": False,
            }
            if info:
                entry.update(info)
            entry["is_staging"] = _is_staging_issuer(entry.get("issuer") or "")
            entry["used_by_gui"] = (
                bool(gui_cert)
                and gui_cert.get("cert_path") == entry["cert_path"]
                and gui_cert.get("key_path") == entry["key_path"]
            )
            certs.append(entry)
    return jsonify({"certificates": certs, "gui_certificate": gui_cert})


def _optional_listen_ip(payload: dict) -> str:
    """Return the optional public IPv4 address used for HTTP-01 validation."""
    raw = payload.get("listen_ip") or payload.get("bind_ip") or payload.get("ip_address") or ""
    listen_ip = str(raw).strip()
    if not listen_ip:
        return ""
    return validate_ipv4(listen_ip)


def _ensure_letsencrypt_hooks() -> dict:
    """Install certbot hooks that temporarily open HTTP for ACME renewal."""
    script = r'''
from pathlib import Path

pre = Path("/etc/letsencrypt/renewal-hooks/pre/00-syncautm.sh")
post = Path("/etc/letsencrypt/renewal-hooks/post/00-syncautm.sh")
deploy = Path("/etc/letsencrypt/renewal-hooks/deploy/00-syncautm-reload-nginx.sh")
pre.parent.mkdir(parents=True, exist_ok=True)
post.parent.mkdir(parents=True, exist_ok=True)
deploy.parent.mkdir(parents=True, exist_ok=True)
pre.write_text("""#!/usr/bin/env bash
set -euo pipefail
STATE_DIR=/run/synca-acme
install -d -m 0755 "$STATE_DIR"
rm -f "$STATE_DIR/http-was-open" "$STATE_DIR/ppp80-was-open" "$STATE_DIR/ip80-added"
: > "$STATE_DIR/ip80-added"
if systemctl is-active --quiet firewalld; then
    if firewall-cmd --zone=public --query-service=http >/dev/null 2>&1; then
        touch "$STATE_DIR/http-was-open"
    else
        firewall-cmd --zone=public --add-service=http >/dev/null 2>&1 || true
    fi
    ppp_rule='ipv4 filter INPUT 0 -i ppp+ -p tcp --dport 80 -j ACCEPT'
    if firewall-cmd --direct --get-all-rules 2>/dev/null | grep -Fxq "$ppp_rule"; then
        touch "$STATE_DIR/ppp80-was-open"
    else
        firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -i ppp+ -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
    fi
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        rule="ipv4 filter INPUT 0 -d ${ip} -p tcp --dport 80 -j ACCEPT"
        if ! firewall-cmd --direct --get-all-rules 2>/dev/null | grep -Fxq "$rule"; then
            firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -d "$ip" -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
            echo "$ip" >> "$STATE_DIR/ip80-added"
        fi
    done < <(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1)
fi
""", encoding="utf-8")
post.write_text("""#!/usr/bin/env bash
set -euo pipefail
STATE_DIR=/run/synca-acme
if systemctl is-active --quiet firewalld; then
    if [[ -f "$STATE_DIR/ip80-added" ]]; then
        while read -r ip; do
            [[ -z "$ip" ]] && continue
            firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -d "$ip" -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
        done < "$STATE_DIR/ip80-added"
    fi
    if [[ ! -f "$STATE_DIR/ppp80-was-open" ]]; then
        firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -i ppp+ -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
    fi
    if [[ ! -f "$STATE_DIR/http-was-open" ]]; then
        firewall-cmd --zone=public --remove-service=http >/dev/null 2>&1 || true
    fi
fi
rm -f "$STATE_DIR/http-was-open" "$STATE_DIR/ppp80-was-open" "$STATE_DIR/ip80-added"
""", encoding="utf-8")
deploy.write_text("""#!/usr/bin/env bash
set -euo pipefail
if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx; then
    nginx -t >/dev/null 2>&1 && systemctl reload-or-restart nginx >/dev/null 2>&1 || true
fi
if systemctl list-unit-files synca-central-report.service >/dev/null 2>&1; then
    systemctl start synca-central-report.service >/dev/null 2>&1 || true
fi
""", encoding="utf-8")
pre.chmod(0o755)
post.chmod(0o755)
deploy.chmod(0o755)
'''
    res = sudo_run(["python3", "-c", script])
    if not res.ok:
        return {"ok": False, "error": res.stderr or res.stdout}
    return {"ok": True}


def _ensure_certbot_runtime() -> None:
    """Provision renewal hooks and timer wiring for updated hosts."""
    if _schedule_certbot_runtime_helper():
        return

    hook_result = _ensure_letsencrypt_hooks()
    if not hook_result.get("ok"):
        logger.warning("Let's Encrypt hook provisioning failed: %s", hook_result.get("error"))
    timer_result = _enable_certbot_timer()
    if not timer_result.get("ok"):
        logger.warning("certbot renewal timer provisioning failed: %s", timer_result.get("error"))
    _enable_time_sync_if_available()


def _schedule_certbot_runtime_helper() -> bool:
    """Run the full runtime repair helper outside the GUI request lifecycle."""
    if not CERTBOT_RUNTIME_HELPER.exists():
        return False
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    unit = f"synca-certbot-runtime-{ts}-{os.getpid()}"
    res = sudo_run([
        "systemd-run",
        f"--unit={unit}",
        "--no-block",
        "--",
        str(CERTBOT_RUNTIME_HELPER),
    ], timeout=10)
    if res.ok:
        return True
    logger.warning("certbot runtime helper scheduling failed: %s", res.stderr or res.stdout)
    return False


def _enable_certbot_timer() -> dict:
    """Enable the distro-specific certbot renewal timer when it exists."""
    script = r'''
set -euo pipefail
for timer in certbot-renew.timer certbot.timer snap.certbot.renew.timer; do
    if systemctl list-unit-files --no-legend "$timer" 2>/dev/null | awk '{print $1}' | grep -Fxq "$timer"; then
        systemctl enable "$timer" >/dev/null 2>&1 || exit 1
        systemctl start --no-block "$timer" >/dev/null 2>&1 || exit 1
        exit 0
    fi
done
exit 2
'''
    res = sudo_run(["bash", "-lc", script], timeout=30)
    if res.ok:
        return {"ok": True}
    if res.returncode == 2:
        return {"ok": False, "error": "certbot renewal timer unit not found"}
    return {"ok": False, "error": res.stderr or res.stdout}


def _enable_time_sync_if_available() -> None:
    """Enable installed time-sync services without installing packages."""
    script = r'''
set -euo pipefail
if systemctl list-unit-files --no-legend chronyd.service 2>/dev/null | awk '{print $1}' | grep -Fxq chronyd.service; then
    systemctl enable --now chronyd >/dev/null 2>&1 || true
    timedatectl set-ntp true >/dev/null 2>&1 || true
elif systemctl list-unit-files --no-legend systemd-timesyncd.service 2>/dev/null | awk '{print $1}' | grep -Fxq systemd-timesyncd.service; then
    systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    timedatectl set-ntp true >/dev/null 2>&1 || true
fi
'''
    sudo_run(["bash", "-lc", script], timeout=30)


def _ensure_acme_http_vhost(domains: list[str] | None = None, listen_ip: str = "") -> dict:
    """Prepare a port 80 nginx vhost that serves only ACME HTTP-01 files."""
    script = r'''
import json
import sys
from pathlib import Path

payload = json.load(sys.stdin)
domains = payload.get("domains") or []
webroot = Path("/var/www/letsencrypt/.well-known/acme-challenge")
conf = Path("/etc/nginx/conf.d/00-synca-acme.conf")
webroot.mkdir(parents=True, exist_ok=True)
server_name = " ".join(domains) if domains else "synca-acme.invalid"
conf.write_text(f"""# Managed by SyncA UTM. Serves Let's Encrypt HTTP-01 challenges only.
server {{
    listen 80;
    listen [::]:80;
    server_name {server_name};
    location ^~ /.well-known/acme-challenge/ {{
        root /var/www/letsencrypt;
        default_type "text/plain";
        try_files $uri =404;
    }}
    location / {{
        return 404;
    }}
}}
""", encoding="utf-8")
'''
    write_res = sudo_run(
        ["python3", "-c", script],
        stdin=json.dumps({"domains": domains or [], "listen_ip": listen_ip}),
    )
    if not write_res.ok:
        return {"ok": False, "error": write_res.stderr or write_res.stdout}
    test = sudo_run(["nginx", "-t"])
    if not test.ok:
        return {"ok": False, "error": test.stderr or test.stdout}
    reload_res = sudo_run(["systemctl", "reload-or-restart", "nginx"])
    if not reload_res.ok:
        return {"ok": False, "error": reload_res.stderr or reload_res.stdout}
    return {"ok": True}


def _global_ipv4_addresses() -> list[str]:
    """Return global IPv4 addresses currently configured on the appliance."""
    res = sudo_run(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=10)
    if not res.ok:
        return []
    ips: list[str] = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        ip = parts[3].split("/", 1)[0]
        try:
            validate_ipv4(ip)
        except ValidationError:
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def _open_http_for_acme(listen_ip: str = "") -> dict:
    """Open HTTP on firewalld only for the ACME transaction window."""
    state = {"http_was_open": False, "ppp80_was_open": False, "ip_rules": []}
    http_state = sudo_run(["firewall-cmd", "--zone=public", "--query-service=http"])
    state["http_was_open"] = http_state.ok and http_state.stdout.strip() == "yes"
    direct_rules = sudo_run(["firewall-cmd", "--direct", "--get-all-rules"])
    direct_lines = direct_rules.stdout.splitlines() if direct_rules.ok else []
    state["ppp80_was_open"] = (
        direct_rules.ok
        and "ipv4 filter INPUT 0 -i ppp+ -p tcp --dport 80 -j ACCEPT" in direct_lines
    )
    if not state["http_was_open"]:
        sudo_run(["firewall-cmd", "--zone=public", "--add-service=http"])
    if not state["ppp80_was_open"]:
        sudo_run([
            "firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "0",
            "-i", "ppp+", "-p", "tcp", "--dport", "80", "-j", "ACCEPT",
        ])
    target_ips = [listen_ip] if listen_ip else _global_ipv4_addresses()
    for ip in target_ips:
        rule_line = f"ipv4 filter INPUT 0 -d {ip} -p tcp --dport 80 -j ACCEPT"
        was_open = direct_rules.ok and rule_line in direct_lines
        state["ip_rules"].append({"ip": ip, "was_open": was_open})
        if not was_open:
            sudo_run([
                "firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "0",
                "-d", ip, "-p", "tcp", "--dport", "80", "-j", "ACCEPT",
            ])
    return state


def _close_http_for_acme(state: dict) -> None:
    """Close the temporary HTTP firewalld rules after certbot returns."""
    for entry in state.get("ip_rules") or []:
        if entry.get("was_open"):
            continue
        ip = entry.get("ip")
        if not ip:
            continue
        sudo_run([
            "firewall-cmd", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "0",
            "-d", ip, "-p", "tcp", "--dport", "80", "-j", "ACCEPT",
        ])
    if not state.get("ppp80_was_open"):
        sudo_run([
            "firewall-cmd", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "0",
            "-i", "ppp+", "-p", "tcp", "--dport", "80", "-j", "ACCEPT",
        ])
    if not state.get("http_was_open"):
        sudo_run(["firewall-cmd", "--zone=public", "--remove-service=http"])


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

def _certificate_domains(name: str) -> list[str]:
    """Return validated DNS names currently present on an existing cert."""
    live_dir = LETSENCRYPT_LIVE / name
    fullchain = live_dir / "fullchain.pem"
    if not fullchain.exists():
        return []
    info = _parse_cert(fullchain) or {}
    domains = info.get("sans") or []
    if not domains:
        subject = info.get("subject") or name
        domains = [subject]
    out: list[str] = []
    for domain in domains:
        try:
            validated = validate_hostname(str(domain).strip())
        except ValidationError:
            continue
        if validated not in out:
            out.append(validated)
    return out


def _is_staging_issuer(issuer: str) -> bool:
    """Detect Let's Encrypt staging issuers exposed by openssl subject text."""
    lowered = issuer.lower()
    return any(marker in lowered for marker in ("staging", "fake le", "pretend pear"))


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
    """Point the GUI vhost and central GUI URL at a Let's Encrypt certificate."""
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
server_name = payload["server_name"]
gui_url = payload["gui_url"]
central_config = Path(payload["central_config"])
if not conf.exists():
    raise SystemExit(f"{conf} does not exist")
text = conf.read_text(encoding="utf-8", errors="replace")
text, count = re.subn(r"^\s*server_name\s+[^;]+;", f"    server_name {server_name};", text, count=1, flags=re.M)
if count == 0:
    text = text.replace("    listen [::]:4444 ssl;\n", "    listen [::]:4444 ssl;\n    server_name " + server_name + ";\n", 1)
text = re.sub(r"^\s*ssl_certificate\s+[^;]+;", f"    ssl_certificate {cert};", text, flags=re.M)
text = re.sub(r"^\s*ssl_certificate_key\s+[^;]+;", f"    ssl_certificate_key {key};", text, flags=re.M)
conf.write_text(text, encoding="utf-8")
if central_config.exists():
    data = json.loads(central_config.read_text(encoding="utf-8"))
    data["gui_url"] = gui_url
    central_config.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    central_config.chmod(0o600)
'''
    res = sudo_run(
        ["python3", "-c", script],
        stdin=json.dumps({
            "conf": str(GUI_NGINX_CONF),
            "cert": str(cert),
            "key": str(key),
            "server_name": name,
            "gui_url": f"https://{name}:4444/",
            "central_config": str(CENTRAL_CONFIG),
        }),
    )
    if not res.ok:
        return {"ok": False, "error": res.stderr or res.stdout}
    test = sudo_run(["nginx", "-t"])
    if not test.ok:
        return {"ok": False, "error": test.stderr or test.stdout}
    reload_res = _reload_or_restart_nginx_for_gui(name)
    report_res = sudo_run(["systemctl", "start", "synca-central-report.service"])
    return {
        "ok": reload_res.ok,
        "cert_path": str(cert),
        "key_path": str(key),
        "gui_url": f"https://{name}:4444/",
        "central_report_ok": report_res.ok,
        "output": (
            test.stdout + test.stderr + reload_res.stdout + reload_res.stderr +
            report_res.stdout + report_res.stderr
        ).strip(),
    }


def _reload_or_restart_nginx_for_gui(name: str):
    """Reload nginx, then restart if the live 4444 certificate did not switch."""
    reload_res = sudo_run(["systemctl", "reload", "nginx"])
    verify_res = _served_gui_certificate(name)
    if reload_res.ok and verify_res.ok:
        return reload_res
    restart_res = sudo_run(["systemctl", "restart", "nginx"])
    verify_after_restart = _served_gui_certificate(name)
    if verify_after_restart.ok:
        return restart_res
    return verify_after_restart if not verify_after_restart.ok else restart_res


def _served_gui_certificate(name: str):
    """Return ok when nginx 4444 is actively serving the requested certificate."""
    script = (
        "echo | openssl s_client -connect 127.0.0.1:4444 "
        f"-servername {name} 2>/dev/null | "
        "openssl x509 -noout -subject -ext subjectAltName"
    )
    res = sudo_run(["bash", "-lc", script], timeout=15)
    if not res.ok:
        return res
    if f"DNS:{name}" in res.stdout or f"CN = {name}" in res.stdout or f"CN={name}" in res.stdout:
        return res
    res.returncode = 1
    res.stderr = f"nginx is not serving certificate for {name}\n{res.stdout}"
    return res


def _current_gui_certificate() -> dict | None:
    """Return the certificate paths currently configured for the 4444 GUI vhost."""
    if not GUI_NGINX_CONF.exists():
        return None
    try:
        text = GUI_NGINX_CONF.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    cert_match = re.search(r"^\s*ssl_certificate\s+([^;]+);", text, flags=re.M)
    key_match = re.search(r"^\s*ssl_certificate_key\s+([^;]+);", text, flags=re.M)
    if not cert_match or not key_match:
        return None
    cert_path = cert_match.group(1).strip().strip('"').strip("'")
    key_path = key_match.group(1).strip().strip('"').strip("'")
    return {"cert_path": cert_path, "key_path": key_path}


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
