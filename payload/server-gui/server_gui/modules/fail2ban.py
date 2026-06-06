"""payload/server-gui/server_gui/modules/fail2ban.py - Manage fail2ban jails and bans.

This module exposes GUI APIs for fail2ban installation, default jail creation,
open-port based jail synchronization, ban inspection, unban, and ignoreip
operations. Runtime fail2ban changes are used for immediate effect; managed
files are written only under server-gui owned paths to avoid overwriting
operator-maintained fail2ban configuration.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from flask import Blueprint, Flask, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..shell import run, sudo_run

logger = logging.getLogger(__name__)

bp = Blueprint("fail2ban", __name__, url_prefix="/fail2ban")

IP_RE = re.compile(r"^[0-9a-fA-F:.]+(?:/\d{1,3})?$")
JAIL_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,63}$")

JAIL_LOCAL = Path("/etc/fail2ban/jail.local")
FAIL2BAN_LOCAL = Path("/etc/fail2ban/fail2ban.local")
JAIL_D = Path("/etc/fail2ban/jail.d")
FILTER_D = Path("/etc/fail2ban/filter.d")
AUTO_JAIL = JAIL_D / "server-gui-auto.local"
IGNOREIP_JAIL = JAIL_D / "server-gui-ignoreip.local"
SERVER_GUI_FILTER = FILTER_D / "server-gui-auth.conf"

_MANAGED_MARKER = "# Managed by server-gui"
_AUTO_MARKER = "# Managed by server-gui (fail2ban auto-open-ports)."

# Sensible defaults for an AlmaLinux router: SSH brute force, HTTP auth abuse,
# GUI login abuse, and recidive. firewallcmd-ipset keeps fail2ban bans inside
# firewalld, which is the firewall authority used elsewhere in the GUI.
DEFAULT_JAIL_LOCAL = """# Managed by server-gui (fail2ban /api/install-defaults).
# Edit by hand only after reviewing; the GUI will not overwrite if this file
# does not contain the "Managed by server-gui" header.

[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
banaction        = firewallcmd-ipset
banaction_allports = firewallcmd-ipset
# Loopback + RFC 1918. Adjust via GUI per-jail addignoreip if needed.
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port    = ssh
backend = systemd

[nginx-http-auth]
enabled = true
port    = http,https,4444
logpath = /var/log/nginx/error.log

[server-gui-auth]
enabled = true
filter  = server-gui-auth
port    = 4444
backend = systemd
journalmatch = _SYSTEMD_UNIT=server-gui.service

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
backend  = polling
bantime  = 1w
findtime = 1d
maxretry = 3
"""

FAIL2BAN_LOCAL_CONTENT = """# Managed by server-gui (fail2ban logging target).
[Definition]
logtarget = /var/log/fail2ban.log
"""

SERVER_GUI_FILTER_CONTENT = """# Managed by server-gui (fail2ban auto-open-ports).
[Definition]
failregex = ^.*failed login for user=.* from <HOST>.*$
            ^.*rate limit hit for <HOST>.*$
ignoreregex =
"""


def register(app: Flask) -> None:
    app.register_blueprint(bp)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("fail2ban.html", active_tab="fail2ban")


@bp.route("/api/status", methods=["GET"])
@login_required
def status():
    """Report whether fail2ban is installed and active."""
    which = run(["which", "fail2ban-client"])
    if not which.ok:
        return jsonify({
            "installed": False,
            "active": False,
            "hint": "dnf install -y fail2ban-server fail2ban-firewalld",
        })
    active = sudo_run(["systemctl", "is-active", "fail2ban"])
    version_res = sudo_run(["fail2ban-client", "--version"])
    return jsonify({
        "installed": True,
        "active": active.stdout.strip() == "active",
        "version": version_res.stdout.strip() if version_res.ok else "",
        "auto_jail_path": str(AUTO_JAIL),
        "auto_filter_path": str(SERVER_GUI_FILTER),
    })


@bp.route("/api/install-defaults", methods=["POST"])
@login_required
@csrf_protect
def install_defaults():
    """Write /etc/fail2ban/jail.local with server-gui defaults."""
    payload = request.get_json(force=True, silent=True) or {}
    force = bool(payload.get("force", False))

    if JAIL_LOCAL.exists():
        try:
            head = JAIL_LOCAL.read_text(encoding="utf-8", errors="replace")[:200]
        except OSError as e:
            return jsonify({"error": f"cannot read existing jail.local: {e}"}), 500
        if _MANAGED_MARKER not in head and not force:
            return jsonify({
                "ok": False,
                "error": "/etc/fail2ban/jail.local exists and was not placed by server-gui. "
                         "Pass force=true to overwrite (a .bak backup will be kept).",
                "existing_first_lines": head,
            }), 409
        bak = JAIL_LOCAL.with_suffix(".local.bak")
        try:
            bak.write_bytes(JAIL_LOCAL.read_bytes())
        except OSError as e:
            return jsonify({"error": f"backup failed: {e}"}), 500

    write_res = _write_managed_file(JAIL_LOCAL, DEFAULT_JAIL_LOCAL)
    if write_res:
        return jsonify({"error": write_res}), 500

    logtarget_res = _write_managed_file(FAIL2BAN_LOCAL, FAIL2BAN_LOCAL_CONTENT)
    if logtarget_res:
        return jsonify({"error": logtarget_res}), 500

    filter_res = _write_managed_file(SERVER_GUI_FILTER, SERVER_GUI_FILTER_CONTENT)
    if filter_res:
        return jsonify({"error": filter_res}), 500

    reload_res = _reload_fail2ban()
    if not reload_res["ok"]:
        return jsonify(reload_res), 500
    return jsonify({
        "ok": True,
        "path": str(JAIL_LOCAL),
        "reload_output": reload_res["output"],
        "jails_enabled": ["sshd", "nginx-http-auth", "server-gui-auth", "recidive"],
    })


@bp.route("/api/jail-local", methods=["GET"])
@login_required
def get_jail_local():
    """Return current managed fail2ban config for read-only inspection."""
    files = []
    for path in (FAIL2BAN_LOCAL, JAIL_LOCAL, AUTO_JAIL, IGNOREIP_JAIL, SERVER_GUI_FILTER):
        item = {"path": str(path), "exists": path.exists(), "content": "", "managed": False}
        if path.exists():
            try:
                item["content"] = path.read_text(encoding="utf-8", errors="replace")
                item["managed"] = _MANAGED_MARKER in item["content"]
            except OSError as e:
                item["error"] = str(e)
        files.append(item)
    return jsonify({
        "exists": JAIL_LOCAL.exists(),
        "content": next((f["content"] for f in files if f["path"] == str(JAIL_LOCAL)), ""),
        "managed": next((f["managed"] for f in files if f["path"] == str(JAIL_LOCAL)), False),
        "files": files,
    })


@bp.route("/api/install", methods=["POST"])
@login_required
@csrf_protect
def install():
    """One-click install. Uses dnf and may run for several seconds."""
    res = sudo_run(["dnf", "install", "-y", "fail2ban-server", "fail2ban-firewalld"], timeout=120)
    if not res.ok:
        return jsonify({"ok": False, "error": (res.stderr or res.stdout).strip()}), 500
    enable = sudo_run(["systemctl", "enable", "--now", "fail2ban"], timeout=30)
    return jsonify({
        "ok": enable.ok,
        "install_output": res.stdout[-2000:],
        "enable_output": (enable.stdout + enable.stderr).strip(),
    })


@bp.route("/api/sync-open-ports", methods=["POST"])
@login_required
@csrf_protect
def sync_open_ports():
    """Generate managed jails for supported services exposed by firewalld."""
    if not run(["which", "fail2ban-client"]).ok:
        return jsonify({"ok": False, "error": "fail2ban-client is not installed"}), 400

    exposure = _detect_firewalld_exposure()
    selected = _select_supported_jails(exposure)
    filter_res = _write_managed_file(SERVER_GUI_FILTER, SERVER_GUI_FILTER_CONTENT)
    if filter_res:
        return jsonify({"ok": False, "error": filter_res}), 500

    jail_content = _build_auto_jail_file(selected["jails"])
    write_res = _write_managed_file(AUTO_JAIL, jail_content)
    if write_res:
        return jsonify({"ok": False, "error": write_res}), 500

    reload_res = _reload_fail2ban()
    return jsonify({
        "ok": reload_res["ok"],
        "output": reload_res["output"],
        "active_zones": exposure["active_zones"],
        "services": sorted(exposure["services"]),
        "ports": sorted(exposure["ports"]),
        "jails_enabled": selected["jails"],
        "unsupported": selected["unsupported"],
        "paths": [str(AUTO_JAIL), str(SERVER_GUI_FILTER)],
    }), (200 if reload_res["ok"] else 500)


@bp.route("/api/jails", methods=["GET"])
@login_required
def list_jails():
    """List configured jails and their stats."""
    jail_names, error = _list_jail_names()
    if error:
        return jsonify({"jails": [], "error": error})
    return jsonify({"jails": [_jail_info(j) for j in jail_names]})


@bp.route("/api/bans", methods=["GET"])
@login_required
def list_bans():
    """Return a flattened list of banned IP addresses across all jails."""
    jail_names, error = _list_jail_names()
    if error:
        return jsonify({"bans": [], "error": error})
    bans = []
    for jail in jail_names:
        info = _jail_info(jail)
        for ip in info.get("banned_ips", []):
            bans.append({
                "ip": ip,
                "jail": jail,
                "reason": _ban_reason(jail, ip, info),
                "filter": info.get("filter") or jail,
                "file_list": info.get("file_list", []),
                "journal_matches": info.get("journal_matches", ""),
            })
    return jsonify({"bans": bans})


@bp.route("/api/jails/<jail>", methods=["GET"])
@login_required
def get_jail(jail: str):
    if not JAIL_NAME_RE.match(jail):
        return jsonify({"error": "invalid jail name"}), 400
    return jsonify(_jail_info(jail))


@bp.route("/api/jails/<jail>/unban", methods=["POST"])
@login_required
@csrf_protect
def unban(jail: str):
    if not JAIL_NAME_RE.match(jail):
        return jsonify({"error": "invalid jail name"}), 400
    ip, error = _payload_ip("ip")
    if error:
        return jsonify({"error": error}), 400
    res = sudo_run(["fail2ban-client", "set", jail, "unbanip", ip])
    return jsonify({"ok": res.ok, "output": (res.stdout + res.stderr).strip()})


@bp.route("/api/jails/<jail>/ignoreip", methods=["POST"])
@login_required
@csrf_protect
def add_ignoreip(jail: str):
    if not JAIL_NAME_RE.match(jail):
        return jsonify({"error": "invalid jail name"}), 400
    ip, error = _payload_ip("ip")
    if error:
        return jsonify({"error": error}), 400
    res = sudo_run(["fail2ban-client", "set", jail, "addignoreip", ip])
    persist_error = None
    if res.ok:
        persist_error = _persist_ignoreip(jail)
    return jsonify({
        "ok": res.ok and not persist_error,
        "output": (res.stdout + res.stderr).strip(),
        "persist_error": persist_error or "",
    })


@bp.route("/api/jails/<jail>/ignoreip", methods=["DELETE"])
@login_required
@csrf_protect
def remove_ignoreip(jail: str):
    if not JAIL_NAME_RE.match(jail):
        return jsonify({"error": "invalid jail name"}), 400
    ip, error = _payload_ip("ip")
    if error:
        return jsonify({"error": error}), 400
    res = sudo_run(["fail2ban-client", "set", jail, "delignoreip", ip])
    persist_error = None
    if res.ok:
        persist_error = _persist_ignoreip(jail)
    return jsonify({
        "ok": res.ok and not persist_error,
        "output": (res.stdout + res.stderr).strip(),
        "persist_error": persist_error or "",
    })


@bp.route("/api/jails/<jail>/ban-to-ignore", methods=["POST"])
@login_required
@csrf_protect
def ban_to_ignore(jail: str):
    """Add the banned IP to ignoreip and then unban it from the same jail."""
    if not JAIL_NAME_RE.match(jail):
        return jsonify({"error": "invalid jail name"}), 400
    ip, error = _payload_ip("ip")
    if error:
        return jsonify({"error": error}), 400
    ignore_res = sudo_run(["fail2ban-client", "set", jail, "addignoreip", ip])
    if not ignore_res.ok:
        return jsonify({"ok": False, "output": (ignore_res.stdout + ignore_res.stderr).strip()}), 500
    persist_error = _persist_ignoreip(jail)
    unban_res = sudo_run(["fail2ban-client", "set", jail, "unbanip", ip])
    return jsonify({
        "ok": unban_res.ok and not persist_error,
        "ignore_output": (ignore_res.stdout + ignore_res.stderr).strip(),
        "persist_error": persist_error or "",
        "unban_output": (unban_res.stdout + unban_res.stderr).strip(),
    })


# ---- internals ---------------------------------------------------------

def _payload_ip(field: str) -> tuple[str, str | None]:
    payload = request.get_json(force=True, silent=True) or {}
    ip = (payload.get(field) or "").strip()
    if not ip or not IP_RE.match(ip):
        return "", "invalid IP / CIDR"
    return ip, None


def _write_managed_file(path: Path, content: str) -> str | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o644)
        return None
    except OSError as e:
        return f"write failed for {path}: {e}"


def _reload_fail2ban() -> dict:
    reload_res = sudo_run(["fail2ban-client", "reload"], timeout=30)
    if reload_res.ok:
        return {"ok": True, "output": (reload_res.stdout + reload_res.stderr).strip()}
    sudo_run(["systemctl", "enable", "fail2ban"], timeout=15)
    start_res = sudo_run(["systemctl", "restart", "fail2ban"], timeout=30)
    return {
        "ok": start_res.ok,
        "output": ((reload_res.stdout + reload_res.stderr + "\n" + start_res.stdout + start_res.stderr).strip()),
    }


def _list_jail_names() -> tuple[list[str], str | None]:
    res = sudo_run(["fail2ban-client", "status"])
    if not res.ok:
        return [], (res.stderr or res.stdout).strip()
    for line in res.stdout.splitlines():
        if "Jail list:" in line:
            tail = line.split("Jail list:", 1)[1].strip()
            return [j.strip() for j in tail.split(",") if j.strip()], None
    return [], None


def _jail_info(jail_name: str) -> dict:
    info: dict = {
        "name": jail_name,
        "currently_failed": 0,
        "total_failed": 0,
        "currently_banned": 0,
        "total_banned": 0,
        "file_list": [],
        "journal_matches": "",
        "banned_ips": [],
        "ignoreip": [],
        "filter": jail_name,
        "actions": [],
    }
    status = sudo_run(["fail2ban-client", "status", jail_name])
    if not status.ok:
        info["error"] = (status.stderr or status.stdout).strip()
        return info

    prefix_re = re.compile(r"^[\s|`\-]+")
    for line in status.stdout.splitlines():
        s = prefix_re.sub("", line).strip()
        if ":" not in s:
            continue
        key, _, value = s.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "Currently failed":
            info["currently_failed"] = _safe_int(value)
        elif key == "Total failed":
            info["total_failed"] = _safe_int(value)
        elif key == "Currently banned":
            info["currently_banned"] = _safe_int(value)
        elif key == "Total banned":
            info["total_banned"] = _safe_int(value)
        elif key == "File list":
            info["file_list"] = value.split() if value else []
        elif key == "Journal matches":
            info["journal_matches"] = value
        elif key == "Banned IP list":
            info["banned_ips"] = value.split() if value else []

    for key, command in {
        "filter": ["fail2ban-client", "get", jail_name, "filter"],
        "actions": ["fail2ban-client", "get", jail_name, "actions"],
    }.items():
        res = sudo_run(command)
        if res.ok:
            parsed = _parse_actions(res.stdout) if key == "actions" else _parse_fail2ban_get_list(res.stdout)
            info[key] = parsed if key == "actions" else (parsed[0] if parsed else res.stdout.strip())

    ig = sudo_run(["fail2ban-client", "get", jail_name, "ignoreip"])
    if ig.ok:
        info["ignoreip"] = [ip for ip in _parse_fail2ban_get_list(ig.stdout) if IP_RE.match(ip)]
    return info


def _detect_firewalld_exposure() -> dict:
    exposure = {"active_zones": [], "services": set(), "ports": set()}
    zones_res = sudo_run(["firewall-cmd", "--get-active-zones"], timeout=10)
    if not zones_res.ok:
        return exposure

    current_zone = ""
    for raw in zones_res.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not raw.startswith((" ", "\t")):
            current_zone = line
            exposure["active_zones"].append(current_zone)
            continue
        if current_zone:
            exposure["active_zones"].append(f"{current_zone}: {line}")

    for zone_entry in exposure["active_zones"]:
        zone = zone_entry.split(":", 1)[0]
        services = sudo_run(["firewall-cmd", "--zone", zone, "--list-services"], timeout=10)
        ports = sudo_run(["firewall-cmd", "--zone", zone, "--list-ports"], timeout=10)
        if services.ok:
            exposure["services"].update(s for s in services.stdout.split() if s)
        if ports.ok:
            exposure["ports"].update(p for p in ports.stdout.split() if p)
    return exposure


def _select_supported_jails(exposure: dict) -> dict:
    services = exposure["services"]
    ports = exposure["ports"]
    jails: list[str] = []
    unsupported: list[dict] = []

    if "ssh" in services or "22/tcp" in ports:
        jails.append("sshd")
    if {"http", "https"} & services or {"80/tcp", "443/tcp", "4444/tcp"} & ports:
        jails.append("nginx-http-auth")
    if "4444/tcp" in ports or "https" in services:
        jails.append("server-gui-auth")

    if "wireguard" in services or "51820/udp" in ports:
        unsupported.append({
            "service": "wireguard",
            "reason": "WireGuard のハンドシェイク失敗は fail2ban が安定して判定できる形式でログ出力されません。",
        })
    if {"ipsec", "ipsec-ike", "ipsec-nat-t"} & services or {"500/udp", "4500/udp"} & ports:
        unsupported.append({
            "service": "ipsec",
            "reason": "strongSwan は対向ごとの journald 解析が必要なため、現時点では自動生成対象外です。",
        })

    for port in sorted(ports):
        if port not in {"22/tcp", "80/tcp", "443/tcp", "4444/tcp", "500/udp", "4500/udp", "51820/udp"}:
            unsupported.append({"service": port, "reason": "このポートに安全な標準 fail2ban filter が割り当てられていません。"})

    ordered = []
    for jail in [*jails, "recidive"]:
        if jail not in ordered:
            ordered.append(jail)
    return {"jails": ordered, "unsupported": unsupported}


def _build_auto_jail_file(jails: list[str]) -> str:
    lines = [
        _AUTO_MARKER,
        "# Generated from currently exposed firewalld services/ports.",
        "# Unsupported UDP/VPN ports are intentionally listed in the API response, not guessed here.",
        "",
        "[DEFAULT]",
        "bantime  = 1h",
        "findtime = 10m",
        "maxretry = 5",
        "backend  = systemd",
        "banaction        = firewallcmd-ipset",
        "banaction_allports = firewallcmd-ipset",
        "",
    ]
    if "sshd" in jails:
        lines += ["[sshd]", "enabled = true", "port = ssh", "backend = systemd", ""]
    if "nginx-http-auth" in jails:
        lines += [
            "[nginx-http-auth]",
            "enabled = true",
            "port = http,https,4444",
            "logpath = /var/log/nginx/error.log",
            "",
        ]
    if "server-gui-auth" in jails:
        lines += [
            "[server-gui-auth]",
            "enabled = true",
            "filter = server-gui-auth",
            "port = 4444",
            "backend = systemd",
            "journalmatch = _SYSTEMD_UNIT=server-gui.service",
            "",
        ]
    if "recidive" in jails:
        lines += [
            "[recidive]",
            "enabled = true",
            "logpath = /var/log/fail2ban.log",
            "backend = polling",
            "bantime = 1w",
            "findtime = 1d",
            "maxretry = 3",
            "",
        ]
    return "\n".join(lines)


def _persist_ignoreip(changed_jail: str) -> str | None:
    """Persist current runtime ignoreip lists without touching operator files."""
    jail_names, error = _list_jail_names()
    if error:
        return error
    if changed_jail not in jail_names:
        jail_names.append(changed_jail)

    lines = [
        "# Managed by server-gui (fail2ban ignoreip persistence).",
        "# The GUI writes full runtime ignoreip lists per jail so fail2ban restarts keep operator changes made in the GUI.",
        "",
    ]
    for jail in sorted(jail_names):
        if not JAIL_NAME_RE.match(jail):
            continue
        ig = sudo_run(["fail2ban-client", "get", jail, "ignoreip"])
        if not ig.ok:
            continue
        ips = [ip for ip in _parse_fail2ban_get_list(ig.stdout) if IP_RE.match(ip)]
        if not ips:
            continue
        lines.extend([f"[{jail}]", "ignoreip = " + " ".join(dict.fromkeys(ips)), ""])
    write_error = _write_managed_file(IGNOREIP_JAIL, "\n".join(lines))
    if write_error:
        return write_error
    reload_res = _reload_fail2ban()
    return None if reload_res["ok"] else reload_res["output"]


def _ban_reason(jail: str, ip: str, info: dict) -> str:
    log_res = sudo_run(["journalctl", "-u", "fail2ban", "--no-pager", "-n", "300"], timeout=10)
    if log_res.ok:
        pattern = re.compile(rf"\bBan\s+{re.escape(ip)}\b")
        for line in reversed(log_res.stdout.splitlines()):
            if jail in line and pattern.search(line):
                return line.strip()
    filter_name = info.get("filter") or jail
    source = ", ".join(info.get("file_list") or []) or info.get("journal_matches") or "fail2ban status"
    return f"jail={jail}, filter={filter_name}, source={source}"


def _parse_fail2ban_get_list(output: str) -> list[str]:
    values = []
    for line in output.splitlines():
        stripped = line.strip(" `|'-").strip()
        if stripped and not stripped.startswith(("The jail has", "No file")):
            values.extend(part.strip(",") for part in stripped.split() if part.strip(","))
    return values


def _parse_actions(output: str) -> list[str]:
    values: list[str] = []
    for line in output.splitlines():
        if "following actions:" in line:
            _, _, tail = line.partition("following actions:")
            values.extend(part.strip(",") for part in tail.split() if part.strip(","))
            continue
        stripped = line.strip(" `|'-").strip()
        if stripped and not stripped.lower().startswith("no actions"):
            values.append(stripped)
    return values


def _safe_int(s: str) -> int:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return 0
