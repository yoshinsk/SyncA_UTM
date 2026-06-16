"""payload/server-gui/server_gui/dnsmasq_apply.py - Generate and apply dnsmasq config.

Both the DNS and DHCP modules share storage under module name `dnsmasq`
and the generated file `/etc/dnsmasq.d/server-gui.conf`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config_store import ConfigStore
from .shell import sudo_run

CONFIG_PATH = Path("/etc/dnsmasq.d/server-gui.conf")
LEGACY_FIRSTBOOT_CONFIG_PATH = Path("/etc/dnsmasq.d/synca-lan.conf")
DNSMASQ_MAIN_CONFIG_PATH = Path("/etc/dnsmasq.conf")
DNSMASQ_SYSTEMD_DROPIN_DIR = Path("/etc/systemd/system/dnsmasq.service.d")
DNSMASQ_SYSTEMD_DROPIN_PATH = DNSMASQ_SYSTEMD_DROPIN_DIR / "synca-utm.conf"
MODULE_NAME = "dnsmasq"
DEFAULT_UPSTREAM = (
    {"id": "cloudflare-1", "domain": "", "server": "1.1.1.1"},
    {"id": "cloudflare-2", "domain": "", "server": "1.0.0.1"},
)
DNSMASQ_SYSTEMD_DROPIN_CONTENT = """# Managed by server-gui.
[Unit]
Wants=network-online.target
After=network-online.target NetworkManager.service
StartLimitIntervalSec=0

[Service]
ExecStartPre=/bin/sh -c 'test ! -x /opt/server-gui/bin/dnsmasq-runtime-guard || exec /opt/server-gui/bin/dnsmasq-runtime-guard'
Restart=on-failure
RestartSec=5s
"""


def default() -> dict:
    return {
        "dns": {
            "hosts": [],       # [{id, domain, ip}]
            "cnames": [],      # [{id, alias, target}]
            "upstream": _default_upstream(),  # [{id, domain, server}] (domain optional)
        },
        "dhcp": {
            "ranges": [],      # [{id, interface, start, end, lease}]
            "static_hosts": [],# [{id, mac, ip, hostname, lease}]
            "options": [],     # [{id, option, value, tag}]
        },
    }


def generate(data: dict) -> str:
    """Render the JSON model to a dnsmasq.conf snippet."""
    lines: list[str] = [
        "# Managed by server-gui - do not edit by hand.",
        "# To stop GUI management, simply delete this file (existing dnsmasq",
        "# config in /etc/dnsmasq.conf and elsewhere is NOT touched).",
        "",
    ]

    dns = data.get("dns", {})
    dhcp = data.get("dhcp", {})
    upstream = dns.get("upstream") or _default_upstream()
    listen_interfaces = _listen_interfaces(data)
    if listen_interfaces:
        lines.append("# --- Listening interfaces ---")
        # AlmaLinux 9 dnsmasq defaults to interface=lo. Add the LAN DHCP
        # interfaces explicitly so clients can use this host as their DNS.
        for interface in listen_interfaces:
            lines.append(f"interface={interface}")
        # LAN bridges can be created after dnsmasq starts. bind-dynamic keeps
        # the service alive and begins listening when the bridge appears.
        lines.append("bind-dynamic")
        lines.append("domain-needed")
        lines.append("bogus-priv")
        lines.append("dhcp-authoritative")
        lines.append("")

    if dns.get("hosts") or dns.get("cnames") or upstream:
        lines.append("# --- DNS ---")
    for h in dns.get("hosts", []):
        lines.append(f"address=/{h['domain']}/{h['ip']}")
    for c in dns.get("cnames", []):
        lines.append(f"cname={c['alias']},{c['target']}")
    for u in upstream:
        server = str(u.get("server", "")).strip()
        if not server:
            continue
        domain = str(u.get("domain", "")).strip()
        if domain:
            lines.append(f"server=/{domain}/{server}")
        else:
            lines.append(f"server={server}")

    if dhcp.get("ranges") or dhcp.get("static_hosts") or dhcp.get("options"):
        lines.append("")
        lines.append("# --- DHCP ---")
    for r in dhcp.get("ranges", []):
        parts: list[str] = []
        if r.get("interface"):
            parts.append(f"interface:{r['interface']}")
        parts.append(r["start"])
        parts.append(r["end"])
        if r.get("netmask"):
            parts.append(r["netmask"])
        parts.append(r.get("lease", "12h"))
        lines.append(f"dhcp-range={','.join(parts)}")
    for h in dhcp.get("static_hosts", []):
        parts = [h["mac"], h["ip"]]
        if h.get("hostname"):
            parts.append(h["hostname"])
        if h.get("lease"):
            parts.append(h["lease"])
        lines.append(f"dhcp-host={','.join(parts)}")
    for o in dhcp.get("options", []):
        opt = _format_option(str(o["option"]))
        if o.get("tag"):
            line = f"dhcp-option=tag:{o['tag']},{opt},{o['value']}"
        else:
            line = f"dhcp-option={opt},{o['value']}"
        lines.append(line)

    return "\n".join(lines) + "\n"


def apply(config_dir: Any) -> None:
    """Regenerate /etc/dnsmasq.d/server-gui.conf, validate, and restart dnsmasq.

    Rolls back on validation/restart failure.
    """
    store = ConfigStore(config_dir)
    data = store.load(MODULE_NAME, default())
    content = generate(data)
    needs_dynamic_bind = bool(_listen_interfaces(data))

    backup: bytes | None = None
    if CONFIG_PATH.exists():
        try:
            backup = CONFIG_PATH.read_bytes()
        except OSError:
            backup = None

    # Write to a sibling tmp then atomic rename
    tmp_path = CONFIG_PATH.with_suffix(".conf.new")
    tmp_path.write_text(content, encoding="utf-8")
    try:
        tmp_path.replace(CONFIG_PATH)
    except OSError as e:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(f"failed to write {CONFIG_PATH}: {e}") from e

    legacy_backup: bytes | None = None
    legacy_removed = False
    if data.get("dhcp", {}).get("ranges") and LEGACY_FIRSTBOOT_CONFIG_PATH.exists():
        try:
            legacy_backup = LEGACY_FIRSTBOOT_CONFIG_PATH.read_bytes()
            LEGACY_FIRSTBOOT_CONFIG_PATH.unlink()
            legacy_removed = True
        except OSError as e:
            _restore(backup)
            raise RuntimeError(f"failed to disable {LEGACY_FIRSTBOOT_CONFIG_PATH}: {e}") from e

    runtime = _ensure_dnsmasq_runtime(needs_dynamic_bind)
    if not runtime.ok:
        _restore(backup)
        _restore_legacy(legacy_backup, legacy_removed)
        raise RuntimeError(f"dnsmasq runtime preparation failed:\n{runtime.stderr.strip() or runtime.stdout.strip()}")

    # Validate with dnsmasq --test (covers the GENERATED file + main config)
    test = sudo_run(["dnsmasq", "--test"])
    if not test.ok:
        _restore(backup)
        _restore_legacy(legacy_backup, legacy_removed)
        raise RuntimeError(f"dnsmasq --test failed:\n{test.stderr.strip() or test.stdout.strip()}")

    # Reload-safe restart
    restart = sudo_run(["systemctl", "restart", "dnsmasq"])
    if not restart.ok:
        _restore(backup)
        _restore_legacy(legacy_backup, legacy_removed)
        sudo_run(["systemctl", "restart", "dnsmasq"])  # best-effort second try
        raise RuntimeError(f"dnsmasq restart failed:\n{restart.stderr.strip()}")


def _format_option(name: str) -> str:
    """dnsmasq requires `option:` prefix for named options. Numeric option
    codes go as-is. Inputs that already carry the prefix are returned untouched.
    """
    if name.startswith("option:") or name.startswith("option6:"):
        return name
    if name.isdigit():
        return name
    return f"option:{name}"


def _default_upstream() -> list[dict[str, str]]:
    return [dict(item) for item in DEFAULT_UPSTREAM]


def _listen_interfaces(data: dict) -> list[str]:
    dhcp = data.get("dhcp", {})
    return sorted({
        str(r.get("interface", "")).strip()
        for r in dhcp.get("ranges", [])
        if str(r.get("interface", "")).strip()
    })


def _ensure_dnsmasq_runtime(needs_dynamic_bind: bool) -> Any:
    """Install systemd retry behavior and avoid bind option conflicts."""
    script = [
        "set -e",
        f"install -d -m 0755 {DNSMASQ_SYSTEMD_DROPIN_DIR}",
        f"cat > {DNSMASQ_SYSTEMD_DROPIN_PATH} <<'EOF'",
        DNSMASQ_SYSTEMD_DROPIN_CONTENT.rstrip("\n"),
        "EOF",
        f"chmod 0644 {DNSMASQ_SYSTEMD_DROPIN_PATH}",
    ]
    if needs_dynamic_bind:
        script.extend([
            f"if [ -f {DNSMASQ_MAIN_CONFIG_PATH} ] && "
            f"grep -Eq '^[[:space:]]*bind-interfaces([[:space:]]|$)' {DNSMASQ_MAIN_CONFIG_PATH}; then",
            f"  cp -a {DNSMASQ_MAIN_CONFIG_PATH} "
            f"{DNSMASQ_MAIN_CONFIG_PATH}.synca-bind-dynamic.$(date +%Y%m%d%H%M%S).bak",
            f"  sed -i -E "
            f"'s/^([[:space:]]*)bind-interfaces([[:space:]]*)$/# SyncA UTM: bind-dynamic is used so LAN bridges can appear after dnsmasq starts.\\n#\\1bind-interfaces\\2/' "
            f"{DNSMASQ_MAIN_CONFIG_PATH}",
            "fi",
        ])
    script.append("systemctl daemon-reload")
    return sudo_run(["/bin/bash", "-lc", "\n".join(script)], timeout=20)


def _restore(backup: bytes | None) -> None:
    if backup is None:
        try:
            CONFIG_PATH.unlink()
        except FileNotFoundError:
            pass
        return
    try:
        CONFIG_PATH.write_bytes(backup)
    except OSError:
        pass


def _restore_legacy(backup: bytes | None, removed: bool) -> None:
    """Restore the firstboot dnsmasq snippet when generated config apply fails."""
    if not removed or backup is None:
        return
    try:
        LEGACY_FIRSTBOOT_CONFIG_PATH.write_bytes(backup)
    except OSError:
        pass
