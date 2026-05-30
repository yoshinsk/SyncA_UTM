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
MODULE_NAME = "dnsmasq"


def default() -> dict:
    return {
        "dns": {
            "hosts": [],       # [{id, domain, ip}]
            "cnames": [],      # [{id, alias, target}]
            "upstream": [],    # [{id, domain, server}] (domain optional)
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
    listen_interfaces = sorted({
        str(r.get("interface", "")).strip()
        for r in dhcp.get("ranges", [])
        if str(r.get("interface", "")).strip()
    })
    if listen_interfaces:
        lines.append("# --- Listening interfaces ---")
        # AlmaLinux 9 dnsmasq defaults to interface=lo. Add the LAN DHCP
        # interfaces explicitly so clients can use this host as their DNS.
        for interface in listen_interfaces:
            lines.append(f"interface={interface}")
        lines.append("domain-needed")
        lines.append("bogus-priv")
        lines.append("dhcp-authoritative")
        lines.append("")

    if dns.get("hosts") or dns.get("cnames") or dns.get("upstream"):
        lines.append("# --- DNS ---")
    for h in dns.get("hosts", []):
        lines.append(f"address=/{h['domain']}/{h['ip']}")
    for c in dns.get("cnames", []):
        lines.append(f"cname={c['alias']},{c['target']}")
    for u in dns.get("upstream", []):
        if u.get("domain"):
            lines.append(f"server=/{u['domain']}/{u['server']}")
        else:
            lines.append(f"server={u['server']}")

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

    # Validate with dnsmasq --test (covers the GENERATED file + main config)
    test = sudo_run(["dnsmasq", "--test"])
    if not test.ok:
        _restore(backup)
        raise RuntimeError(f"dnsmasq --test failed:\n{test.stderr.strip() or test.stdout.strip()}")

    # Reload-safe restart
    restart = sudo_run(["systemctl", "restart", "dnsmasq"])
    if not restart.ok:
        _restore(backup)
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
