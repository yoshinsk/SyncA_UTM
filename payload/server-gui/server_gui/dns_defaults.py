"""payload/server-gui/server_gui/dns_defaults.py - 未設定箇所だけにDNSの既定値を導入する。"""
from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path

from .config_store import ConfigStore
from .dnsmasq_apply import (MODULE_NAME, apply, default, default_dhcp_dns,
                            has_global_dhcp_dns)

DEFAULT_SERVERS = "1.1.1.3,1.0.0.3"


def _command(argv: list[str]) -> str:
    """シェルを介さず実行し、失敗時には移行完了を記録しない。"""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                          env={**os.environ, "LC_ALL": "C"}, check=False)
    if proc.returncode:
        raise RuntimeError(f"DNS初期値の導入に失敗しました: {argv[0]}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _initialize_dnsmasq(store: ConfigStore) -> None:
    """明示設定・空配列を保持し、欠けた上流DNSとグローバルDHCP DNSだけを補う。"""
    with store.transaction(MODULE_NAME, {}) as data:
        existed = store.path(MODULE_NAME).exists()
        before = copy.deepcopy(data)
        dns = data.setdefault("dns", {})
        if dns.get("upstream") is None:
            dns["upstream"] = default()["dns"]["upstream"]
        dns.setdefault("hosts", [])
        dns.setdefault("cnames", [])
        dhcp = data.setdefault("dhcp", {})
        options = dhcp.setdefault("options", [])
        if not has_global_dhcp_dns(options):
            options.append(default_dhcp_dns())
        if data != before:
            # apply()は保存モデルを読むため、検証失敗時にはJSONも元へ戻す。
            store.save(MODULE_NAME, data)
            try:
                apply(store.base_dir)
            except Exception:
                if existed:
                    store.save(MODULE_NAME, before)
                else:
                    store.path(MODULE_NAME).unlink(missing_ok=True)
                raise


def _initialize_system_dns() -> bool:
    """既定経路の稼働プロファイルだけを調べ、DNSプロパティだけを変更する。"""
    routes = json.loads(_command(["ip", "-j", "-4", "route", "show", "default"]))
    routes = sorted((row for row in routes if row.get("dev")), key=lambda row: row.get("metric", 0))
    if not routes:
        return False
    interface = routes[0]["dev"]
    uuid = _command(["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", interface])
    if not uuid or uuid == "--":
        return False
    prefix = ["nmcli", "-g"]
    dns = _command([*prefix, "ipv4.dns", "connection", "show", "uuid", uuid])
    ignore = _command([*prefix, "ipv4.ignore-auto-dns", "connection", "show", "uuid", uuid])
    # DNS指定済み、または空のDNSを明示して自動取得を止めたプロファイルは維持する。
    if dns or ignore == "yes":
        return True
    props = ["ipv4.dns", DEFAULT_SERVERS, "ipv4.ignore-auto-dns", "yes"]
    _command(["nmcli", "connection", "modify", "uuid", uuid, *props])
    try:
        # up/downや全設定のreapplyを避け、接続中のDNSだけを反映する。
        _command(["nmcli", "device", "modify", interface, *props])
    except Exception:
        _command(["nmcli", "connection", "modify", "uuid", uuid,
                  "ipv4.dns", dns, "ipv4.ignore-auto-dns", ignore])
        raise
    return True


def initialize(config_dir: Path | str) -> None:
    """GUI更新後の起動時に一度だけ補完し、後日の利用者による変更を尊重する。"""
    store = ConfigStore(config_dir)
    with store.transaction("dns_defaults", {}) as state:
        if not state.get("dnsmasq_initialized"):
            _initialize_dnsmasq(store)
            state["dnsmasq_initialized"] = True
        if not state.get("system_initialized"):
            state["system_initialized"] = _initialize_system_dns()
