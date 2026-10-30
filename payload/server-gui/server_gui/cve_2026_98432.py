"""payload/server-gui/server_gui/cve_2026_98432.py

CVE-2026-98432の暫定緩和用nftablesテーブルと起動サービスを管理する。
Red Hat RHSB-2026-016準拠。カーネル修正の代替ではない。
"""
from __future__ import annotations

import contextlib
import json
import subprocess
from pathlib import Path

TABLE = "synca_cve_2026_98432"
SERVICE = "synca-cve-2026-98432.service"
UNIT = Path("/etc/systemd/system") / SERVICE
DISABLED = Path("/etc/server-gui/cve-2026-98432.disabled")
RULESET = f"""table inet {TABLE} {{
    chain input {{
        type filter hook input priority -310; policy accept;
        ip protocol tcp ip hdrlength > 5 counter drop
    }}
}}
"""
UNIT_TEXT = """# Managed by server_gui.cve_2026_98432; temporary mitigation only.
[Unit]
Description=SyncA CVE-2026-98432 IPv4 TCP mitigation
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target
ConditionPathExists=!/etc/server-gui/cve-2026-98432.disabled
RequiresMountsFor=/opt/server-gui

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/server-gui
ExecStart=/opt/server-gui/venv/bin/python -m server_gui.cve_2026_98432 apply
ExecStop=/opt/server-gui/venv/bin/python -m server_gui.cve_2026_98432 remove
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
"""


def command(argv: list[str], stdin: str | None = None, check: bool = True):
    """シェルを使わず固定引数で実行し、権限不足やタイムアウトを失敗として返す。"""
    result = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=25)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


@contextlib.contextmanager
def lock(kind: str):
    """GUIの複数workerを直列化する。systemd制御とルール操作は別ロックにする。"""
    import fcntl

    with Path(f"/run/synca-cve-2026-98432-{kind}.lock").open("w") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def table_state() -> dict:
    """専用テーブルの構造と遮断カウンターを読み、存在だけで有効と判定しない。"""
    tables = json.loads(command(["nft", "-j", "list", "tables"]).stdout)["nftables"]
    if not any(row.get("table", {}).get("name") == TABLE and
               row["table"].get("family") == "inet" for row in tables):
        return {"active": False, "exists": False, "packets": 0, "bytes": 0}
    data = json.loads(command(["nft", "-j", "list", "table", "inet", TABLE]).stdout)["nftables"]
    chains = [row["chain"] for row in data if "chain" in row]
    rules = [row["rule"] for row in data if "rule" in row]
    expressions = rules[0].get("expr", []) if len(rules) == 1 else []
    expected = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "protocol"}}, "right": "tcp"}},
        {"match": {"op": ">", "left": {"payload": {"protocol": "ip", "field": "hdrlength"}}, "right": 5}},
        {"drop": None},
    ]
    without_counter = [expr for expr in expressions if "counter" not in expr]
    chain = chains[0] if len(chains) == 1 else {}
    active = (chain.get("name") == "input" and chain.get("type") == "filter" and
              chain.get("hook") == "input" and chain.get("prio") == -310 and
              chain.get("policy") == "accept" and len(rules) == 1 and
              rules[0].get("chain") == "input" and without_counter == expected and
              sum("counter" in expr for expr in expressions) == 1)
    counter = next((expr["counter"] for expr in expressions if "counter" in expr), {})
    return {"active": active, "exists": True,
            "packets": counter.get("packets", 0), "bytes": counter.get("bytes", 0)}


def apply() -> dict:
    """検査済みバッチを原子的に適用する。正常な既存ルールのカウンターは維持する。"""
    with lock("rules"):
        state = table_state()
        if not state["active"]:
            batch = (f"delete table inet {TABLE}\n" if state["exists"] else "") + RULESET
            command(["nft", "--check", "--file", "-"], batch)
            command(["nft", "--file", "-"], batch)
            state = table_state()
            if not state["active"]:
                raise RuntimeError("緩和ルールを適用後に確認できません")
        return state


def remove() -> dict:
    """この機能の専用テーブルだけを削除し、firewalldや他のテーブルは維持する。"""
    with lock("rules"):
        if table_state()["exists"]:
            command(["nft", "delete", "table", "inet", TABLE])
    return {"active": False}


def install(enable: bool = False) -> dict:
    """旧更新プログラムでもGUI再起動時に導入する。明示的な解除状態は保持する。"""
    with lock("control"):
        if not UNIT.exists() or UNIT.read_text(encoding="utf-8") != UNIT_TEXT:
            UNIT.parent.mkdir(parents=True, exist_ok=True)
            temporary = UNIT.with_suffix(".service.tmp")
            temporary.write_text(UNIT_TEXT, encoding="utf-8")
            temporary.chmod(0o644)
            temporary.replace(UNIT)
            command(["systemctl", "daemon-reload"])
        if enable:
            DISABLED.unlink(missing_ok=True)
        if DISABLED.exists():
            return {"disabled": True, **table_state()}
        # nftables.serviceは起動しない。独立サービスで他のルールのflushを避ける。
        command(["systemctl", "enable", SERVICE])
        state = apply()
        command(["systemctl", "start", SERVICE])
        return {"disabled": False, **state}


def disable() -> dict:
    """GUI更新で再有効化されないよう解除指定を残し、現在・次回起動の両方を解除。"""
    with lock("control"):
        DISABLED.parent.mkdir(parents=True, exist_ok=True)
        DISABLED.touch(mode=0o600)
        if UNIT.exists():
            command(["systemctl", "disable", "--now", SERVICE])
        return {"disabled": True, **remove()}


def status() -> dict:
    """カーネル修正済みとの誤認を避け、暫定ルールと永続化を個別に報告する。"""
    return {"table": TABLE, "temporary_mitigation": True,
            "disabled": DISABLED.exists(), **table_state(),
            "boot_enabled": command(["systemctl", "is-enabled", SERVICE], check=False).returncode == 0,
            "service_active": command(["systemctl", "is-active", SERVICE], check=False).returncode == 0}


def main() -> int:
    """CLIとGUI共通の実行口。失敗時はJSONと非ゼロ終了コードを返す。"""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "enable", "disable", "apply", "remove", "status"))
    action = parser.parse_args().action
    try:
        result = install(enable=True) if action == "enable" else globals()[action]()
        print(json.dumps({"ok": True, **result}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
