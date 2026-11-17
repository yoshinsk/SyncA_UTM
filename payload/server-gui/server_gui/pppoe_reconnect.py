"""payload/server-gui/server_gui/pppoe_reconnect.py - GUI更新時に既存PPPoEの切断監視と無制限再試行を導入する。"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from .config_store import ConfigStore

MODULE = "pppoe_reconnect"
VERSION = 1
UNIT = "server-gui-pppoe-reconnect"
INSTALL_DIR = Path("/opt/server-gui")
RECONNECT_DELAY = 20
UUID_RE = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
PROPERTIES = ("connection.autoconnect", "connection.autoconnect-retries",
              "ppp.lcp-echo-interval", "ppp.lcp-echo-failure")


def _now() -> str:
    """移行記録をタイムゾーン付きUTCで統一する。"""
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _command(argv: list[str], *, check: bool = True, timeout: int = 30) -> str:
    """秘密情報を取得せず、シェルを介さずにnmcliとsystemdを実行する。"""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "LC_ALL": "C"}, check=False)
    if check and proc.returncode:
        raise RuntimeError(f"{argv[0]} failed (rc={proc.returncode}): {proc.stderr.strip()[:500]}")
    return proc.stdout.strip()


def _profiles() -> list[str]:
    """接続名やPPPoE認証情報を読まず、PPPoEのUUIDだけを列挙する。"""
    output = _command(["nmcli", "-t", "--escape", "no", "-f", "UUID,TYPE",
                       "connection", "show"])
    uuids = []
    for line in output.splitlines():
        uuid, _, kind = line.partition(":")
        if kind != "pppoe":
            continue
        if not UUID_RE.fullmatch(uuid):
            raise ValueError("PPPoE profile UUID is invalid")
        if uuid not in uuids:
            uuids.append(uuid)
    return uuids


def _active_profiles() -> set[str]:
    """手動で切断した接続を再開しないよう、現在の接続だけを判定する。"""
    return set(_command(["nmcli", "-t", "-f", "UUID", "connection", "show",
                         "--active"]).splitlines())


def _settings(uuid: str) -> dict:
    """変更対象の4項目だけを読み、値の不明な接続は変更しない。"""
    values = _command(["nmcli", "-g", ",".join(PROPERTIES), "connection", "show",
                       "uuid", uuid]).splitlines()
    if len(values) != len(PROPERTIES) or values[0] not in ("yes", "no"):
        raise ValueError("PPPoE reconnect properties are invalid")
    numbers = [int(value) for value in values[1:]]
    if numbers[0] < -1 or any(value < 0 for value in numbers[1:]):
        raise ValueError("PPPoE reconnect properties are out of range")
    return dict(zip(PROPERTIES, [values[0], *numbers]))


def _schedule(config_dir: Path) -> None:
    """GUI応答の後に独立workerで再接続し、複数GUI workerの重複予約を避ける。"""
    states = _command(["systemctl", "is-active", UNIT + ".timer", UNIT + ".service"],
                      check=False).splitlines()
    if any(state in ("active", "activating", "reloading") for state in states):
        return
    _command(["systemd-run", "--quiet", "--collect", "--unit=" + UNIT,
              f"--on-active={RECONNECT_DELAY}s", "--timer-property=AccuracySec=1s",
              "--property=WorkingDirectory=" + str(INSTALL_DIR), sys.executable,
              "-m", "server_gui.pppoe_reconnect", "activate",
              "--config-dir", str(config_dir)])


def _profile_states(state: dict) -> dict:
    """不正な移行記録を上書きせず、再接続判断に使う型とUUIDを検査する。"""
    if not isinstance(state, dict):
        raise ValueError("PPPoE migration state is invalid")
    profiles = state.setdefault("profiles", {})
    if not isinstance(profiles, dict) or any(
            not UUID_RE.fullmatch(uuid) or not isinstance(value, dict)
            for uuid, value in profiles.items()):
        raise ValueError("PPPoE profile migration state is invalid")
    return profiles


def initialize(config_dir: Path | str) -> dict:
    """UUIDごとに一度だけ移行する。以後の手動変更と自動接続OFFを保持する。"""
    config_dir = Path(config_dir)
    if (config_dir / (MODULE + ".disabled")).exists():
        return {"ok": True, "disabled": True, "updated": 0, "pending": 0}
    store = ConfigStore(config_dir)
    errors, updated = [], 0
    # 設定変更・完了記録・予約を同じ排他ロックで囲み、複数workerでも一度だけ変更する。
    with store.transaction(MODULE, {"profiles": {}}) as state:
        profiles = _profile_states(state)
        for uuid in _profiles():
            previous = profiles.get(uuid, {})
            if previous.get("version") == VERSION and not previous.get("prepared"):
                continue
            try:
                before = _settings(uuid)
                if before[PROPERTIES[0]] == "no":
                    continue
                target = dict(before)
                target[PROPERTIES[1]] = 0
                # 旧初期値の0/0だけを補完する。片方だけ非ゼロの場合も独自設定として保持する。
                enable_monitor = before[PROPERTIES[2]] == before[PROPERTIES[3]] == 0
                if enable_monitor:
                    target[PROPERTIES[2]], target[PROPERTIES[3]] = 10, 6
                resume_activation = (previous.get("prepared") and previous.get("pending")
                                     and before == previous.get("target"))
                changes = [item for key in PROPERTIES[1:] if before[key] != target[key]
                           for item in (key, str(target[key]))]
                # 変更前に意図を永続化する。設定変更後にプロセスが終了しても、次回起動で再接続を引き継ぐ。
                original = previous.get("before", before) if resume_activation else before
                profile = {"version": VERSION, "before": original, "target": target,
                           "pending": bool(enable_monitor or resume_activation),
                           "prepared": True, "saved_at": _now()}
                profiles[uuid] = profile
                store.save(MODULE, state)
                if changes:
                    _command(["nmcli", "connection", "modify", "uuid", uuid, *changes])
                    updated += 1
                profile["prepared"] = False
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                # 成功した接続は保存し、失敗した接続には完了印を付けず次回に再試行する。
                errors.append(f"{uuid}: {exc}")
        pending = [uuid for uuid, value in profiles.items()
                   if value.get("pending") and not value.get("prepared")]
        if pending:
            try:
                active = _active_profiles()
                for uuid in pending:
                    if uuid not in active:
                        profiles[uuid]["pending"] = False
                        profiles[uuid]["activation_note"] = "inactive; applies on next activation"
                if any(value.get("pending") and not value.get("prepared")
                       for value in profiles.values()):
                    _schedule(config_dir)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                errors.append(str(exc))
        state["last_errors"] = errors
        state["last_check_at"] = _now()
        remaining = sum(bool(value.get("pending")) for value in profiles.values())
    return {"ok": not errors, "disabled": False, "updated": updated,
            "pending": remaining, "errors": errors}


def activate(config_dir: Path | str) -> dict:
    """移行時に接続中だったPPPだけを一度再接続し、変更された運用条件を再確認する。"""
    config_dir = Path(config_dir)
    if (config_dir / (MODULE + ".disabled")).exists():
        return {"ok": True, "disabled": True, "reconnected": 0}
    store = ConfigStore(config_dir)
    errors, reconnected = [], 0
    with store.transaction(MODULE, {"profiles": {}}) as state:
        for uuid, profile in _profile_states(state).items():
            if not profile.get("pending") or profile.get("prepared"):
                continue
            try:
                if not UUID_RE.fullmatch(uuid):
                    raise ValueError("PPPoE profile UUID is invalid")
                # 予約後の手動切断・WAN切替・設定変更を取り消さない。
                if uuid not in _active_profiles():
                    profile["pending"] = False
                    profile["activation_note"] = "inactive; not reconnected"
                    continue
                current = _settings(uuid)
                if current[PROPERTIES[0]] != "yes" or current != profile.get("target"):
                    profile["pending"] = False
                    profile["activation_note"] = "operator settings changed; not reconnected"
                    continue
                _command(["nmcli", "--wait", "60", "connection", "up", "uuid", uuid], timeout=75)
                profile["pending"] = False
                profile["activated_at"] = _now()
                reconnected += 1
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                # 接続失敗は成功扱いにしない。保存済みの無制限再試行はNetworkManagerが継続する。
                errors.append(f"{uuid}: {exc}")
        state["last_errors"] = errors
        state["last_activation_at"] = _now()
    return {"ok": not errors, "disabled": False, "reconnected": reconnected, "errors": errors}


def main() -> int:
    """旧workerのimportキャッシュを避け、新版モジュールを別プロセスから実行する。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("initialize", "activate", "status"))
    parser.add_argument("--config-dir", type=Path, default=Path("/etc/server-gui"))
    args = parser.parse_args()
    try:
        if args.action == "status":
            result = ConfigStore(args.config_dir).load(MODULE, {})
        else:
            result = (initialize if args.action == "initialize" else activate)(args.config_dir)
        if not isinstance(result, dict):
            raise ValueError("PPPoE migration state is invalid")
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("ok", True) else 1
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
