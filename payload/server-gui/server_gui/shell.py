"""payload/server-gui/server_gui/shell.py

Safe subprocess wrappers for SyncA UTM's server GUI. Commands are executed
without shell=True and returned as structured text results for API handlers.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
from typing import Sequence

logger = logging.getLogger(__name__)


class CommandResult:
    def __init__(self, returncode: int, stdout: str, stderr: str, argv: Sequence[str]) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.argv = list(argv)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def __repr__(self) -> str:
        joined = " ".join(shlex.quote(a) for a in self.argv)
        return f"CommandResult(rc={self.returncode}, argv={joined})"


def _coerce_text(value: str | bytes | None) -> str:
    """Normalize subprocess output to text, including TimeoutExpired bytes."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run(argv: Sequence[str], *, timeout: float = 30.0, check: bool = False, stdin: str | None = None) -> CommandResult:
    if not argv:
        raise ValueError("argv must not be empty")
    if not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must contain only strings")

    logger.info("exec: %s", " ".join(shlex.quote(a) for a in argv))
    try:
        proc = subprocess.run(
            list(argv),
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        stdout = _coerce_text(e.stdout)
        stderr = _coerce_text(e.stderr)
        if stderr:
            stderr += "\n"
        stderr += "[timeout]"
        return CommandResult(124, stdout, stderr, argv)
    except FileNotFoundError as e:
        return CommandResult(127, "", str(e), argv)

    result = CommandResult(proc.returncode, proc.stdout, proc.stderr, argv)
    if check and not result.ok:
        raise subprocess.CalledProcessError(proc.returncode, list(argv), proc.stdout, proc.stderr)
    return result


def sudo_run(argv: Sequence[str], **kw) -> CommandResult:
    """Run with `sudo -n` prefix. Required when the service is not root."""
    if list(argv) == ["firewall-cmd", "--reload"]:
        from .firewalld_safety import ensure_before_firewalld_reload

        guard = ensure_before_firewalld_reload()
        if not guard.ok:
            return CommandResult(1, "", guard.output, argv)
    return run(["sudo", "-n", *argv], **kw)
