"""Safe subprocess wrappers. Never uses shell=True."""
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
        return CommandResult(124, e.stdout or "", (e.stderr or "") + "\n[timeout]", argv)
    except FileNotFoundError as e:
        return CommandResult(127, "", str(e), argv)

    result = CommandResult(proc.returncode, proc.stdout, proc.stderr, argv)
    if check and not result.ok:
        raise subprocess.CalledProcessError(proc.returncode, list(argv), proc.stdout, proc.stderr)
    return result


def sudo_run(argv: Sequence[str], **kw) -> CommandResult:
    """Run with `sudo -n` prefix. Required when the service is not root."""
    return run(["sudo", "-n", *argv], **kw)
