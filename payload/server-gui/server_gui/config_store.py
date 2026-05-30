"""Per-module JSON config persistence with file locking and atomic writes."""
from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,31}$")


class ConfigStore:
    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def path(self, module: str) -> Path:
        if not _NAME_RE.match(module):
            raise ValueError(f"invalid module name: {module!r}")
        return self.base_dir / f"{module}.json"

    def _lock_path(self, module: str) -> Path:
        return self.base_dir / f".{module}.lock"

    def load(self, module: str, default: Any = None) -> Any:
        p = self.path(module)
        if not p.exists():
            return default if default is not None else {}
        with p.open("r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                content = f.read()
                if not content.strip():
                    return default if default is not None else {}
                return json.loads(content)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def save(self, module: str, data: Any) -> None:
        p = self.path(module)
        fd, tmp_path_str = tempfile.mkstemp(prefix=f".{module}-", suffix=".tmp", dir=str(self.base_dir))
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, p)
        except Exception:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
            raise

    @contextmanager
    def transaction(self, module: str, default: Any = None) -> Iterator[Any]:
        """Exclusive lock on a sidecar lockfile + atomic save on success."""
        lock = self._lock_path(module)
        lock.touch(mode=0o600, exist_ok=True)
        with lock.open("r+") as lock_f:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
            try:
                data = self.load(module, default)
                yield data
                self.save(module, data)
            finally:
                fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
