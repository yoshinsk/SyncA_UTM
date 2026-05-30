"""Dashboard / system status module."""
from __future__ import annotations

import platform
from pathlib import Path

from flask import Blueprint, Flask, jsonify, render_template

from ..auth import login_required
from ..shell import run

bp = Blueprint("system", __name__, url_prefix="/system")


def register(app: Flask) -> None:
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", active_tab="dashboard")


@bp.route("/api/status")
@login_required
def status():
    return jsonify({
        "hostname": _read_text(Path("/etc/hostname")).strip() or platform.node(),
        "os": _read_os_release(),
        "uptime": run(["uptime"]).stdout.strip(),
        "memory": run(["free", "-h"]).stdout,
        "disk": run(["df", "-h", "/"]).stdout,
        "kernel": platform.release(),
    })


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def _read_os_release() -> str:
    text = _read_text(Path("/etc/os-release"))
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "Unknown"
