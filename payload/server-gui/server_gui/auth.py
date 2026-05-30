"""Session-based authentication with CSRF protection and rate limiting."""
from __future__ import annotations

import hmac
import json
import logging
import secrets
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path
from typing import Callable

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

_failures: dict[str, list[float]] = defaultdict(list)
_FAILURE_WINDOW = 60.0
_FAILURE_LIMIT = 5


def _credentials_path() -> Path:
    return Path(current_app.config["CONFIG_DIR"]) / "credentials.json"


def _load_credentials() -> dict | None:
    p = _credentials_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.error("failed to load credentials: %s", e)
        return None


def set_password(username: str, password: str, config_dir: Path) -> None:
    """Initial password setup (used by installer / passwd helper)."""
    p = Path(config_dir) / "credentials.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {"username": username, "password_hash": generate_password_hash(password)}
    p.write_text(json.dumps(data), encoding="utf-8")
    p.chmod(0o600)


def _record_failure(ip: str) -> bool:
    now = time.time()
    bucket = _failures[ip]
    _failures[ip] = [t for t in bucket if now - t < _FAILURE_WINDOW]
    _failures[ip].append(now)
    return len(_failures[ip]) > _FAILURE_LIMIT


def _clear_failures(ip: str) -> None:
    _failures.pop(ip, None)


def login_required(f: Callable) -> Callable:
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/") or "/api/" in request.path:
                return jsonify({"error": "not authenticated"}), 401
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def csrf_protect(f: Callable) -> Callable:
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            provided = request.headers.get("X-CSRF-Token")
            if not provided and request.is_json:
                payload = request.get_json(silent=True) or {}
                provided = payload.get("_csrf")
            stored = session.get("csrf_token", "")
            if not provided or not stored or not hmac.compare_digest(str(provided), stored):
                return jsonify({"error": "invalid CSRF token"}), 403
        return f(*args, **kwargs)
    return wrapper


def _new_csrf_token() -> str:
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    if request.method == "POST":
        if _record_failure(ip):
            logger.warning("rate limit hit for %s", ip)
            return render_template("login.html", error="Too many attempts, retry in 1 minute"), 429
        creds = _load_credentials()
        if creds is None:
            return render_template("login.html", error="Not initialized. Run the installer first."), 500
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == creds["username"] and check_password_hash(creds["password_hash"], password):
            _clear_failures(ip)
            session.clear()
            session["user"] = username
            _new_csrf_token()
            next_url = request.args.get("next") or "/"
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = "/"
            return redirect(next_url)
        logger.warning("failed login for user=%r from %s", username, ip)
        return render_template("login.html", error="Invalid credentials"), 401
    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
