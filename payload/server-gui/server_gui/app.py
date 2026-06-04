"""Flask application factory for server-gui."""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from flask import Flask, redirect, session, url_for

from .auth import auth_bp, login_required
from .modules import admin as admin_module
from .modules import backup as backup_module
from .modules import certs as certs_module
from .modules import central_sso as central_sso_module
from .modules import ddns as ddns_module
from .modules import dhcp as dhcp_module
from .modules import dns as dns_module
from .modules import fail2ban as fail2ban_module
from .modules import firewall as firewall_module
from .modules import geoip as geoip_module
from .modules import ipsec as ipsec_module
from .modules import network as network_module
from .modules import nginx_proxy as nginx_module
from .modules import sophos_import as sophos_import_module
from .modules import system as system_module
from .modules import wireguard as wireguard_module


def create_app(config_dir: str | None = None) -> Flask:
    config_dir_path = Path(config_dir or os.environ.get("SERVER_GUI_CONFIG_DIR", "/etc/server-gui"))

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["CONFIG_DIR"] = config_dir_path
    app.config["SECRET_KEY"] = _load_or_create_secret(config_dir_path)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SERVER_GUI_INSECURE_COOKIE", "0") != "1"
    # Allow up to 50 MiB so the backup restore upload endpoint works.
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
    app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 8  # 8h

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app.register_blueprint(auth_bp)
    system_module.register(app)
    network_module.register(app)
    firewall_module.register(app)
    geoip_module.register(app)
    dns_module.register(app)
    dhcp_module.register(app)
    ipsec_module.register(app)
    wireguard_module.register(app)
    nginx_module.register(app)
    certs_module.register(app)
    fail2ban_module.register(app)
    ddns_module.register(app)
    backup_module.register(app)
    sophos_import_module.register(app)
    admin_module.register(app)
    central_sso_module.register(app)

    @app.route("/")
    @login_required
    def index():
        return redirect(url_for("system.dashboard"))

    @app.context_processor
    def inject_globals():
        return {"csrf_token": session.get("csrf_token", "")}

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # Don't let browsers cache server-rendered HTML — when we deploy a
        # template update the UI must reflect it without forcing the
        # operator to hard-refresh.
        ctype = response.headers.get("Content-Type", "")
        if ctype.startswith("text/html"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        # Content Security Policy:
        #   - Everything from self only — Bootstrap CSS/JS/icons are shipped
        #     under /static/vendor/ instead of fetched from a CDN.
        #   - Allow inline scripts (templates currently rely on this)
        #   - Connect only to self
        #   - No plugins (object-src none)
        #   - Frame ancestors none — pair with X-Frame-Options
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        return response

    return app


def _load_or_create_secret(config_dir: Path) -> bytes:
    config_dir.mkdir(parents=True, exist_ok=True)
    # Enforce restrictive perms on the config dir; it holds secrets
    # (session_secret, credentials.json, wireguard.json private keys, etc.)
    try:
        config_dir.chmod(0o700)
    except OSError:
        pass
    secret_file = config_dir / "session_secret"
    if secret_file.exists():
        try:
            secret_file.chmod(0o600)
        except OSError:
            pass
        return secret_file.read_bytes()
    data = secrets.token_bytes(48)
    secret_file.write_bytes(data)
    try:
        secret_file.chmod(0o600)
    except OSError:
        pass
    return data


if __name__ == "__main__":
    # Development entrypoint only. In production use gunicorn (see systemd unit).
    os.environ.setdefault("SERVER_GUI_INSECURE_COOKIE", "1")
    create_app().run(host="127.0.0.1", port=5010, debug=False)
