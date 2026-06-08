#!/usr/bin/env bash
# scripts/bootstrap-synca-testhost.sh - Bootstrap SyncA UTM GUI on an AlmaLinux 9.8 test host.

set -euo pipefail

# Test-host defaults. The ISO installer must collect these values interactively;
# this script keeps them explicit so the current physical test can be repeated.
GUI_USER="${GUI_USER:-loginuser}"
GUI_PASS="${GUI_PASS:-}"
DDNS_HOST="${DDNS_HOST:-synca}"
DDNS_DOMAIN="${DDNS_DOMAIN:-ddnsft.com}"
LAN_IF="${LAN_IF:-enp3s0}"
WAN_IF="${WAN_IF:-enp2s0}"
LAN_CIDR="${LAN_CIDR:-172.17.17.1/24}"
LAN_IP="${LAN_CIDR%/*}"
DHCP_START="${DHCP_START:-172.17.17.20}"
DHCP_END="${DHCP_END:-172.17.17.120}"
WG_ADDR="${WG_ADDR:-10.252.1.1/24}"
WG_PORT="${WG_PORT:-51820}"
APP_ARCHIVE="${APP_ARCHIVE:-/tmp/server-gui-payload-testhost.tar.gz}"
WGUI_BINARY="${WGUI_BINARY:-/tmp/wireguard-ui}"
SYNCA_INSTALLED_SHA="${SYNCA_INSTALLED_SHA:-}"

require_root() {
    # Root is required because the script writes /opt, /etc, systemd, firewalld,
    # nginx, and WireGuard runtime configuration.
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "run as root" >&2
        exit 1
    fi
}

require_config() {
    # Credentials are intentionally not defaulted because this repository is
    # public. The installer should collect them interactively.
    if [[ -z "$GUI_PASS" ]]; then
        echo "GUI_PASS is required" >&2
        exit 1
    fi
}

install_application_tree() {
    # Replace only the application tree created by this bootstrap. Runtime
    # config lives under /etc/server-gui and is generated separately below.
    install -d -m 0755 /opt
    rm -rf /opt/server-gui
    tar -xzf "$APP_ARCHIVE" -C /opt
    chown -R root:root /opt/server-gui
    chmod 0755 /opt/server-gui

    python3 -m venv /opt/server-gui/venv
    /opt/server-gui/venv/bin/pip install --upgrade pip setuptools wheel
    /opt/server-gui/venv/bin/pip install -r /opt/server-gui/requirements.txt
    chmod +x /opt/server-gui/bin/*
}

install_wireguard_ui() {
    # The current product uses wireguard-ui as a local binary service behind
    # nginx. Database/state directories are created up front for predictable
    # ownership and backup coverage.
    install -d -m 0755 /opt/wireguard/db
    install -m 0755 "$WGUI_BINARY" /opt/wireguard/wireguard-ui
}

write_server_gui_config() {
    # Generate the minimum config set needed for login, DDNS, GeoIP, DHCP/DNS,
    # WireGuard, nginx proxy inventory, and update status pages.
    install -d -m 0700 /etc/server-gui
    install -d -m 0755 /var/lib/server-gui/backups /var/log/server-gui

    PYTHONPATH=/opt/server-gui /opt/server-gui/venv/bin/python - <<PY
from pathlib import Path
from server_gui.auth import set_password
set_password(${GUI_USER@Q}, ${GUI_PASS@Q}, Path("/etc/server-gui"))
PY

    cat > /etc/server-gui/ddns.json <<JSON
{
  "check_url": "https://update.ddnsft.com/checkip.php",
  "current_ip": null,
  "last_check": null,
  "last_error": null,
  "overwrite_pin": null,
  "providers": []
}
JSON

    cat > /etc/server-gui/geoip.json <<JSON
{
  "countries": [
    {
      "code": "jp",
      "name": "Japan",
      "ipset": "jp-ipv4",
      "zone": "japan",
      "adopted": false,
      "last_updated": null,
      "entry_count": 0
    }
  ],
  "dynamic_ipsets": [
    {
      "id": "acrobits-sipis",
      "name": "Acrobits SIPIS",
      "ipset": "acrobits-sipis-ipv4",
      "hostname": "all.sipis.acrobits.cz",
      "resolver": "getent-ahostsv4",
      "last_updated": null,
      "entry_count": 0,
      "source": "DNS A records for all.sipis.acrobits.cz"
    }
  ]
}
JSON

    cat > /etc/server-gui/dnsmasq.json <<JSON
{
  "dns": {
    "hosts": [],
    "cnames": [],
    "upstream": [
      {"id": "cloudflare-1", "domain": "", "server": "1.1.1.1"},
      {"id": "cloudflare-2", "domain": "", "server": "1.0.0.1"}
    ]
  },
  "dhcp": {
    "ranges": [
      {
        "id": "lan-default",
        "interface": "${LAN_IF}",
        "start": "${DHCP_START}",
        "end": "${DHCP_END}",
        "netmask": "255.255.255.0",
        "lease": "4h"
      }
    ],
    "static_hosts": [],
    "options": [
      {"id": "router", "tag": "", "option": "router", "value": "${LAN_IP}"},
      {"id": "dns", "tag": "", "option": "dns-server", "value": "${LAN_IP},1.1.1.1,1.0.0.1"}
    ]
  }
}
JSON

    cat > /etc/server-gui/wireguard.json <<JSON
{
  "interfaces": [
    {
      "name": "wg0",
      "address": "${WG_ADDR}",
      "listen_port": ${WG_PORT},
      "mtu": 1450,
      "endpoint": "${DDNS_HOST}.${DDNS_DOMAIN}:${WG_PORT}",
      "peers": []
    }
  ]
}
JSON

    cat > /etc/server-gui/nginx.json <<'JSON'
{
  "backends": [],
  "vhosts": []
}
JSON

    local installed_sha_json
    if [[ "$SYNCA_INSTALLED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
        installed_sha_json="\"$SYNCA_INSTALLED_SHA\""
    else
        installed_sha_json="null"
    fi

    cat > /etc/server-gui/admin.json <<JSON
{
  "github_url": "https://github.com/yoshinsk/SyncA_UTM",
  "branch": "main",
  "installed_sha": ${installed_sha_json},
  "last_check_at": null,
  "last_check_ok": null,
  "last_check_log": "",
  "last_apply_at": null,
  "last_apply_ok": null,
  "last_apply_log": ""
}
JSON

    SYNCA_CONFIG_DIR="/etc/server-gui" python3 - <<'PY'
import json
import os
from pathlib import Path

central_url = os.environ.get("SYNCA_CENTRAL_URL", "https://nsksys.com/syncautm/admin").strip().rstrip("/")
enrollment_token = os.environ.get("SYNCA_CENTRAL_ENROLLMENT_TOKEN", "").strip()
enabled = os.environ.get("SYNCA_CENTRAL_ENABLED", "1") not in ("0", "false", "False", "no", "No")
version_id = ""
try:
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION_ID="):
            version_id = line.split("=", 1)[1].strip().strip('"')
            break
except OSError:
    pass

path = Path(os.environ["SYNCA_CONFIG_DIR"]) / "central.json"
data = {
    "enabled": enabled,
    "central_url": central_url,
    "device_id": "",
    "api_secret": "",
    "sso_secret": "",
    "enrollment_token": enrollment_token,
    "gui_url": os.environ.get("SYNCA_CENTRAL_GUI_URL", "").strip(),
    "family": os.environ.get("SYNCA_CENTRAL_FAMILY", version_id).strip(),
    "backup_enabled": os.environ.get("SYNCA_CENTRAL_BACKUP_ENABLED", "1") not in ("0", "false", "False", "no", "No"),
}
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

    chmod 0600 /etc/server-gui/*.json
}

write_wireguard_config() {
    # Create a server key and a basic wg0 interface. Peers are intentionally
    # empty for this first bootstrap; the GUI can add them later.
    install -d -m 0700 /etc/wireguard
    if [[ ! -f /etc/wireguard/server_private.key ]]; then
        wg genkey > /etc/wireguard/server_private.key
        chmod 0600 /etc/wireguard/server_private.key
    fi
    local private_key
    private_key="$(cat /etc/wireguard/server_private.key)"
    cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${private_key}
MTU = 1450
CONF
    chmod 0600 /etc/wireguard/wg0.conf
}

install_modsecurity_config() {
    # Prepare the ModSecurity rule entrypoint expected by the GUI. The ISO must
    # install nginx-mod-modsecurity, mod_security, and mod_security_crs before
    # this file can be used by a vhost.
    install -d -m 0755 /etc/nginx/modsec
    cat > /etc/nginx/modsec/main.conf <<'CONF'
# Managed by SyncA UTM installer.
# Enables the packaged ModSecurity v2 engine and OWASP CRS on AlmaLinux 9.
Include /etc/nginx/modsecurity.conf
SecRuleEngine On
Include /etc/httpd/modsecurity.d/crs-setup.conf
Include /etc/httpd/modsecurity.d/activated_rules/*.conf
CONF
}

write_nginx_config() {
    # Use a self-signed certificate for the bootstrap. Let's Encrypt can be
    # tested only after PPPoE/DDNS reachability is confirmed.
    install -d -m 0755 /etc/pki/server-gui
    install -d -m 0755 /var/www/letsencrypt/.well-known/acme-challenge
    if [[ ! -f /etc/pki/server-gui/server-gui.crt ]]; then
        openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
            -subj "/CN=${DDNS_HOST}.${DDNS_DOMAIN}" \
            -keyout /etc/pki/server-gui/server-gui.key \
            -out /etc/pki/server-gui/server-gui.crt
        chmod 0600 /etc/pki/server-gui/server-gui.key
    fi

    cat > /etc/nginx/conf.d/vhost-server-gui.conf <<NGINX
server {
    listen 4444 ssl;
    listen [::]:4444 ssl;
    server_name ${DDNS_HOST}.${DDNS_DOMAIN};

    ssl_certificate /etc/pki/server-gui/server-gui.crt;
    ssl_certificate_key /etc/pki/server-gui/server-gui.key;
    client_max_body_size 64m;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        proxy_pass http://127.0.0.1:5010;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_connect_timeout 180s;
        proxy_send_timeout 180s;
        proxy_read_timeout 180s;
    }
}
NGINX

    cat > /etc/nginx/conf.d/vhost-ssl_wireguardui.conf <<NGINX
server {
    listen 5011 ssl;
    listen [::]:5011 ssl;
    server_name ${DDNS_HOST}.${DDNS_DOMAIN};

    ssl_certificate /etc/pki/server-gui/server-gui.crt;
    ssl_certificate_key /etc/pki/server-gui/server-gui.key;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
    }
}
NGINX
}

write_systemd_units() {
    # These units mirror the manually built appliance closely enough for test
    # validation and later ISO conversion.
    cat > /etc/systemd/system/server-gui.service <<'UNIT'
[Unit]
Description=Server GUI - AlmaLinux router management
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/server-gui
Environment=SERVER_GUI_CONFIG_DIR=/etc/server-gui
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/server-gui/venv/bin/gunicorn --bind 127.0.0.1:5010 --workers 2 --timeout 180 --access-logfile - --error-logfile - 'server_gui.app:create_app()'
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

    cat > /etc/systemd/system/wgui-worker.service <<'UNIT'
[Unit]
Description=wireguard web ui
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/wireguard
ExecStart=/opt/wireguard/wireguard-ui
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

    cat > /etc/systemd/system/server-gui-ddns.service <<'UNIT'
[Unit]
Description=server-gui DDNS update check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/server-gui/bin/ddns-check
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/server-gui-ddns.timer <<'UNIT'
[Unit]
Description=Run server-gui DDNS update check periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    cat > /etc/systemd/system/server-gui-geoip.service <<'UNIT'
[Unit]
Description=server-gui GeoIP ipset refresh
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/server-gui/bin/geoip-update
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/server-gui-geoip.timer <<'UNIT'
[Unit]
Description=Run server-gui GeoIP ipset refresh periodically

[Timer]
OnBootSec=3min
OnUnitActiveSec=1w
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    cat > /etc/systemd/system/server-gui-backup.service <<'UNIT'
[Unit]
Description=server-gui local configuration backup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/server-gui
Environment=SERVER_GUI_CONFIG_DIR=/etc/server-gui
ExecStart=/opt/server-gui/bin/backup-create
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/server-gui-backup.timer <<'UNIT'
[Unit]
Description=Run server-gui local backup daily

[Timer]
OnBootSec=10min
OnCalendar=*-*-* 03:10:00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    cat > /etc/systemd/system/server-gui-update-check.service <<'UNIT'
[Unit]
Description=server-gui GitHub update check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/server-gui
Environment=SERVER_GUI_CONFIG_DIR=/etc/server-gui
ExecStart=/opt/server-gui/bin/update-check
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/server-gui-update-check.timer <<'UNIT'
[Unit]
Description=Run server-gui GitHub update check daily

[Timer]
OnBootSec=15min
OnCalendar=*-*-* 04:10:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    cat > /etc/systemd/system/synca-central-report.service <<'UNIT'
[Unit]
Description=SyncA UTM 集中管理 状態送信
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/server-gui/bin/central-agent --report
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/synca-central-report.timer <<'UNIT'
[Unit]
Description=SyncA UTM 集中管理 状態送信タイマー

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    cat > /etc/systemd/system/synca-central-backup.service <<'UNIT'
[Unit]
Description=SyncA UTM 集中管理 バックアップ送信
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/opt/server-gui/bin/central-agent --backup-upload
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/synca-central-backup.timer <<'UNIT'
[Unit]
Description=SyncA UTM 集中管理 バックアップ送信タイマー

[Timer]
OnBootSec=10min
OnCalendar=*-*-* 03:20:00
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
}

configure_firewall_for_bootstrap() {
    # Keep current SSH reachability intact. At this phase enp3s0 still carries
    # the temporary management network, so only add management ports.
    systemctl enable --now firewalld
    firewall-cmd --permanent --add-port=4444/tcp
    firewall-cmd --permanent --add-port=5011/tcp
    firewall-cmd --permanent --add-port="${WG_PORT}/udp"
    firewall-cmd --reload
}

configure_selinux_compatibility() {
    # Production history used SELinux disabled via kernel arg. For the live test
    # host, make the current boot permissive and persist disabled for the next
    # reboot so service behavior matches the existing appliance.
    setenforce 0 || true
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    grubby --update-kernel ALL --args selinux=0 || true
}

start_services() {
    # Do not start dnsmasq DHCP until LAN IP migration is intentionally run.
    systemctl daemon-reload
    systemctl enable --now server-gui nginx wgui-worker
    systemctl enable --now server-gui-ddns.timer server-gui-geoip.timer server-gui-backup.timer server-gui-update-check.timer
    local central_enabled="${SYNCA_CENTRAL_ENABLED:-1}"
    local central_url="${SYNCA_CENTRAL_URL:-https://nsksys.com/syncautm/admin}"
    if [[ "$central_enabled" != "0" && "$central_enabled" != "false" && "$central_enabled" != "False" && "$central_enabled" != "no" && "$central_enabled" != "No" && -n "$central_url" && -n "${SYNCA_CENTRAL_ENROLLMENT_TOKEN:-}" ]]; then
        systemctl enable --now synca-central-report.timer synca-central-backup.timer
    fi
    nginx -t
}

main() {
    require_root
    require_config
    install_application_tree
    install_wireguard_ui
    write_server_gui_config
    write_wireguard_config
    install_modsecurity_config
    write_nginx_config
    write_systemd_units
    configure_firewall_for_bootstrap
    configure_selinux_compatibility
    start_services
    echo "bootstrap complete: https://$(hostname -I | awk '{print $1}'):4444/"
}

main "$@"
