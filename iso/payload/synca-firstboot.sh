#!/usr/bin/env bash
# iso/payload/synca-firstboot.sh
# ASCII console firstboot configurator for SyncA UTM appliances.

set -euo pipefail

CONFIG_DIR="/etc/server-gui"
SYNC_DIR="/etc/synca"

bind_firstboot_tty() {
    local tty="${SYNCA_FIRSTBOOT_TTY:-/dev/tty1}"
    if [[ -z "${SYNCA_FIRSTBOOT_TTY_BOUND:-}" && -e "$tty" ]]; then
        export SYNCA_FIRSTBOOT_TTY_BOUND=1
        exec "$0" "$@" <"$tty" >"$tty" 2>&1
    fi
}

prompt() {
    # Read one line with a default. Prompts are ASCII for installer console
    # compatibility; Japanese is available later in the web GUI.
    local label="$1"
    local default="$2"
    local value
    read -r -p "${label} [${default}]: " value
    printf '%s' "${value:-$default}"
}

prompt_secret() {
    local label="$1"
    local value
    while [[ -z "${value:-}" ]]; do
        read -r -s -p "${label}: " value
        echo
    done
    printf '%s' "$value"
}

require_interface() {
    local name="$1"
    if ! nmcli -t -f DEVICE device status | grep -Fxq "$name"; then
        echo "Network interface not found: $name" >&2
        echo "Available interfaces:" >&2
        nmcli -t -f DEVICE,TYPE,STATE device status >&2 || true
        exit 1
    fi
}

list_ethernet_interfaces() {
    nmcli -t -f DEVICE,TYPE device status | awk -F: '$2 == "ethernet" {print $1}'
}

print_interface_table() {
    local exclude="${1:-}"
    local index=1
    local name state mac connection
    echo "Available ethernet interfaces:" >&2
    while IFS= read -r name; do
        [[ -z "$name" || "$name" == "$exclude" ]] && continue
        state="$(nmcli -g GENERAL.STATE device show "$name" 2>/dev/null | head -n1 || true)"
        mac="$(nmcli -g GENERAL.HWADDR device show "$name" 2>/dev/null | head -n1 || true)"
        connection="$(nmcli -g GENERAL.CONNECTION device show "$name" 2>/dev/null | head -n1 || true)"
        printf '  %d) %s  state=%s  mac=%s  connection=%s\n' \
            "$index" "$name" "${state:-unknown}" "${mac:--}" "${connection:---}" >&2
        index=$((index + 1))
    done < <(list_ethernet_interfaces)
}

select_interface() {
    local role="$1"
    local exclude="${2:-}"
    local choice count name index
    local -a names=()

    while IFS= read -r name; do
        [[ -z "$name" || "$name" == "$exclude" ]] && continue
        names+=("$name")
    done < <(list_ethernet_interfaces)

    count="${#names[@]}"
    if [[ "$count" -eq 0 ]]; then
        echo "No selectable ethernet interface found for ${role}." >&2
        exit 1
    fi

    while true; do
        print_interface_table "$exclude"
        read -r -p "Select ${role} interface by number or name: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            index=$((choice - 1))
            if [[ "$index" -ge 0 && "$index" -lt "$count" ]]; then
                printf '%s' "${names[$index]}"
                return 0
            fi
        else
            for name in "${names[@]}"; do
                if [[ "$choice" == "$name" ]]; then
                    printf '%s' "$name"
                    return 0
                fi
            done
        fi
        echo "Invalid ${role} interface selection: ${choice}" >&2
    done
}

cidr_ip() {
    printf '%s' "${1%/*}"
}

cidr_prefix() {
    printf '%s' "${1#*/}"
}

cidr_netmask() {
    # Converts common IPv4 CIDR prefixes used by appliance LANs.
    case "$(cidr_prefix "$1")" in
        8) echo "255.0.0.0" ;;
        16) echo "255.255.0.0" ;;
        24) echo "255.255.255.0" ;;
        25) echo "255.255.255.128" ;;
        26) echo "255.255.255.192" ;;
        27) echo "255.255.255.224" ;;
        28) echo "255.255.255.240" ;;
        29) echo "255.255.255.248" ;;
        30) echo "255.255.255.252" ;;
        *) echo "255.255.255.0" ;;
    esac
}

collect_config() {
    clear || true
    echo "SyncA UTM first boot setup"
    echo "Use ASCII input on this console. Japanese UI is available in the web GUI."
    echo
    SYSTEM_HOSTNAME="$(prompt "System hostname" "synca-utm")"
    ADMIN_USER="$(prompt "Linux sudo user" "loginuser")"
    ADMIN_PASS="$(prompt_secret "Linux sudo user password")"
    GUI_USER="$(prompt "GUI user" "$ADMIN_USER")"
    GUI_PASS="$(prompt_secret "GUI password")"
    ADMIN_CIDR="$(prompt "Management source CIDR" "0.0.0.0/0")"

    WAN_IF="$(select_interface "WAN")"
    echo
    LAN_IF="$(select_interface "LAN" "$WAN_IF")"
    echo
    require_interface "$WAN_IF"
    require_interface "$LAN_IF"

    WAN_MODE="$(prompt "WAN mode: dhcp/static/pppoe" "dhcp")"
    WAN_MODE="${WAN_MODE,,}"
    WAN_ADDRESS=""
    WAN_GATEWAY=""
    WAN_DNS="1.1.1.1,1.0.0.1"
    PPPOE_USER=""
    PPPOE_PASS=""

    case "$WAN_MODE" in
        static)
            WAN_ADDRESS="$(prompt "WAN static address CIDR" "192.0.2.2/24")"
            WAN_GATEWAY="$(prompt "WAN gateway" "192.0.2.1")"
            WAN_DNS="$(prompt "WAN DNS comma separated" "$WAN_DNS")"
            ;;
        pppoe)
            PPPOE_USER="$(prompt "PPPoE user" "")"
            PPPOE_PASS="$(prompt_secret "PPPoE password")"
            ;;
        dhcp) ;;
        *) echo "Invalid WAN mode: $WAN_MODE" >&2; exit 1 ;;
    esac

    LAN_CIDR="$(prompt "LAN address CIDR" "172.17.17.1/24")"
    DHCP_START="$(prompt "LAN DHCP start" "172.17.17.10")"
    DHCP_END="$(prompt "LAN DHCP end" "172.17.17.20")"
    WG_ADDR="$(prompt "WireGuard interface CIDR" "10.252.1.1/24")"
    WG_PORT="$(prompt "WireGuard listen port" "51820")"
    DDNS_LEFT="$(prompt "DDNS host left label, blank to skip" "")"
    DDNS_DOMAIN="ddnsft.com"
}

collect_auto_safe_config() {
    SYSTEM_HOSTNAME="${SYNCA_SYSTEM_HOSTNAME:-synca-utm}"
    ADMIN_USER="${SYNCA_ADMIN_USER:-loginuser}"
    ADMIN_PASS="${SYNCA_ADMIN_PASSWORD:-Asdf-1234}"
    GUI_USER="${SYNCA_GUI_USER:-$ADMIN_USER}"
    GUI_PASS="${SYNCA_GUI_PASSWORD:-$ADMIN_PASS}"
    ADMIN_CIDR="${SYNCA_ADMIN_CIDR:-0.0.0.0/0}"
    WAN_IF="${SYNCA_WAN_IF:-enp2s0}"
    LAN_IF="${SYNCA_LAN_IF:-enp3s0}"
    WAN_MODE="${SYNCA_WAN_MODE:-dhcp}"
    WAN_MODE="${WAN_MODE,,}"
    WAN_ADDRESS="${SYNCA_WAN_ADDRESS:-}"
    WAN_GATEWAY="${SYNCA_WAN_GATEWAY:-}"
    WAN_DNS="${SYNCA_WAN_DNS:-1.1.1.1,1.0.0.1}"
    PPPOE_USER="${SYNCA_PPPOE_USER:-}"
    PPPOE_PASS="${SYNCA_PPPOE_PASS:-}"
    LAN_CIDR="${SYNCA_LAN_CIDR:-172.17.17.1/24}"
    DHCP_START="${SYNCA_DHCP_START:-172.17.17.10}"
    DHCP_END="${SYNCA_DHCP_END:-172.17.17.20}"
    WG_ADDR="${SYNCA_WG_ADDR:-10.252.1.1/24}"
    WG_PORT="${SYNCA_WG_PORT:-51820}"
    DDNS_LEFT="${SYNCA_DDNS_LEFT:-}"
    DDNS_DOMAIN="ddnsft.com"
}

write_install_env() {
    install -d -m 0700 "$SYNC_DIR"
    cat > "${SYNC_DIR}/install.env" <<ENV
SYSTEM_HOSTNAME=${SYSTEM_HOSTNAME}
ADMIN_USER=${ADMIN_USER}
GUI_USER=${GUI_USER}
ADMIN_CIDR=${ADMIN_CIDR}
WAN_IF=${WAN_IF}
LAN_IF=${LAN_IF}
WAN_MODE=${WAN_MODE}
WAN_ADDRESS=${WAN_ADDRESS}
WAN_GATEWAY=${WAN_GATEWAY}
WAN_DNS=${WAN_DNS}
PPPOE_USER=${PPPOE_USER}
LAN_CIDR=${LAN_CIDR}
DHCP_START=${DHCP_START}
DHCP_END=${DHCP_END}
WG_ADDR=${WG_ADDR}
WG_PORT=${WG_PORT}
DDNS_LEFT=${DDNS_LEFT}
DDNS_DOMAIN=${DDNS_DOMAIN}
ENV
    chmod 0600 "${SYNC_DIR}/install.env"
}

configure_hostname() {
    hostnamectl set-hostname "$SYSTEM_HOSTNAME"
}

configure_users() {
    if ! id "$ADMIN_USER" >/dev/null 2>&1; then
        useradd -m -G wheel "$ADMIN_USER"
    else
        usermod -aG wheel "$ADMIN_USER"
    fi
    printf '%s:%s\n' "$ADMIN_USER" "$ADMIN_PASS" | chpasswd
    install -d -m 0750 /etc/sudoers.d
    echo "%wheel ALL=(ALL) ALL" > /etc/sudoers.d/10-synca-wheel
    chmod 0440 /etc/sudoers.d/10-synca-wheel
}

configure_network() {
    if [[ "${SYNCA_APPLY_LAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        nmcli connection delete synca-lan >/dev/null 2>&1 || true
        nmcli connection add type ethernet ifname "$LAN_IF" con-name synca-lan \
            ipv4.method manual ipv4.addresses "$LAN_CIDR" \
            connection.autoconnect yes connection.zone trusted
        nmcli connection up synca-lan || true
    fi

    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" != "1" ]]; then
        return 0
    fi

    nmcli connection delete synca-wan >/dev/null 2>&1 || true
    nmcli connection delete synca-pppoe >/dev/null 2>&1 || true
    case "$WAN_MODE" in
        dhcp)
            nmcli connection add type ethernet ifname "$WAN_IF" con-name synca-wan \
                ipv4.method auto connection.autoconnect yes connection.zone public
            nmcli connection up synca-wan || true
            ;;
        static)
            nmcli connection add type ethernet ifname "$WAN_IF" con-name synca-wan \
                ipv4.method manual ipv4.addresses "$WAN_ADDRESS" ipv4.gateway "$WAN_GATEWAY" \
                ipv4.dns "$WAN_DNS" connection.autoconnect yes connection.zone public
            nmcli connection up synca-wan || true
            ;;
        pppoe)
            nmcli connection add type pppoe ifname "$WAN_IF" con-name synca-pppoe \
                pppoe.username "$PPPOE_USER" pppoe.password "$PPPOE_PASS" \
                ppp.mtu 1492 ppp.mru 1492 connection.autoconnect yes connection.zone public
            nmcli connection up synca-pppoe || true
            ;;
    esac
}

write_server_gui_config() {
    local lan_ip endpoint_host netmask
    lan_ip="$(cidr_ip "$LAN_CIDR")"
    netmask="$(cidr_netmask "$LAN_CIDR")"
    endpoint_host="${DDNS_LEFT}.${DDNS_DOMAIN}"
    if [[ -z "$DDNS_LEFT" ]]; then
        endpoint_host="$lan_ip"
    fi

    install -d -m 0700 "$CONFIG_DIR"
    install -d -m 0755 /var/lib/server-gui/backups /var/log/server-gui

    PYTHONPATH=/opt/server-gui /opt/server-gui/venv/bin/python - <<PY
from pathlib import Path
from server_gui.auth import set_password
set_password(${GUI_USER@Q}, ${GUI_PASS@Q}, Path(${CONFIG_DIR@Q}))
PY

    cat > "${CONFIG_DIR}/ddns.json" <<'JSON'
{
  "check_url": "https://update.ddnsft.com/checkip.php",
  "current_ip": null,
  "last_check": null,
  "last_error": null,
  "overwrite_pin": null,
  "providers": []
}
JSON

    cat > "${CONFIG_DIR}/geoip.json" <<'JSON'
{
  "countries": [
    {"code": "jp", "name": "Japan", "ipset": "jp-ipv4", "zone": "japan", "adopted": false, "last_updated": null, "entry_count": 0}
  ]
}
JSON

    cat > "${CONFIG_DIR}/dnsmasq.json" <<JSON
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
      {"id": "lan-default", "interface": "${LAN_IF}", "start": "${DHCP_START}", "end": "${DHCP_END}", "netmask": "${netmask}", "lease": "4h"}
    ],
    "static_hosts": [],
    "options": [
      {"id": "router", "tag": "", "option": "router", "value": "${lan_ip}"},
      {"id": "dns", "tag": "", "option": "dns-server", "value": "${lan_ip}"}
    ]
  }
}
JSON

    cat > "${CONFIG_DIR}/wireguard.json" <<JSON
{
  "interfaces": [
    {"name": "wg0", "address": "${WG_ADDR}", "listen_port": ${WG_PORT}, "mtu": 1450, "endpoint": "${endpoint_host}:${WG_PORT}", "peers": []}
  ]
}
JSON

    cat > "${CONFIG_DIR}/nginx.json" <<'JSON'
{"backends": [], "vhosts": []}
JSON

    cat > "${CONFIG_DIR}/admin.json" <<'JSON'
{
  "github_url": "https://github.com/yoshinsk/SyncA_UTM",
  "branch": "main",
  "installed_sha": null,
  "last_check_at": null,
  "last_check_ok": null,
  "last_check_log": "",
  "last_apply_at": null,
  "last_apply_ok": null,
  "last_apply_log": ""
}
JSON
    chmod 0600 "${CONFIG_DIR}"/*.json
}

configure_wireguard() {
    install -d -m 0700 /etc/wireguard
    if [[ ! -f /etc/wireguard/server_private.key ]]; then
        wg genkey > /etc/wireguard/server_private.key
        chmod 0600 /etc/wireguard/server_private.key
    fi
    cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/wireguard/server_private.key)
MTU = 1450
CONF
    chmod 0600 /etc/wireguard/wg0.conf
}

configure_dnsmasq() {
    if [[ "${SYNCA_APPLY_LAN:-${SYNCA_APPLY_NETWORK:-1}}" != "1" ]]; then
        return 0
    fi
    local lan_ip netmask
    lan_ip="$(cidr_ip "$LAN_CIDR")"
    netmask="$(cidr_netmask "$LAN_CIDR")"
    install -d -m 0755 /etc/dnsmasq.d
    cat > /etc/dnsmasq.d/synca-lan.conf <<CONF
# Managed by SyncA UTM firstboot.
interface=${LAN_IF}
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},${netmask},4h
dhcp-option=option:router,${lan_ip}
dhcp-option=option:dns-server,${lan_ip}
server=1.1.1.1
server=1.0.0.1
domain-needed
bogus-priv
CONF
    systemctl enable dnsmasq
}

configure_nginx() {
    local lan_ip server_name
    lan_ip="$(cidr_ip "$LAN_CIDR")"
    server_name="${DDNS_LEFT}.${DDNS_DOMAIN}"
    [[ -z "$DDNS_LEFT" ]] && server_name="$lan_ip"

    install -d -m 0755 /etc/pki/server-gui /var/www/letsencrypt/.well-known/acme-challenge
    if [[ ! -f /etc/pki/server-gui/server-gui.crt ]]; then
        openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
            -subj "/CN=${server_name}" \
            -keyout /etc/pki/server-gui/server-gui.key \
            -out /etc/pki/server-gui/server-gui.crt
        chmod 0600 /etc/pki/server-gui/server-gui.key
    fi

    cat > /etc/nginx/conf.d/vhost-server-gui.conf <<NGINX
server {
    listen 4444 ssl;
    listen [::]:4444 ssl;
    server_name ${server_name};
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
    }
}
NGINX
}

configure_firewall() {
    cat > /etc/sysctl.d/99-synca-utm.conf <<'CONF'
net.ipv4.ip_forward = 1
CONF
    sysctl --system >/dev/null

    systemctl enable --now firewalld
    firewall-cmd --set-default-zone=public
    firewall-cmd --permanent --zone=public --add-service=ssh || true
    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        firewall-cmd --permanent --zone=public --add-interface="$WAN_IF" || true
    fi
    if [[ "${SYNCA_APPLY_LAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        firewall-cmd --permanent --zone=trusted --add-interface="$LAN_IF" || true
    fi
    if [[ "$ADMIN_CIDR" != "0.0.0.0/0" ]]; then
        firewall-cmd --permanent --zone=trusted --add-source="$ADMIN_CIDR" || true
    fi
    if [[ "${SYNCA_APPLY_LAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        firewall-cmd --permanent --zone=trusted --add-service=dhcp || true
        firewall-cmd --permanent --zone=trusted --add-service=dns || true
    fi
    firewall-cmd --permanent --zone=public --add-port=4444/tcp
    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        local nat_out_if="$WAN_IF"
        if [[ "$WAN_MODE" == "pppoe" ]]; then
            nat_out_if="ppp+"
        fi
        firewall-cmd --permanent --zone=public --add-port="${WG_PORT}/udp"
        firewall-cmd --permanent --zone=public --add-masquerade
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 1 -o "$nat_out_if" -j MASQUERADE || true
    fi
    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" && "$WAN_MODE" == "pppoe" ]]; then
        firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
    fi
    firewall-cmd --reload
}

start_services() {
    systemctl daemon-reload
    if [[ "${SYNCA_APPLY_LAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        systemctl enable dnsmasq
        systemctl start --no-block dnsmasq || true
    fi
    systemctl enable nginx server-gui
    systemctl start --no-block nginx server-gui || true
    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]]; then
        systemctl enable server-gui-ddns.timer server-gui-geoip.timer
        systemctl start --no-block server-gui-ddns.timer server-gui-geoip.timer || true
    fi
    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" == "1" ]] && systemctl list-unit-files wgui-worker.service >/dev/null 2>&1; then
        systemctl enable wgui-worker || true
        systemctl start --no-block wgui-worker || true
    fi
    nginx -t
}

main() {
    local mode="${1:---auto-safe}"
    case "$mode" in
        --interactive)
            bind_firstboot_tty "$@"
            export SYNCA_APPLY_NETWORK=1
            export SYNCA_APPLY_LAN=1
            export SYNCA_APPLY_WAN=1
            collect_config
            ;;
        --auto-safe)
            export SYNCA_APPLY_NETWORK="${SYNCA_APPLY_NETWORK:-0}"
            export SYNCA_APPLY_LAN="${SYNCA_APPLY_LAN:-1}"
            export SYNCA_APPLY_WAN="${SYNCA_APPLY_WAN:-0}"
            collect_auto_safe_config
            ;;
        *)
            echo "Usage: $0 [--auto-safe|--interactive]" >&2
            exit 2
            ;;
    esac
    write_install_env
    configure_hostname
    configure_users
    configure_network
    write_server_gui_config
    configure_wireguard
    configure_dnsmasq
    configure_nginx
    configure_firewall
    start_services
    touch "${SYNC_DIR}/firstboot.done"
    systemctl disable synca-firstboot.service || true
    echo
    echo "SyncA UTM setup complete."
    echo "GUI: https://$(cidr_ip "$LAN_CIDR"):4444/"
}

main "$@"
