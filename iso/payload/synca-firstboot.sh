#!/usr/bin/env bash
# iso/payload/synca-firstboot.sh
# ASCII console firstboot configurator for SyncA UTM appliances.

set -euo pipefail

CONFIG_DIR="/etc/server-gui"
SYNC_DIR="/etc/synca"
BACKTITLE="SyncA UTM initial setup"
FIRSTBOOT_LOG="/var/log/synca-firstboot-apply.log"
TTY_PATH="${SYNCA_FIRSTBOOT_TTY:-/dev/tty1}"

quiet_firstboot_console() {
    dmesg -n 1 >/dev/null 2>&1 || true
    if command -v setterm >/dev/null 2>&1 && [[ -e "$TTY_PATH" ]]; then
        setterm --msg off <"$TTY_PATH" >/dev/null 2>&1 || true
        setterm --blank 0 --powerdown 0 <"$TTY_PATH" >/dev/null 2>&1 || true
    fi
}

bind_firstboot_tty() {
    local tty="${SYNCA_FIRSTBOOT_TTY:-/dev/tty1}"
    if [[ -z "${SYNCA_FIRSTBOOT_TTY_BOUND:-}" && -e "$tty" ]]; then
        export SYNCA_FIRSTBOOT_TTY_BOUND=1
        quiet_firstboot_console
        exec "$0" "$@" <"$tty" >"$tty" 2>&1
    fi
    quiet_firstboot_console
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

has_dialog() {
    command -v dialog >/dev/null 2>&1
}

fatal() {
    local message="$1"
    if has_dialog; then
        dialog --backtitle "$BACKTITLE" --title "Error" --msgbox "$message" 12 70 || true
    else
        echo "$message" >&2
    fi
    exit 1
}

ui_message() {
    local title="$1"
    local message="$2"
    if has_dialog; then
        dialog --backtitle "$BACKTITLE" --title "$title" --msgbox "$message" 16 72
    else
        echo "$title"
        echo "$message"
        echo
    fi
}

ui_input() {
    local title="$1"
    local message="$2"
    local default="$3"
    local value
    if has_dialog; then
        value="$(dialog --stdout --backtitle "$BACKTITLE" --title "$title" --inputbox "$message" 12 72 "$default")" \
            || fatal "Setup cancelled."
        printf '%s' "${value:-$default}"
    else
        prompt "$title" "$default"
    fi
}

ui_password() {
    local title="$1"
    local message="$2"
    local value
    if has_dialog; then
        while [[ -z "${value:-}" ]]; do
            value="$(dialog --stdout --backtitle "$BACKTITLE" --title "$title" --insecure --passwordbox "$message" 10 72)" \
                || fatal "Setup cancelled."
        done
        printf '%s' "$value"
    else
        prompt_secret "$title"
    fi
}

ui_apply_started() {
    if has_dialog; then
        dialog --backtitle "$BACKTITLE" --title "Applying settings" --infobox \
            "Applying SyncA UTM settings.\n\nLogs: ${FIRSTBOOT_LOG}" 8 72 \
            >"$TTY_PATH" 2>&1 || true
    else
        echo "Applying SyncA UTM settings. Logs: ${FIRSTBOOT_LOG}" >"$TTY_PATH" 2>/dev/null || true
    fi
}

ui_apply_finished() {
    local message="SyncA UTM setup complete.\n\nGUI: https://$(cidr_ip "$LAN_CIDR"):4444/\n\nLogs: ${FIRSTBOOT_LOG}"
    if has_dialog; then
        dialog --backtitle "$BACKTITLE" --title "Complete" --infobox "$message\n\nContinuing in 5 seconds..." 12 72 \
            >"$TTY_PATH" 2>&1 || true
        sleep 5
    else
        printf '%b\n' "$message" >"$TTY_PATH" 2>/dev/null || true
    fi
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
    local -a menu_items=()

    while IFS= read -r name; do
        [[ -z "$name" || "$name" == "$exclude" ]] && continue
        names+=("$name")
    done < <(list_ethernet_interfaces)

    count="${#names[@]}"
    if [[ "$count" -eq 0 ]]; then
        fatal "No selectable ethernet interface found for ${role}."
    fi

    if has_dialog; then
        for name in "${names[@]}"; do
            local state mac connection
            state="$(nmcli -g GENERAL.STATE device show "$name" 2>/dev/null | head -n1 || true)"
            mac="$(nmcli -g GENERAL.HWADDR device show "$name" 2>/dev/null | head -n1 || true)"
            connection="$(nmcli -g GENERAL.CONNECTION device show "$name" 2>/dev/null | head -n1 || true)"
            menu_items+=("$name" "state=${state:-unknown} mac=${mac:--} con=${connection:---}")
        done
        dialog --stdout --backtitle "$BACKTITLE" --title "${role} interface" --menu \
            "Select the ${role} interface." 20 78 10 "${menu_items[@]}" || fatal "Setup cancelled."
        return 0
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

select_wan_mode() {
    if has_dialog; then
        dialog --stdout --backtitle "$BACKTITLE" --title "WAN mode" --menu \
            "Select the WAN connection method." 12 72 3 \
            "dhcp" "DHCP client" \
            "static" "Static IP address" \
            "pppoe" "PPPoE" || fatal "Setup cancelled."
    else
        prompt "WAN mode: dhcp/static/pppoe" "dhcp"
    fi
}

connection_names_for_interface() {
    local ifname="$1"
    {
        nmcli -t -f NAME,DEVICE connection show | awk -F: -v d="$ifname" '$2 == d {print $1}'
        nmcli -t -f NAME connection show | while IFS= read -r name; do
            [[ -z "$name" ]] && continue
            if [[ "$(nmcli -g connection.interface-name connection show "$name" 2>/dev/null || true)" == "$ifname" ]]; then
                printf '%s\n' "$name"
            fi
        done
    } | awk 'NF && !seen[$0]++'
}

delete_connections_for_interface() {
    local ifname="$1"
    local conn
    while IFS= read -r conn; do
        [[ -z "$conn" || "$conn" == "lo" ]] && continue
        nmcli connection down "$conn" >/dev/null 2>&1 || true
        nmcli connection delete "$conn" >/dev/null 2>&1 || true
    done < <(connection_names_for_interface "$ifname")
}

wait_for_carrier() {
    local ifname="$1"
    local i
    for i in {1..20}; do
        if [[ "$(cat "/sys/class/net/${ifname}/carrier" 2>/dev/null || echo 0)" == "1" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

activate_connection_with_retry() {
    local conn="$1"
    local tries="${2:-3}"
    local i
    for ((i = 1; i <= tries; i++)); do
        if nmcli connection up "$conn"; then
            return 0
        fi
        echo "warning: activation failed for ${conn}; retry ${i}/${tries}" >&2
        sleep 3
    done
    return 1
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
    ui_message "Welcome" "This wizard configures SyncA UTM for first use.

Use ASCII input on this console. Japanese UI is available later in the web GUI.

You will select WAN/LAN interfaces, WAN connection method, administrator account, and LAN defaults."

    SYSTEM_HOSTNAME="$(ui_input "System hostname" "Hostname for this machine." "synca-utm")"
    ADMIN_USER="$(ui_input "Linux sudo user" "Linux sudo user name." "loginuser")"
    ADMIN_PASS="$(ui_password "Linux sudo user password" "Password for the Linux sudo user.")"
    GUI_USER="$(ui_input "GUI user" "Web GUI user name." "$ADMIN_USER")"
    GUI_PASS="$(ui_password "GUI password" "Password for the Web GUI user.")"
    ADMIN_CIDR="$(ui_input "Management source CIDR" "CIDR allowed to manage this appliance. Use 0.0.0.0/0 for initial setup from any source." "0.0.0.0/0")"

    WAN_IF="$(select_interface "WAN")"
    echo
    LAN_IF="$(select_interface "LAN" "$WAN_IF")"
    echo
    require_interface "$WAN_IF"
    require_interface "$LAN_IF"

    WAN_MODE="$(select_wan_mode)"
    WAN_MODE="${WAN_MODE,,}"
    WAN_ADDRESS=""
    WAN_GATEWAY=""
    WAN_DNS="1.1.1.1,1.0.0.1"
    PPPOE_USER=""
    PPPOE_PASS=""

    case "$WAN_MODE" in
        static)
            WAN_ADDRESS="$(ui_input "WAN static address" "WAN static address in CIDR form." "192.0.2.2/24")"
            WAN_GATEWAY="$(ui_input "WAN gateway" "WAN default gateway." "192.0.2.1")"
            WAN_DNS="$(ui_input "WAN DNS" "WAN DNS servers, comma separated." "$WAN_DNS")"
            ;;
        pppoe)
            PPPOE_USER="$(ui_input "PPPoE user" "PPPoE username." "")"
            PPPOE_PASS="$(ui_password "PPPoE password" "PPPoE password.")"
            ;;
        dhcp) ;;
        *) fatal "Invalid WAN mode: $WAN_MODE" ;;
    esac

    LAN_CIDR="$(ui_input "LAN address" "LAN-side IP address in CIDR form." "172.17.17.1/24")"
    DHCP_START="$(ui_input "LAN DHCP start" "First DHCP address for LAN clients." "172.17.17.10")"
    DHCP_END="$(ui_input "LAN DHCP end" "Last DHCP address for LAN clients." "172.17.17.20")"
    WG_ADDR="$(ui_input "WireGuard address" "WireGuard interface address in CIDR form." "10.252.1.1/24")"
    WG_PORT="$(ui_input "WireGuard port" "WireGuard UDP listen port." "51820")"
    DDNS_LEFT="$(ui_input "DDNS host label" "ddnsft.com host label only. Leave blank to skip initial DDNS registration." "")"
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
        delete_connections_for_interface "$LAN_IF"
        nmcli connection delete synca-lan >/dev/null 2>&1 || true
        nmcli connection add type ethernet ifname "$LAN_IF" con-name synca-lan \
            ipv4.method manual ipv4.addresses "$LAN_CIDR" \
            ipv4.never-default yes ipv6.method ignore \
            connection.autoconnect yes connection.zone trusted
        activate_connection_with_retry synca-lan 2 || true
    fi

    if [[ "${SYNCA_APPLY_WAN:-${SYNCA_APPLY_NETWORK:-1}}" != "1" ]]; then
        return 0
    fi

    delete_connections_for_interface "$WAN_IF"
    nmcli connection delete synca-wan >/dev/null 2>&1 || true
    nmcli connection delete synca-pppoe >/dev/null 2>&1 || true
    wait_for_carrier "$WAN_IF" || echo "warning: carrier did not become ready on ${WAN_IF}" >&2
    case "$WAN_MODE" in
        dhcp)
            nmcli connection add type ethernet ifname "$WAN_IF" con-name synca-wan \
                ipv4.method auto ipv6.method ignore connection.autoconnect yes connection.zone public
            activate_connection_with_retry synca-wan 3 || true
            ;;
        static)
            nmcli connection add type ethernet ifname "$WAN_IF" con-name synca-wan \
                ipv4.method manual ipv4.addresses "$WAN_ADDRESS" ipv4.gateway "$WAN_GATEWAY" \
                ipv4.dns "$WAN_DNS" ipv6.method ignore connection.autoconnect yes connection.zone public
            activate_connection_with_retry synca-wan 3 || true
            ;;
        pppoe)
            nmcli connection add type pppoe ifname "$WAN_IF" con-name synca-pppoe \
                pppoe.username "$PPPOE_USER" pppoe.password "$PPPOE_PASS" \
                ppp.mtu 1454 ppp.mru 1454 ipv6.method ignore \
                connection.autoconnect yes connection.zone public
            activate_connection_with_retry synca-pppoe 4 || true
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
    if [[ -n "$DDNS_LEFT" && -n "${SYNCA_DDNSFT_AUTH_USER:-}" && -n "${SYNCA_DDNSFT_AUTH_PASS:-}" ]]; then
        python3 - <<PY
import json
from pathlib import Path

path = Path(${CONFIG_DIR@Q}) / "ddns.json"
data = json.loads(path.read_text(encoding="utf-8"))
data["providers"] = [{
    "id": "default-ddnsft",
    "name": ${DDNS_LEFT@Q},
    "enabled": True,
    "preset_type": "ddnsft",
    "template": "https://update.ddnsft.com/update/update.php?host={account}&dm={domain}&ip={ip}",
    "account": ${DDNS_LEFT@Q},
    "domain": ${DDNS_DOMAIN@Q},
    "auth_user": ${SYNCA_DDNSFT_AUTH_USER@Q},
    "auth_pass": ${SYNCA_DDNSFT_AUTH_PASS@Q},
}]
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
    fi

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
        firewall-cmd --permanent --direct --add-rule ipv4 mangle FORWARD 0 -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
        firewall-cmd --permanent --direct --add-rule ipv4 mangle FORWARD 0 -i ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
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
    ui_apply_started
    install -d -m 0755 "$(dirname "$FIRSTBOOT_LOG")"
    exec >>"$FIRSTBOOT_LOG" 2>&1
    echo "SyncA UTM firstboot apply started at $(date -Is)"
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
    echo "SyncA UTM firstboot apply completed at $(date -Is)"
    ui_apply_finished
}

main "$@"
