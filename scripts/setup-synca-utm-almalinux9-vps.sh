#!/usr/bin/env bash
# scripts/setup-synca-utm-almalinux9-vps.sh
# Online setup script for SyncA UTM 9.x on VPS hosts with existing WAN/LAN IPv4 settings.

set -euo pipefail
umask 077

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
REPO_CANDIDATE="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd || true)"

CLI_ENV_FILE=""
CLI_SOURCE_DIR=""
CLI_SOURCE_REF=""
CLI_REPO_URL=""

log() {
    printf '[%s] %s\n' "$(date -Is)" "$*"
}

warn() {
    printf '[%s] warning: %s\n' "$(date -Is)" "$*" >&2
}

die() {
    printf '[%s] error: %s\n' "$(date -Is)" "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage:
  sudo bash scripts/setup-synca-utm-almalinux9-vps.sh [options]

Options:
  --env-file PATH     Load private setup values from PATH.
  --source-dir PATH   Use an existing SyncA_UTM checkout instead of cloning.
  --source-ref REF    Git branch/tag/commit to clone. Default: main.
  --repo-url URL      Git repository URL. Default: https://github.com/yoshinsk/SyncA_UTM.git.
  -h, --help          Show this help.

Important environment variables:
  SYNCA_ADMIN_PASSWORD              Required unless run from an interactive TTY.
  SYNCA_WAN_IF / SYNCA_LAN_IF       Existing WAN/LAN NetworkManager device names.
  SYNCA_LAN_CIDR                    Existing LAN IPv4 address in CIDR form.
  SYNCA_DDNS_LEFT                   ddnsft.com host label, without domain.
  SYNCA_DDNSFT_AUTH_USER/PASS       DDNS update authentication.
  SYNCA_CENTRAL_ENROLLMENT_TOKEN    Central automatic enrollment token.
  SYNCA_DDNS_PIN_SMTP_*             SMTP settings for DDNS overwrite PIN mail.
  SYNCA_INTERNAL_SECRETS_DIR         Internal ISO secrets root. Default: output/internal-secrets when present.
  SYNCA_TIMEZONE                     System timezone. Default: Asia/Tokyo, matching the internal ISO.
USAGE
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --env-file)
                [[ $# -ge 2 ]] || die "--env-file requires a path"
                CLI_ENV_FILE="$2"
                shift 2
                ;;
            --source-dir)
                [[ $# -ge 2 ]] || die "--source-dir requires a path"
                CLI_SOURCE_DIR="$2"
                shift 2
                ;;
            --source-ref)
                [[ $# -ge 2 ]] || die "--source-ref requires a value"
                CLI_SOURCE_REF="$2"
                shift 2
                ;;
            --repo-url)
                [[ $# -ge 2 ]] || die "--repo-url requires a URL"
                CLI_REPO_URL="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1"
                ;;
        esac
    done
}

require_root() {
    # This script installs RPMs, writes /opt and /etc, and controls systemd.
    [[ "$(id -u)" -eq 0 ]] || die "run this script as root"
}

load_env_file() {
    local env_file="${CLI_ENV_FILE:-${SYNCA_SETUP_ENV_FILE:-}}"
    if [[ -z "$env_file" && -f /root/synca-utm-setup.env ]]; then
        env_file="/root/synca-utm-setup.env"
    fi
    [[ -z "$env_file" ]] && return 0
    [[ -f "$env_file" ]] || die "env file does not exist: $env_file"
    # shellcheck disable=SC1090
    set -a
    . "$env_file"
    set +a
    log "Loaded setup environment: $env_file"
}

apply_cli_overrides() {
    [[ -n "$CLI_SOURCE_DIR" ]] && SYNCA_SOURCE_DIR="$CLI_SOURCE_DIR"
    [[ -n "$CLI_SOURCE_REF" ]] && SYNCA_SOURCE_REF="$CLI_SOURCE_REF"
    [[ -n "$CLI_REPO_URL" ]] && SYNCA_REPO_URL="$CLI_REPO_URL"
    return 0
}

start_logging() {
    local log_file="${SYNCA_SETUP_LOG:-/var/log/synca-utm-vps-setup.log}"
    install -d -m 0755 "$(dirname "$log_file")"
    touch "$log_file"
    chmod 0600 "$log_file"
    exec > >(tee -a "$log_file") 2>&1
    log "SyncA UTM VPS setup started"
    log "Log file: $log_file"
}

is_truthy() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

shell_env_quote() {
    local value="$1"
    printf "'%s'" "${value//\'/\'\\\'\'}"
}

is_placeholder_env_value() {
    local key="$1"
    local value="$2"
    case "$key" in
        SYNCA_CENTRAL_ENROLLMENT_TOKEN)
            case "$value" in
                ""|"集中管理トークン"|"<"*">"|"CHANGE_ME"|"changeme"|"token"|"TOKEN")
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

systemd_env_value() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

write_env_assignment() {
    local key="$1"
    local value=""
    if [[ -v $key ]]; then
        value="${!key}"
    fi
    [[ -n "$value" ]] || return 0
    if is_placeholder_env_value "$key" "$value"; then
        warn "ignoring placeholder value for $key; keeping private ISO value when available"
        return 0
    fi
    printf '%s=%s\n' "$key" "$(shell_env_quote "$value")"
}

write_systemd_environment_line() {
    local key="$1"
    local value=""
    if [[ -v $key ]]; then
        value="${!key}"
    fi
    [[ -n "$value" ]] || return 0
    printf 'Environment="%s=%s"\n' "$key" "$(systemd_env_value "$value")"
}

os_release_value() {
    local key="$1"
    awk -F= -v k="$key" '$1 == k {gsub(/^"|"$/, "", $2); print $2; exit}' /etc/os-release
}

validate_os() {
    local os_id version_id major
    os_id="$(os_release_value ID)"
    version_id="$(os_release_value VERSION_ID)"
    major="${version_id%%.*}"

    [[ "$os_id" == "almalinux" ]] || die "unsupported OS ID: ${os_id:-unknown}; AlmaLinux 9.x is required"
    [[ "$major" == "9" ]] || die "unsupported AlmaLinux major version: ${version_id:-unknown}; AlmaLinux 9.x is required"
    if [[ "$version_id" != "9.8" ]]; then
        warn "tested target is AlmaLinux 9.8; continuing on VERSION_ID=${version_id}"
    fi
}

enable_repositories() {
    # Install the small bootstrap set first. The full feature package set is
    # read from the repository after git is available.
    log "Installing bootstrap packages and enabling EPEL/CRB"
    dnf install -y dnf-plugins-core ca-certificates curl git tar python3 python3-pip policycoreutils-python-utils >/dev/null
    dnf config-manager --set-enabled crb >/dev/null 2>&1 || warn "could not enable CRB repository"
    if ! rpm -q epel-release >/dev/null 2>&1; then
        dnf install -y epel-release >/dev/null || \
            dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm" >/dev/null
    fi
    dnf makecache -y --refresh >/dev/null
}

resolve_source_tree() {
    local checkout_dir="${SYNCA_CHECKOUT_DIR:-/opt/synca-utm-source}"
    SYNCA_REPO_URL="${SYNCA_REPO_URL:-https://github.com/yoshinsk/SyncA_UTM.git}"
    SYNCA_SOURCE_REF="${SYNCA_SOURCE_REF:-main}"

    if [[ -n "${SYNCA_SOURCE_DIR:-}" ]]; then
        [[ -d "$SYNCA_SOURCE_DIR/payload/server-gui" ]] || die "invalid SYNCA_SOURCE_DIR: $SYNCA_SOURCE_DIR"
        SOURCE_ROOT="$(readlink -f "$SYNCA_SOURCE_DIR")"
    elif [[ -n "$REPO_CANDIDATE" && -d "$REPO_CANDIDATE/payload/server-gui" ]]; then
        SOURCE_ROOT="$REPO_CANDIDATE"
    else
        rm -rf "$checkout_dir"
        git clone --depth 1 --branch "$SYNCA_SOURCE_REF" "$SYNCA_REPO_URL" "$checkout_dir"
        SOURCE_ROOT="$checkout_dir"
    fi

    SOURCE_SHA="$(git -C "$SOURCE_ROOT" rev-parse --verify HEAD 2>/dev/null || true)"
    if [[ -z "$SOURCE_SHA" && -r "$SOURCE_ROOT/.synca-source-sha" ]]; then
        SOURCE_SHA="$(tr -d '[:space:]' < "$SOURCE_ROOT/.synca-source-sha")"
    fi
    if [[ -z "$SOURCE_SHA" && -n "${SYNCA_SOURCE_SHA:-}" ]]; then
        SOURCE_SHA="$SYNCA_SOURCE_SHA"
    fi
    [[ -n "$SOURCE_SHA" ]] || warn "source tree has no git SHA; installed_sha will be empty"
    log "Source tree: $SOURCE_ROOT"
    log "Source ref: ${SYNCA_SOURCE_REF}"
    [[ -n "$SOURCE_SHA" ]] && log "Source SHA: $SOURCE_SHA"
    return 0
}

resolve_internal_secret_defaults() {
    local secrets_dir="${SYNCA_INTERNAL_SECRETS_DIR:-$SOURCE_ROOT/output/internal-secrets}"
    if is_truthy "${SYNCA_DISABLE_INTERNAL_SECRET_AUTODETECT:-0}"; then
        return 0
    fi

    if [[ -z "${SYNCA_PRIVATE_FIRSTBOOT_ENV:-}" && -f "$secrets_dir/generated/firstboot-9.env" ]]; then
        SYNCA_PRIVATE_FIRSTBOOT_ENV="$secrets_dir/generated/firstboot-9.env"
        log "Using internal firstboot environment from current ISO secrets."
    fi
    if [[ -z "${SYNCA_PRIVATE_SMTP_DROPIN:-}" && -f "$secrets_dir/server-gui-ddns-smtp.conf" ]]; then
        SYNCA_PRIVATE_SMTP_DROPIN="$secrets_dir/server-gui-ddns-smtp.conf"
        log "Using internal SMTP drop-in from current ISO secrets."
    fi
    if is_truthy "${SYNCA_REQUIRE_INTERNAL_SECRETS:-0}"; then
        [[ -n "${SYNCA_PRIVATE_FIRSTBOOT_ENV:-}" && -f "$SYNCA_PRIVATE_FIRSTBOOT_ENV" ]] || \
            die "internal firstboot environment was required but not found"
        [[ -n "${SYNCA_PRIVATE_SMTP_DROPIN:-}" && -f "$SYNCA_PRIVATE_SMTP_DROPIN" ]] || \
            die "internal SMTP drop-in was required but not found"
    fi
}

install_feature_packages() {
    local package_file="$SOURCE_ROOT/iso/package-lists/synca-rpms.txt"
    local package
    local -a packages=()
    [[ -f "$package_file" ]] || die "package list not found: $package_file"

    while IFS= read -r package; do
        package="${package%%#*}"
        package="${package//[[:space:]]/}"
        [[ -z "$package" ]] && continue
        case "$package" in
            efibootmgr|grub2-*|kernel|kbd|kbd-misc|lvm2|rootfiles|xfsprogs)
                continue
                ;;
        esac
        packages+=("$package")
    done < "$package_file"

    log "Installing SyncA UTM feature packages (${#packages[@]} RPM goals)"
    dnf install -y --setopt=install_weak_deps=False "${packages[@]}"
}

enable_time_sync() {
    # A correct clock is required before GitHub, DDNS, GeoIP, and central HTTPS
    # calls can validate certificates.
    local timezone="${SYNCA_TIMEZONE:-Asia/Tokyo}"
    log "Configuring timezone and chrony time synchronization"
    if [[ -n "$timezone" ]]; then
        if [[ -e "/usr/share/zoneinfo/$timezone" ]]; then
            timedatectl set-timezone "$timezone" >/dev/null 2>&1 || warn "could not set timezone: $timezone"
        else
            warn "timezone data not found: $timezone"
        fi
    fi
    systemctl enable --now chronyd >/dev/null 2>&1 || warn "chronyd could not be started"
    timedatectl set-ntp true >/dev/null 2>&1 || true
    chronyc -a makestep >/dev/null 2>&1 || true

    local i synced
    for i in {1..30}; do
        synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
        [[ "$synced" == "yes" ]] && return 0
        sleep 2
    done
    warn "NTP synchronization was not confirmed within 60 seconds"
}

first_ipv4_cidr() {
    local iface="$1"
    ip -o -4 addr show dev "$iface" scope global 2>/dev/null | awk 'NR == 1 {print $4}'
}

default_route_iface() {
    ip -4 route show default 2>/dev/null | awk 'NR == 1 {print $5}'
}

is_private_cidr() {
    python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    print("yes" if ipaddress.ip_interface(sys.argv[1]).ip.is_private else "no")
except Exception:
    print("no")
PY
}

detect_lan_iface() {
    local wan_if="$1"
    local ifname cidr private
    while read -r ifname cidr; do
        ifname="${ifname%@*}"
        [[ -z "$ifname" || "$ifname" == "lo" || "$ifname" == "$wan_if" ]] && continue
        private="$(is_private_cidr "$cidr")"
        if [[ "$private" == "yes" ]]; then
            printf '%s' "$ifname"
            return 0
        fi
    done < <(ip -o -4 addr show scope global | awk '{print $2, $4}')
    return 1
}

detect_network_defaults() {
    SYNCA_WAN_IF="${SYNCA_WAN_IF:-$(default_route_iface)}"
    [[ -n "$SYNCA_WAN_IF" ]] || die "could not detect WAN interface; set SYNCA_WAN_IF"

    if [[ -z "${SYNCA_LAN_IF:-}" ]]; then
        SYNCA_LAN_IF="$(detect_lan_iface "$SYNCA_WAN_IF" || true)"
    fi
    [[ -n "${SYNCA_LAN_IF:-}" ]] || die "could not detect LAN interface; set SYNCA_LAN_IF"

    SYNCA_LAN_CIDR="${SYNCA_LAN_CIDR:-$(first_ipv4_cidr "$SYNCA_LAN_IF")}"
    [[ -n "$SYNCA_LAN_CIDR" ]] || die "could not detect LAN CIDR; set SYNCA_LAN_CIDR"

    SYNCA_WAN_ADDRESS="${SYNCA_WAN_ADDRESS:-$(first_ipv4_cidr "$SYNCA_WAN_IF")}"
    SYNCA_WAN_GATEWAY="${SYNCA_WAN_GATEWAY:-$(ip -4 route show default dev "$SYNCA_WAN_IF" 2>/dev/null | awk 'NR == 1 {print $3}')}"
    if [[ -z "${SYNCA_WAN_MODE:-}" ]]; then
        if [[ "$SYNCA_WAN_IF" == ppp* ]]; then
            SYNCA_WAN_MODE="pppoe"
        elif [[ -n "$SYNCA_WAN_ADDRESS" && -n "$SYNCA_WAN_GATEWAY" ]]; then
            SYNCA_WAN_MODE="static"
        else
            SYNCA_WAN_MODE="dhcp"
        fi
    fi

    log "Detected WAN: if=${SYNCA_WAN_IF} mode=${SYNCA_WAN_MODE} address=${SYNCA_WAN_ADDRESS:-none} gateway=${SYNCA_WAN_GATEWAY:-none}"
    log "Detected LAN: if=${SYNCA_LAN_IF} cidr=${SYNCA_LAN_CIDR}"
}

ensure_admin_password() {
    SYNCA_ADMIN_USER="${SYNCA_ADMIN_USER:-loginuser}"
    if [[ -z "${SYNCA_ADMIN_PASSWORD:-}" ]]; then
        if [[ -t 0 ]]; then
            local pass1 pass2
            while true; do
                read -r -s -p "SyncA admin password: " pass1
                printf '\n'
                read -r -s -p "Confirm SyncA admin password: " pass2
                printf '\n'
                [[ -n "$pass1" ]] || { warn "password cannot be empty"; continue; }
                [[ "$pass1" == "$pass2" ]] || { warn "passwords do not match"; continue; }
                SYNCA_ADMIN_PASSWORD="$pass1"
                break
            done
        else
            SYNCA_ADMIN_PASSWORD="$(openssl rand -base64 32)"
            GENERATED_PASSWORD_FILE="${SYNCA_GENERATED_PASSWORD_FILE:-/root/synca-utm-setup-credentials.txt}"
            {
                printf 'SYNCA_ADMIN_USER=%s\n' "$SYNCA_ADMIN_USER"
                printf 'SYNCA_ADMIN_PASSWORD=%s\n' "$SYNCA_ADMIN_PASSWORD"
            } > "$GENERATED_PASSWORD_FILE"
            chmod 0600 "$GENERATED_PASSWORD_FILE"
            log "Generated admin password file: $GENERATED_PASSWORD_FILE"
        fi
    fi
    SYNCA_GUI_USER="${SYNCA_GUI_USER:-$SYNCA_ADMIN_USER}"
    SYNCA_GUI_PASSWORD="${SYNCA_GUI_PASSWORD:-$SYNCA_ADMIN_PASSWORD}"
}

prepare_installer_payload() {
    local installer_dir="${SYNCA_INSTALLER_DIR:-/opt/synca-installer}"
    INSTALLER_DIR="$installer_dir"
    rm -rf "$INSTALLER_DIR"
    install -d -m 0755 "$INSTALLER_DIR" "$INSTALLER_DIR/wheelhouse" "$INSTALLER_DIR/firewalld-profiles"

    log "Preparing installer payload in $INSTALLER_DIR"
    tar -C "$SOURCE_ROOT/payload" -czf "$INSTALLER_DIR/server-gui.tar.gz" server-gui
    install -m 0755 "$SOURCE_ROOT/iso/payload/synca-install.sh" "$INSTALLER_DIR/synca-install.sh"
    install -m 0755 "$SOURCE_ROOT/iso/payload/synca-firstboot.sh" "$INSTALLER_DIR/synca-firstboot.sh"
    install -m 0644 "$SOURCE_ROOT/payload/firewalld-profiles/synca-utm-default.json" \
        "$INSTALLER_DIR/firewalld-profiles/synca-utm-default.json"

    log "Downloading Python wheels for offline local venv installation"
    python3 -m pip install --upgrade pip wheel >/dev/null
    python3 -m pip download --dest "$INSTALLER_DIR/wheelhouse" \
        -r "$SOURCE_ROOT/payload/server-gui/requirements.txt" >/dev/null
}

prepare_wireguard_ui() {
    local url tmp archive binary
    if is_truthy "${SYNCA_SKIP_WIREGUARD_UI:-0}"; then
        warn "wireguard-ui download skipped by SYNCA_SKIP_WIREGUARD_UI"
        return 0
    fi
    if [[ -n "${SYNCA_WGUI_BINARY:-}" ]]; then
        [[ -f "$SYNCA_WGUI_BINARY" ]] || die "SYNCA_WGUI_BINARY does not exist: $SYNCA_WGUI_BINARY"
        install -m 0755 "$SYNCA_WGUI_BINARY" "$INSTALLER_DIR/wireguard-ui"
        log "Included wireguard-ui from $SYNCA_WGUI_BINARY"
        return 0
    fi
    if [[ "$(uname -m)" != "x86_64" ]]; then
        warn "wireguard-ui automatic download is only configured for x86_64; skipping"
        return 0
    fi

    url="${SYNCA_WIREGUARD_UI_URL:-https://github.com/ngoduykhanh/wireguard-ui/releases/download/v0.6.1/wireguard-ui-v0.6.1-linux-amd64.tar.gz}"
    tmp="$(mktemp -d)"
    archive="$tmp/wireguard-ui.tar.gz"
    if ! curl -fsSL "$url" -o "$archive"; then
        warn "wireguard-ui download failed; server-gui WireGuard management remains available"
        rm -rf "$tmp"
        return 0
    fi
    tar -xzf "$archive" -C "$tmp"
    binary="$(find "$tmp" -type f -name 'wireguard-ui' -perm /111 | head -n1)"
    if [[ -z "$binary" ]]; then
        warn "wireguard-ui archive did not contain an executable binary"
        rm -rf "$tmp"
        return 0
    fi
    install -m 0755 "$binary" "$INSTALLER_DIR/wireguard-ui"
    rm -rf "$tmp"
    log "Downloaded wireguard-ui from $url"
}

write_private_firstboot_env() {
    local private_dir="$INSTALLER_DIR/private"
    local env_file="$private_dir/firstboot.env"
    local has_private_firstboot=0
    install -d -m 0700 "$private_dir"
    : > "$env_file"
    chmod 0600 "$env_file"

    if [[ -n "${SYNCA_PRIVATE_FIRSTBOOT_ENV:-}" ]]; then
        [[ -f "$SYNCA_PRIVATE_FIRSTBOOT_ENV" ]] || die "SYNCA_PRIVATE_FIRSTBOOT_ENV does not exist: $SYNCA_PRIVATE_FIRSTBOOT_ENV"
        cat "$SYNCA_PRIVATE_FIRSTBOOT_ENV" > "$env_file"
        printf '\n' >> "$env_file"
        has_private_firstboot=1
    fi

    {
        printf '# Managed by setup-synca-utm-almalinux9-vps.sh\n'
        printf 'SYNCA_UPDATE_BRANCH=%s\n' "$(shell_env_quote "${SYNCA_UPDATE_BRANCH:-main}")"
        [[ -n "$SOURCE_SHA" ]] && printf 'SYNCA_INSTALLED_SHA=%s\n' "$(shell_env_quote "$SOURCE_SHA")"
        if [[ "$has_private_firstboot" != "1" ]] || is_truthy "${SYNCA_ALLOW_ENV_SECRET_OVERRIDE:-0}"; then
            write_env_assignment SYNCA_DDNSFT_AUTH_USER
            write_env_assignment SYNCA_DDNSFT_AUTH_PASS
            write_env_assignment SYNCA_CENTRAL_ENROLLMENT_TOKEN
        fi
        write_env_assignment SYNCA_DDNS_PIN_RECIPIENT
        write_env_assignment SYNCA_DDNS_PIN_TTL_SECONDS
        write_env_assignment SYNCA_CENTRAL_ENABLED
        write_env_assignment SYNCA_CENTRAL_URL
        write_env_assignment SYNCA_CENTRAL_GUI_URL
        write_env_assignment SYNCA_CENTRAL_FAMILY
        write_env_assignment SYNCA_CENTRAL_BACKUP_ENABLED
    } >> "$env_file"
}

write_private_smtp_dropin() {
    local private_dir="$INSTALLER_DIR/private"
    local dropin="$private_dir/server-gui-ddns-smtp.conf"
    local has_smtp=0
    install -d -m 0700 "$private_dir"

    if [[ -n "${SYNCA_PRIVATE_SMTP_DROPIN:-}" ]]; then
        [[ -f "$SYNCA_PRIVATE_SMTP_DROPIN" ]] || die "SYNCA_PRIVATE_SMTP_DROPIN does not exist: $SYNCA_PRIVATE_SMTP_DROPIN"
        install -m 0600 "$SYNCA_PRIVATE_SMTP_DROPIN" "$dropin"
        return 0
    fi

    for key in \
        SYNCA_DDNS_PIN_SMTP_HOST SYNCA_DDNS_PIN_SMTP_PORT SYNCA_DDNS_PIN_SMTP_USER \
        SYNCA_DDNS_PIN_SMTP_PASS SYNCA_DDNS_PIN_SMTP_FROM SYNCA_DDNS_PIN_SMTP_SSL \
        SYNCA_DDNS_PIN_RECIPIENT SYNCA_DDNS_PIN_TTL_SECONDS
    do
        if [[ -v $key && -n "${!key}" ]]; then
            has_smtp=1
        fi
    done
    [[ "$has_smtp" -eq 1 ]] || return 0

    {
        printf '[Service]\n'
        write_systemd_environment_line SYNCA_DDNS_PIN_SMTP_HOST
        write_systemd_environment_line SYNCA_DDNS_PIN_SMTP_PORT
        write_systemd_environment_line SYNCA_DDNS_PIN_SMTP_USER
        write_systemd_environment_line SYNCA_DDNS_PIN_SMTP_PASS
        write_systemd_environment_line SYNCA_DDNS_PIN_SMTP_FROM
        write_systemd_environment_line SYNCA_DDNS_PIN_SMTP_SSL
        write_systemd_environment_line SYNCA_DDNS_PIN_RECIPIENT
        write_systemd_environment_line SYNCA_DDNS_PIN_TTL_SECONDS
    } > "$dropin"
    chmod 0600 "$dropin"
}

source_private_firstboot_env() {
    local env_file="$INSTALLER_DIR/private/firstboot.env"
    local key value
    [[ -f "$env_file" ]] || return 0
    # The generated file uses shell-compatible KEY='value' assignments. Reading
    # it here makes DDNS and central values available to the immediate firstboot
    # run as well as to the later systemd services.
    for key in SYNCA_CENTRAL_ENROLLMENT_TOKEN; do
        value=""
        if [[ -v $key ]]; then
            value="${!key}"
        fi
        if is_placeholder_env_value "$key" "$value"; then
            unset "$key"
        fi
    done
    # shellcheck disable=SC1090
    set -a
    . "$env_file"
    set +a
}

run_synca_installers() {
    log "Installing SyncA application payload"
    INSTALLER_DIR="$INSTALLER_DIR" "$INSTALLER_DIR/synca-install.sh" --postinstall

    log "Applying firstboot configuration without changing existing WAN/LAN IP settings"
    export SYNCA_ADMIN_USER SYNCA_ADMIN_PASSWORD SYNCA_GUI_USER SYNCA_GUI_PASSWORD
    export SYNCA_WAN_IF SYNCA_LAN_IF SYNCA_WAN_MODE SYNCA_WAN_ADDRESS SYNCA_WAN_GATEWAY SYNCA_LAN_CIDR
    export SYNCA_APPLY_NETWORK=1 SYNCA_APPLY_LAN=1 SYNCA_APPLY_WAN=1 SYNCA_PRESERVE_NETWORK=1
    export SYNCA_UPDATE_BRANCH="${SYNCA_UPDATE_BRANCH:-main}"
    export SYNCA_INSTALLED_SHA="${SOURCE_SHA:-}"
    export SYNCA_SYSTEM_HOSTNAME="${SYNCA_SYSTEM_HOSTNAME:-synca-utm}"
    export SYNCA_ADMIN_CIDR="${SYNCA_ADMIN_CIDR:-0.0.0.0/0}"
    export SYNCA_WG_ADDR="${SYNCA_WG_ADDR:-10.252.1.1/24}"
    export SYNCA_WG_PORT="${SYNCA_WG_PORT:-51820}"
    export SYNCA_DDNS_LEFT="${SYNCA_DDNS_LEFT:-}"
    "$INSTALLER_DIR/synca-firstboot.sh" --auto-safe
}

configure_modsecurity() {
    # Nginx vhosts created by the GUI point at this file when WAF is enabled.
    install -d -m 0755 /etc/nginx/modsec
    cat > /etc/nginx/modsec/main.conf <<'CONF'
# Managed by SyncA UTM setup script.
# Enables the packaged ModSecurity v2 engine and OWASP CRS on AlmaLinux 9.
Include /etc/nginx/modsecurity.conf
SecRuleEngine On
Include /etc/httpd/modsecurity.d/crs-setup.conf
Include /etc/httpd/modsecurity.d/activated_rules/*.conf
CONF
    chmod 0644 /etc/nginx/modsec/main.conf
}

configure_selinux_ports() {
    # The management GUI is exposed by nginx on 4444/tcp. SELinux blocks nginx
    # from binding non-http ports unless the port is labeled http_port_t. It
    # also blocks reverse proxy connections to the local gunicorn upstream
    # unless httpd_can_network_connect is enabled.
    if ! command -v semanage >/dev/null 2>&1; then
        if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
            warn "semanage is missing while SELinux is enforcing; nginx may fail to bind 4444/tcp"
        fi
    else
        if ! semanage port -l | awk '$1 == "http_port_t" {print}' | grep -Eq '(^|[,[:space:]])4444([,[:space:]]|$)'; then
            semanage port -a -t http_port_t -p tcp 4444 >/dev/null 2>&1 || \
                semanage port -m -t http_port_t -p tcp 4444 >/dev/null 2>&1 || \
                warn "failed to label 4444/tcp as http_port_t"
        fi
    fi
    if command -v setsebool >/dev/null 2>&1; then
        setsebool -P httpd_can_network_connect 1 >/dev/null 2>&1 || \
            warn "failed to enable SELinux httpd_can_network_connect"
    fi
}

configure_fail2ban_defaults() {
    # Reuse the exact defaults exposed by the GUI module so the CLI setup and
    # later GUI "install defaults" action do not drift.
    SERVER_GUI_CONFIG_DIR=/etc/server-gui PYTHONPATH=/opt/server-gui \
        /opt/server-gui/venv/bin/python - <<'PY'
from pathlib import Path
from server_gui.modules.fail2ban import (
    DEFAULT_JAIL_LOCAL,
    FAIL2BAN_LOCAL_CONTENT,
    JAIL_D,
    FILTER_D,
    SERVER_GUI_FILTER_CONTENT,
)

paths = {
    Path("/etc/fail2ban/jail.local"): DEFAULT_JAIL_LOCAL,
    Path("/etc/fail2ban/fail2ban.local"): FAIL2BAN_LOCAL_CONTENT,
    FILTER_D / "server-gui-auth.conf": SERVER_GUI_FILTER_CONTENT,
}
JAIL_D.mkdir(parents=True, exist_ok=True)
FILTER_D.mkdir(parents=True, exist_ok=True)
for path, text in paths.items():
    if path.exists() and path.read_text(encoding="utf-8", errors="replace") != text:
        backup = path.with_suffix(path.suffix + ".synca-setup.bak")
        backup.write_bytes(path.read_bytes())
    path.write_text(text, encoding="utf-8")
    path.chmod(0o644)
Path("/var/log/fail2ban.log").touch(mode=0o640, exist_ok=True)
PY
    systemctl enable --now fail2ban >/dev/null 2>&1 || warn "fail2ban could not be started"
}

start_optional_services() {
    log "Starting optional feature services and timers"
    systemctl enable --now strongswan >/dev/null 2>&1 || warn "strongswan could not be started"
    firewall-cmd --permanent --zone=public --add-service=ssh >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    nginx -t
    systemctl reload-or-restart nginx >/dev/null 2>&1 || true
    systemctl restart server-gui >/dev/null 2>&1 || true
    systemctl start server-gui-ddns.service >/dev/null 2>&1 || warn "initial DDNS check failed or is not configured"
    systemctl start server-gui-geoip.service >/dev/null 2>&1 || warn "initial GeoIP ipset refresh failed"
    systemctl start server-gui-backup.service >/dev/null 2>&1 || warn "initial local backup failed"
    systemctl start server-gui-update-check.service >/dev/null 2>&1 || warn "initial GitHub update check failed"
    if [[ -n "${SYNCA_CENTRAL_ENROLLMENT_TOKEN:-}" ]]; then
        /opt/server-gui/bin/central-agent --report >/dev/null 2>&1 || warn "initial central enrollment/report failed"
    fi
}

verify_installation() {
    local service lan_ip
    local -a required_services=(NetworkManager chronyd firewalld nginx server-gui dnsmasq fail2ban strongswan)

    log "Verifying service state"
    for service in "${required_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "active: $service"
        else
            warn "not active: $service"
        fi
    done

    lan_ip="${SYNCA_LAN_CIDR%/*}"
    if curl -kfsS --max-time 10 -o /dev/null "https://127.0.0.1:4444/"; then
        log "GUI local HTTPS check passed: https://127.0.0.1:4444/"
    else
        warn "GUI local HTTPS check failed"
    fi

    log "SyncA UTM VPS setup completed"
    log "GUI URL: https://${lan_ip}:4444/"
}

main() {
    parse_args "$@"
    require_root
    load_env_file
    apply_cli_overrides
    start_logging
    validate_os
    enable_repositories
    resolve_source_tree
    resolve_internal_secret_defaults
    install_feature_packages
    enable_time_sync
    detect_network_defaults
    ensure_admin_password
    prepare_installer_payload
    prepare_wireguard_ui
    write_private_firstboot_env
    write_private_smtp_dropin
    source_private_firstboot_env
    configure_modsecurity
    configure_selinux_ports
    run_synca_installers
    configure_fail2ban_defaults
    start_optional_services
    verify_installation
}

main "$@"
