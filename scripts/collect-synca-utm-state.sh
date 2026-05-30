#!/usr/bin/env bash
# scripts/collect-synca-utm-state.sh
# SyncA UTM manual server state collector for rebuilding the setup as an AlmaLinux 9 installable ISO.
# The script is read-only by design: it collects OS, package, service, network, firewall,
# and selected configuration data into a timestamped directory, then creates a tar.gz archive.

set -u
set -o pipefail

TS="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown-host)"
OUT_BASE="${1:-/root/synca-utm-state-${HOST}-${TS}}"
ARCHIVE="${OUT_BASE}.tar.gz"

mkdir -p "${OUT_BASE}"/{commands,etc,logs,history}
chmod 700 "${OUT_BASE}"

run_cmd() {
  local name="$1"
  shift

  {
    echo "# command: $*"
    echo "# collected_at: $(date -Is)"
    echo
    "$@"
  } > "${OUT_BASE}/commands/${name}.txt" 2>&1
}

copy_if_exists() {
  local src="$1"
  local dst_dir="$2"

  if [ -e "${src}" ]; then
    mkdir -p "${dst_dir}"
    cp -a --parents "${src}" "${dst_dir}/" 2>"${OUT_BASE}/logs/copy-errors.log" || true
  fi
}

redact_file() {
  local file="$1"

  if [ -f "${file}" ]; then
    sed -i -E \
      -e 's/(password|passwd|secret|psk|privatekey|private_key|token|apikey|api_key)[[:space:]]*[:=][[:space:]]*[^[:space:]'"'"'"]+/\1=REDACTED/Ig' \
      -e 's/(CHAP-Secrets|PAP-Secrets).*/\1 REDACTED/Ig' \
      "${file}" || true
  fi
}

echo "Collecting SyncA UTM state into ${OUT_BASE}"

# Core OS and hardware facts. These define the target baseline for the AlmaLinux 9 ISO.
run_cmd hostnamectl hostnamectl
run_cmd os-release bash -lc 'cat /etc/os-release; echo; uname -a'
run_cmd cpu-memory bash -lc 'lscpu; echo; free -h; echo; lsblk -f; echo; df -hT'
run_cmd boot-loader bash -lc 'bootctl status 2>/dev/null || true; grubby --info=ALL 2>/dev/null || true'

# Package and repository facts. dnf history is especially useful for reconstructing manual install order.
run_cmd dnf-repolist dnf repolist --all
run_cmd dnf-history dnf history list
run_cmd dnf-userinstalled dnf repoquery --userinstalled
run_cmd rpm-packages rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'
run_cmd enabled-modules bash -lc 'dnf module list --enabled 2>/dev/null || true'

# Service state. Enabled services become Kickstart/systemd preset candidates.
run_cmd systemctl-enabled systemctl list-unit-files --state=enabled
run_cmd systemctl-running systemctl --type=service --state=running --no-pager
run_cmd timers systemctl list-timers --all --no-pager
run_cmd sockets systemctl list-sockets --all --no-pager

# Network topology. Captures NIC names, NetworkManager profiles, routes, and listening ports.
run_cmd nmcli-general nmcli general status
run_cmd nmcli-devices nmcli device show
run_cmd nmcli-connections nmcli connection show
run_cmd ip-address ip -br address
run_cmd ip-route ip route show table all
run_cmd ip-rule ip rule show
run_cmd ss-listening ss -lntup
run_cmd ethtool bash -lc 'for dev in $(ls /sys/class/net | grep -v "^lo$"); do echo "## ${dev}"; ethtool "${dev}" 2>/dev/null || true; done'

# Firewall and packet processing. Both firewalld and lower-level nft/iptables data are collected.
run_cmd firewalld-state bash -lc 'systemctl status firewalld --no-pager; echo; firewall-cmd --state; echo; firewall-cmd --get-active-zones'
run_cmd firewalld-all-zones firewall-cmd --list-all-zones
run_cmd firewalld-services firewall-cmd --get-services
run_cmd firewalld-policies bash -lc 'firewall-cmd --get-policies 2>/dev/null; echo; firewall-cmd --list-all-policies 2>/dev/null || true'
run_cmd firewalld-direct bash -lc 'firewall-cmd --direct --get-all-rules 2>/dev/null || true; echo; firewall-cmd --direct --get-all-passthroughs 2>/dev/null || true'
run_cmd nft-ruleset bash -lc 'nft list ruleset 2>/dev/null || true'
run_cmd iptables-save bash -lc 'iptables-save 2>/dev/null || true; echo; ip6tables-save 2>/dev/null || true'

# UTM-adjacent components. Missing commands are tolerated because the manual server may not use all of them.
run_cmd wireguard bash -lc 'wg show all 2>/dev/null || true; echo; ip -d link show type wireguard 2>/dev/null || true'
run_cmd pppoe bash -lc 'nmcli connection show | grep -i ppp || true; echo; ls -la /etc/ppp 2>/dev/null || true'
run_cmd dhcp-dns bash -lc 'systemctl status dhcpd dnsmasq named unbound systemd-resolved --no-pager 2>/dev/null || true'
run_cmd proxy-web bash -lc 'systemctl status squid nginx httpd cockpit.socket --no-pager 2>/dev/null || true'
run_cmd ids-antivirus bash -lc 'systemctl status suricata snort clamav-freshclam clamd@scan --no-pager 2>/dev/null || true'
run_cmd vpn-services bash -lc 'systemctl status wg-quick@wg0 openvpn-server@server strongswan ipsec --no-pager 2>/dev/null || true'

# Kernel forwarding and hardening knobs often matter for routing, NAT, and VPN behavior.
run_cmd sysctl-routing bash -lc 'sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter 2>/dev/null || true'
run_cmd sysctl-all sysctl -a

# Account and sudo facts. Password hashes are not copied.
run_cmd users-groups bash -lc 'getent passwd; echo; getent group; echo; getent shadow | sed -E "s/^([^:]+):[^:]*:/\1:REDACTED:/"'
run_cmd sudoers bash -lc 'cat /etc/sudoers 2>/dev/null; echo; find /etc/sudoers.d -maxdepth 1 -type f -print -exec sed -E "s/(password|secret|token).*/REDACTED/Ig" {} \; 2>/dev/null'

# Shell histories can reveal manual installation steps. They may contain secrets, so redact the collected copies.
find /root /home -maxdepth 2 \( -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' \) -print 2>/dev/null |
  while read -r history_file; do
    dst="${OUT_BASE}/history/${history_file#/}"
    mkdir -p "$(dirname "${dst}")"
    cp -a "${history_file}" "${dst}" 2>/dev/null || true
    redact_file "${dst}"
  done

# Configuration trees selected for ISO reconstruction. The copy keeps paths via --parents.
for path in \
  /etc/NetworkManager \
  /etc/firewalld \
  /etc/sysconfig \
  /etc/wireguard \
  /etc/ppp \
  /etc/dhcp \
  /etc/dnsmasq.conf \
  /etc/dnsmasq.d \
  /etc/squid \
  /etc/nginx \
  /etc/httpd \
  /etc/cockpit \
  /etc/suricata \
  /etc/snort \
  /etc/clamd.d \
  /etc/freshclam.conf \
  /etc/strongswan \
  /etc/openvpn \
  /etc/cron.d \
  /etc/crontab \
  /var/spool/cron; do
  copy_if_exists "${path}" "${OUT_BASE}/etc"
done

# Redact copied configuration files while preserving structure for comparison.
find "${OUT_BASE}/etc" -type f -print 2>/dev/null | while read -r file; do
  redact_file "${file}"
done

tar -C "$(dirname "${OUT_BASE}")" -czf "${ARCHIVE}" "$(basename "${OUT_BASE}")"
chmod 600 "${ARCHIVE}"

echo "Archive created: ${ARCHIVE}"
