#!/usr/bin/env bash
# scripts/collect-synca-utm-deep.sh
# Deep collector for DDNS, Let's Encrypt/certbot, fail2ban, nginx proxy, server-gui state, and update wiring.

set -u
set -o pipefail

OUT="/tmp/synca-deep"
ARCHIVE="/tmp/synca-deep.tar.gz"

rm -rf "${OUT}"
mkdir -p "${OUT}"/{commands,etc,opt,var}

run_cmd() {
  local name="$1"
  shift
  {
    echo "# command: $*"
    echo "# collected_at: $(date -Is)"
    echo
    "$@"
  } > "${OUT}/commands/${name}.txt" 2>&1
}

copy_path() {
  local path="$1"
  if [ -e "${path}" ]; then
    cp -a --parents "${path}" "${OUT}/" 2>>"${OUT}/commands/copy-errors.txt" || true
  fi
}

run_cmd certbot-version bash -lc 'certbot --version 2>/dev/null || true; snap list certbot 2>/dev/null || true; rpm -qa | grep -Ei "certbot|letsencrypt|acme" || true'
run_cmd certbot-certificates bash -lc 'certbot certificates 2>/dev/null || true'
run_cmd certbot-renew-dry-run-systemd bash -lc 'systemctl cat certbot-renew.service certbot-renew.timer snap.certbot.renew.timer 2>/dev/null || true'
run_cmd letsencrypt-tree bash -lc 'find /etc/letsencrypt -maxdepth 4 -type f -o -type l 2>/dev/null | sort || true'
run_cmd fail2ban-status bash -lc 'fail2ban-client status 2>/dev/null || true; for j in $(fail2ban-client status 2>/dev/null | sed -n "s/.*Jail list:[[:space:]]*//p" | tr "," " "); do echo "## $j"; fail2ban-client status "$j" 2>/dev/null || true; fail2ban-client get "$j" ignoreip 2>/dev/null || true; done'
run_cmd fail2ban-systemd bash -lc 'systemctl cat fail2ban.service 2>/dev/null || true; systemctl status fail2ban --no-pager 2>/dev/null || true'
run_cmd nginx-test bash -lc 'nginx -T 2>/dev/null || nginx -t 2>&1 || true'
run_cmd server-gui-api-files bash -lc 'find /etc/server-gui /var/lib/server-gui /var/log/server-gui -maxdepth 4 -type f 2>/dev/null | sort || true'
run_cmd server-gui-systemd bash -lc 'systemctl cat server-gui.service server-gui-ddns.service server-gui-ddns.timer server-gui-geoip.service server-gui-geoip.timer server-gui-update-check.service server-gui-update-check.timer 2>/dev/null || true'
run_cmd wgui-systemd bash -lc 'systemctl cat wgui.service wgui.path wgui-worker.service wg-quick@wg0.service 2>/dev/null || true'
run_cmd python-freeze bash -lc '/opt/server-gui/venv/bin/pip freeze 2>/dev/null || true'
run_cmd wireguard-ui-version bash -lc '/opt/wireguard/wireguard-ui --version 2>/dev/null || strings /opt/wireguard/wireguard-ui 2>/dev/null | grep -Ei "wireguard-ui|version" | head -20 || true'

for path in \
  /etc/server-gui \
  /var/lib/server-gui \
  /etc/fail2ban \
  /etc/letsencrypt/renewal \
  /etc/letsencrypt/renewal-hooks \
  /etc/nginx \
  /opt/server-gui/bin \
  /opt/server-gui/requirements.txt \
  /opt/server-gui/server_gui \
  /opt/wireguard; do
  copy_path "${path}"
done

tar -C /tmp -czf "${ARCHIVE}" synca-deep
chown alma:alma "${ARCHIVE}" 2>/dev/null || true
chmod 600 "${ARCHIVE}"
echo "${ARCHIVE}"
