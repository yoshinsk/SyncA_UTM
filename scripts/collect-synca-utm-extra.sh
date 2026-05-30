#!/usr/bin/env bash
# scripts/collect-synca-utm-extra.sh
# Additional SyncA UTM collector for custom systemd units and locally installed UI applications.

set -u
set -o pipefail

OUT="/tmp/synca-extra"
ARCHIVE="/tmp/synca-extra.tar.gz"

rm -rf "${OUT}"
mkdir -p "${OUT}"/{systemd,paths,apps}

systemctl cat \
  server-gui.service \
  wgui.service \
  wgui-worker.service \
  wgui.path \
  server-gui-ddns.timer \
  server-gui-geoip.timer \
  server-gui-update-check.timer \
  > "${OUT}/systemd/units.txt" 2>&1 || true

find /etc/systemd/system /usr/local /opt -maxdepth 5 \
  \( -iname '*server-gui*' -o -iname '*wgui*' -o -iname '*wireguard*ui*' \) \
  -print > "${OUT}/paths/app-paths.txt" 2>&1 || true

find / -xdev -maxdepth 5 \
  \( -name 'server-gui' -o -name 'wireguard-ui' -o -name 'wgui*' \) \
  -print >> "${OUT}/paths/app-paths.txt" 2>/dev/null || true

while read -r path; do
  [ -e "${path}" ] || continue
  case "${path}" in
    /usr/local/*|/opt/*|/etc/systemd/system/*)
      cp -a --parents "${path}" "${OUT}/apps/" 2>/dev/null || true
      ;;
  esac
done < "${OUT}/paths/app-paths.txt"

tar -C /tmp -czf "${ARCHIVE}" synca-extra
chown alma:alma "${ARCHIVE}" 2>/dev/null || true
chmod 600 "${ARCHIVE}"
echo "${ARCHIVE}"
