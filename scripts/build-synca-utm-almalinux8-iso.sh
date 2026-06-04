#!/usr/bin/env bash
# scripts/build-synca-utm-almalinux8-iso.sh
# Builds the AlmaLinux 8.10 SyncA UTM installer ISO without changing 9.x defaults.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export ALMA_MAJOR="${ALMA_MAJOR:-8}"
export ALMA_VERSION="${ALMA_VERSION:-8.10}"
export SYNCA_ISO_LABEL="${SYNCA_ISO_LABEL:-SYNCA_UTM_8}"
export BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/output/iso-build-almalinux8}"
export OUTPUT_ISO="${OUTPUT_ISO:-${ROOT_DIR}/output/SyncA-UTM-AlmaLinux-8.10.iso}"
export KICKSTART_FILE="${KICKSTART_FILE:-${ROOT_DIR}/iso/kickstart/synca-utm-el8.ks}"
export SYNC_PRUNE_DVD_REPOS="${SYNC_PRUNE_DVD_REPOS:-1}"
export SYNCA_DEFAULT_UPDATE_BRANCH="${SYNCA_DEFAULT_UPDATE_BRANCH:-codex/almalinux8-iso}"

INTERNAL_SECRETS_DIR="${SYNCA_INTERNAL_SECRETS_DIR:-${ROOT_DIR}/output/internal-secrets}"
if [[ -z "${SYNCA_PRIVATE_SMTP_DROPIN:-}" && -f "${INTERNAL_SECRETS_DIR}/server-gui-ddns-smtp.conf" ]]; then
    export SYNCA_PRIVATE_SMTP_DROPIN="${INTERNAL_SECRETS_DIR}/server-gui-ddns-smtp.conf"
fi
if [[ -z "${SYNCA_PRIVATE_FIRSTBOOT_ENV:-}" && -f "${INTERNAL_SECRETS_DIR}/firstboot.env" ]]; then
    export SYNCA_PRIVATE_FIRSTBOOT_ENV="${INTERNAL_SECRETS_DIR}/firstboot.env"
fi

if [[ -z "${RPM_DIR_SRC:-}" && -d "${ROOT_DIR}/output/rpms-almalinux8" ]]; then
    export RPM_DIR_SRC="${ROOT_DIR}/output/rpms-almalinux8"
fi

if [[ -z "${WHEELHOUSE_SRC:-}" && -d "${ROOT_DIR}/output/wheelhouse-almalinux8" ]]; then
    export WHEELHOUSE_SRC="${ROOT_DIR}/output/wheelhouse-almalinux8"
fi

exec "${ROOT_DIR}/scripts/build-synca-utm-iso.sh" "$@"
