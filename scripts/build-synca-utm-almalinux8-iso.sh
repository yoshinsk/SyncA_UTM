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

if [[ -z "${RPM_DIR_SRC:-}" && -d "${ROOT_DIR}/output/rpms-almalinux8" ]]; then
    export RPM_DIR_SRC="${ROOT_DIR}/output/rpms-almalinux8"
fi

if [[ -z "${WHEELHOUSE_SRC:-}" && -d "${ROOT_DIR}/output/wheelhouse-almalinux8" ]]; then
    export WHEELHOUSE_SRC="${ROOT_DIR}/output/wheelhouse-almalinux8"
fi

exec "${ROOT_DIR}/scripts/build-synca-utm-iso.sh" "$@"
