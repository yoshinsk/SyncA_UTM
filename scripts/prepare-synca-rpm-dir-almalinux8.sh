#!/usr/bin/env bash
# scripts/prepare-synca-rpm-dir-almalinux8.sh
# Uses an AlmaLinux 8 container to build the EL8 RPM closure for the 8.10 ISO.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${SYNCA_EL8_BUILD_IMAGE:-quay.io/almalinuxorg/almalinux:8}"
PACKAGE_LIST="${PACKAGE_LIST:-${ROOT_DIR}/iso/package-lists/synca-rpms-el8.txt}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/output/rpms-almalinux8}"
TMP_DIR="${TMP_DIR:-${OUTPUT_DIR}.tmp}"

if ! command -v podman >/dev/null 2>&1; then
    echo "podman is required to prepare AlmaLinux 8 RPM repositories on this host." >&2
    exit 1
fi

podman run --rm --pull=missing \
    -v "${ROOT_DIR}:/work:rw" \
    -w /work \
    "$IMAGE" \
    bash -lc '
set -euo pipefail
dnf install -y dnf-plugins-core epel-release elrepo-release
dnf config-manager --set-enabled powertools >/dev/null 2>&1 || true
dnf install -y createrepo_c curl
PACKAGE_LIST="$1" OUTPUT_DIR="$2" TMP_DIR="$3" /work/scripts/prepare-synca-rpm-dir.sh
' bash \
    "/work/iso/package-lists/synca-rpms-el8.txt" \
    "/work/output/rpms-almalinux8" \
    "/work/output/rpms-almalinux8.tmp"
