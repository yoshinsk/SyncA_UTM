#!/usr/bin/env bash
# scripts/prepare-synca-rpm-dir.sh
# Downloads the curated RPM dependency closure for an offline SyncA UTM ISO.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_LIST="${PACKAGE_LIST:-${ROOT_DIR}/iso/package-lists/synca-rpms.txt}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/output/rpms}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required tool not found: $1" >&2
        exit 1
    fi
}

read_packages() {
    grep -Ev '^\s*(#|$)' "$PACKAGE_LIST"
}

main() {
    require_tool dnf
    mkdir -p "$OUTPUT_DIR"
    if ! dnf download --help >/dev/null 2>&1; then
        dnf install -y dnf-plugins-core
    fi
    mapfile -t packages < <(read_packages)
    dnf download --resolve --alldeps --destdir "$OUTPUT_DIR" "${packages[@]}"
    echo "RPM directory prepared: $OUTPUT_DIR"
}

main "$@"

