#!/usr/bin/env bash
# scripts/prepare-synca-rpm-dir.sh
# Downloads the curated RPM dependency closure and builds pruned offline repos.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_LIST="${PACKAGE_LIST:-${ROOT_DIR}/iso/package-lists/synca-rpms.txt}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/output/rpms}"
TMP_DIR="${TMP_DIR:-${OUTPUT_DIR}.tmp}"

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
    require_tool curl
    if ! dnf download --help >/dev/null 2>&1; then
        dnf install -y dnf-plugins-core
    fi
    if ! command -v createrepo_c >/dev/null 2>&1; then
        dnf install -y createrepo_c
    fi
    mkdir -p \
        "$TMP_DIR/BaseOS/Packages" \
        "$TMP_DIR/AppStream/Packages" \
        "$TMP_DIR/SyncA-Extra/Packages"
    mapfile -t packages < <(read_packages)
    mapfile -t urls < <(
        dnf download --resolve --alldeps --url "${packages[@]}" |
            grep -E '^https?://' |
            grep -E '\.(x86_64|noarch)\.rpm$' |
            sort -u
    )
    for url in "${urls[@]}"; do
        case "$url" in
            */BaseOS/*) dest="$TMP_DIR/BaseOS/Packages" ;;
            */AppStream/*) dest="$TMP_DIR/AppStream/Packages" ;;
            *) dest="$TMP_DIR/SyncA-Extra/Packages" ;;
        esac
        target="$dest/${url##*/}"
        part="${target}.part"
        if [[ -f "$target" ]]; then
            if rpm -K --nosignature "$target" >/dev/null 2>&1; then
                continue
            fi
            mv "$target" "$part"
        fi
        curl -L --fail --continue-at - -o "$part" "$url"
        mv "$part" "$target"
    done
    for repo in BaseOS AppStream SyncA-Extra; do
        if compgen -G "$TMP_DIR/$repo/Packages/*.rpm" >/dev/null; then
            createrepo_c "$TMP_DIR/$repo"
        fi
    done
    rm -rf "$OUTPUT_DIR"
    mv "$TMP_DIR" "$OUTPUT_DIR"
    echo "Pruned RPM repositories prepared: $OUTPUT_DIR"
}

main "$@"
