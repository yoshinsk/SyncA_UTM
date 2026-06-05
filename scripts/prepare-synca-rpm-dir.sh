#!/usr/bin/env bash
# scripts/prepare-synca-rpm-dir.sh
# Downloads the curated RPM dependency closure and builds pruned offline repos.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_PACKAGE_LIST="${ROOT_DIR}/iso/package-lists/synca-rpms.txt"
if [[ -z "${PACKAGE_LIST:-}" && "${ALMA_MAJOR:-}" == "8" ]]; then
    EXTRA_PACKAGE_LIST="${EXTRA_PACKAGE_LIST:-${ROOT_DIR}/iso/package-lists/synca-rpms-almalinux8-extra.txt}"
fi
PACKAGE_LIST="${PACKAGE_LIST:-$DEFAULT_PACKAGE_LIST}"
EXTRA_PACKAGE_LIST="${EXTRA_PACKAGE_LIST:-}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/output/rpms}"
TMP_DIR="${TMP_DIR:-${OUTPUT_DIR}.tmp}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required tool not found: $1" >&2
        exit 1
    fi
}

read_packages() {
    local list
    for list in "$PACKAGE_LIST" ${EXTRA_PACKAGE_LIST:+"$EXTRA_PACKAGE_LIST"}; do
        if [[ ! -f "$list" ]]; then
            echo "package list not found: $list" >&2
            exit 1
        fi
        grep -Ev '^\s*(#|$)' "$list"
    done
}

ensure_optional_repos() {
    local package
    for package in "$@"; do
        if [[ "$package" != "kmod-wireguard" ]]; then
            continue
        fi
        if dnf -q list available kmod-wireguard >/dev/null 2>&1 || rpm -q kmod-wireguard >/dev/null 2>&1; then
            return 0
        fi
        dnf install -y elrepo-release
        return 0
    done
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
    ensure_optional_repos "${packages[@]}"
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
