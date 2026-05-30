#!/usr/bin/env bash
# scripts/build-synca-utm-iso.sh
# Builds a SyncA UTM installer ISO by injecting Kickstart and payload files.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/output/iso-build}"
OUTPUT_ISO="${OUTPUT_ISO:-${ROOT_DIR}/output/SyncA-UTM-AlmaLinux-9.iso}"
ALMA_ISO_URL="${ALMA_ISO_URL:-https://repo.almalinux.org/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso}"
ALMA_ISO="${ALMA_ISO:-${BUILD_DIR}/$(basename "$ALMA_ISO_URL")}"
SYNC_BUILD_WHEELHOUSE="${SYNC_BUILD_WHEELHOUSE:-0}"
WHEELHOUSE_SRC="${WHEELHOUSE_SRC:-}"
RPM_DIR_SRC="${RPM_DIR_SRC:-}"
WGUI_BINARY="${WGUI_BINARY:-}"
SYNC_PREPARE_ONLY="${SYNC_PREPARE_ONLY:-0}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required tool not found: $1" >&2
        exit 1
    fi
}

prepare_workspace() {
    mkdir -p "$BUILD_DIR" "$(dirname "$OUTPUT_ISO")"
    rm -rf "${BUILD_DIR}/payload"
    mkdir -p "${BUILD_DIR}/payload/synca" "${BUILD_DIR}/payload/ks"
}

download_base_iso() {
    if [[ -f "$ALMA_ISO" ]]; then
        echo "Using base ISO: $ALMA_ISO"
        return
    fi
    echo "Downloading AlmaLinux ISO: $ALMA_ISO_URL"
    mkdir -p "$(dirname "$ALMA_ISO")"
    curl -L --fail --continue-at - --output "${ALMA_ISO}.part" "$ALMA_ISO_URL"
    mv "${ALMA_ISO}.part" "$ALMA_ISO"
}

package_server_gui() {
    local archive="${BUILD_DIR}/payload/synca/server-gui.tar.gz"
    tar -C "${ROOT_DIR}/payload" \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.pyo' \
        -czf "$archive" server-gui
}

package_wheelhouse() {
    mkdir -p "${BUILD_DIR}/payload/synca/wheelhouse"
    if [[ -n "$WHEELHOUSE_SRC" ]]; then
        rsync -a "${WHEELHOUSE_SRC%/}/" "${BUILD_DIR}/payload/synca/wheelhouse/"
    elif [[ "$SYNC_BUILD_WHEELHOUSE" == "1" ]]; then
        if ! python3 -m pip --version >/dev/null 2>&1; then
            echo "python3 pip is missing. Install python3-pip in WSL or pass WHEELHOUSE_SRC." >&2
            exit 1
        fi
        python3 -m pip download \
            -r "${ROOT_DIR}/payload/server-gui/requirements.txt" \
            -d "${BUILD_DIR}/payload/synca/wheelhouse"
    else
        echo "Skipping wheel download. Set SYNC_BUILD_WHEELHOUSE=1 for a complete offline Python wheelhouse."
    fi
}

copy_payload_files() {
    install -m 0644 "${ROOT_DIR}/iso/kickstart/synca-utm.ks" \
        "${BUILD_DIR}/payload/ks/synca-utm.ks"
    install -m 0755 "${ROOT_DIR}/iso/payload/synca-install.sh" \
        "${BUILD_DIR}/payload/synca/synca-install.sh"
    install -m 0755 "${ROOT_DIR}/iso/payload/synca-firstboot.sh" \
        "${BUILD_DIR}/payload/synca/synca-firstboot.sh"
    mkdir -p "${BUILD_DIR}/payload/synca/firewalld-profiles"
    install -m 0644 "${ROOT_DIR}/payload/firewalld-profiles/synca-utm-default.json" \
        "${BUILD_DIR}/payload/synca/firewalld-profiles/synca-utm-default.json"
    if [[ -n "$WGUI_BINARY" ]]; then
        install -m 0755 "$WGUI_BINARY" "${BUILD_DIR}/payload/synca/wireguard-ui"
    fi
    if [[ -n "$RPM_DIR_SRC" ]]; then
        mkdir -p "${BUILD_DIR}/payload/synca/rpms"
        rsync -a "${RPM_DIR_SRC%/}/" "${BUILD_DIR}/payload/synca/rpms/"
    fi
}

extract_boot_configs() {
    rm -rf "${BUILD_DIR}/bootcfg"
    mkdir -p "${BUILD_DIR}/bootcfg/isolinux" "${BUILD_DIR}/bootcfg/EFI/BOOT"
    xorriso -osirrox on -indev "$ALMA_ISO" \
        -extract /isolinux/isolinux.cfg "${BUILD_DIR}/bootcfg/isolinux/isolinux.cfg" \
        -extract /EFI/BOOT/grub.cfg "${BUILD_DIR}/bootcfg/EFI/BOOT/grub.cfg" \
        >/dev/null 2>&1 || true
}

patch_isolinux() {
    local cfg="${BUILD_DIR}/bootcfg/isolinux/isolinux.cfg"
    [[ -f "$cfg" ]] || return 0
    if grep -q "Install SyncA UTM" "$cfg"; then
        return 0
    fi
    cat >> "$cfg" <<'CFG'

label synca-utm
  menu label Install SyncA UTM
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.ks=cdrom:/ks/synca-utm.ks quiet
CFG
}

patch_grub() {
    local cfg="${BUILD_DIR}/bootcfg/EFI/BOOT/grub.cfg"
    [[ -f "$cfg" ]] || return 0
    if grep -q "Install SyncA UTM" "$cfg"; then
        return 0
    fi
    cat >> "$cfg" <<'CFG'

menuentry 'Install SyncA UTM' --class fedora --class gnu-linux --class gnu --class os {
    linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.ks=cdrom:/ks/synca-utm.ks quiet
    initrdefi /images/pxeboot/initrd.img
}
CFG
}

build_iso() {
    local cmd=(
        xorriso
        -indev "$ALMA_ISO"
        -outdev "$OUTPUT_ISO"
        -boot_image any replay
        -map "${BUILD_DIR}/payload/ks" /ks
        -map "${BUILD_DIR}/payload/synca" /synca
    )
    if [[ -f "${BUILD_DIR}/bootcfg/isolinux/isolinux.cfg" ]]; then
        cmd+=(-map "${BUILD_DIR}/bootcfg/isolinux/isolinux.cfg" /isolinux/isolinux.cfg)
    fi
    if [[ -f "${BUILD_DIR}/bootcfg/EFI/BOOT/grub.cfg" ]]; then
        cmd+=(-map "${BUILD_DIR}/bootcfg/EFI/BOOT/grub.cfg" /EFI/BOOT/grub.cfg)
    fi
    cmd+=(-volid "SYNCA_UTM_9" -commit -end)
    "${cmd[@]}"
}

main() {
    require_tool xorriso
    require_tool curl
    require_tool tar
    require_tool python3
    prepare_workspace
    package_server_gui
    package_wheelhouse
    copy_payload_files
    if [[ "$SYNC_PREPARE_ONLY" == "1" ]]; then
        echo "Prepared ISO payload only: ${BUILD_DIR}/payload"
        exit 0
    fi
    download_base_iso
    extract_boot_configs
    patch_isolinux
    patch_grub
    build_iso
    echo "ISO created: $OUTPUT_ISO"
}

main "$@"
