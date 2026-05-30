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
SYNC_PRUNE_DVD_REPOS="${SYNC_PRUNE_DVD_REPOS:-1}"
SYNCA_PRIVATE_SMTP_DROPIN="${SYNCA_PRIVATE_SMTP_DROPIN:-}"

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
    if [[ -n "$SYNCA_PRIVATE_SMTP_DROPIN" ]]; then
        if [[ ! -f "$SYNCA_PRIVATE_SMTP_DROPIN" ]]; then
            echo "SYNCA_PRIVATE_SMTP_DROPIN does not exist: $SYNCA_PRIVATE_SMTP_DROPIN" >&2
            exit 1
        fi
        mkdir -p "${BUILD_DIR}/payload/synca/private"
        install -m 0600 "$SYNCA_PRIVATE_SMTP_DROPIN" \
            "${BUILD_DIR}/payload/synca/private/server-gui-ddns-smtp.conf"
        echo "Included private SMTP drop-in for internal ISO."
    fi
    if [[ -n "$WGUI_BINARY" ]]; then
        install -m 0755 "$WGUI_BINARY" "${BUILD_DIR}/payload/synca/wireguard-ui"
    fi
    if [[ -n "$RPM_DIR_SRC" && -d "${RPM_DIR_SRC%/}/SyncA-Extra" ]]; then
        mkdir -p "${BUILD_DIR}/payload/synca/rpms"
        rsync -a "${RPM_DIR_SRC%/}/SyncA-Extra/" "${BUILD_DIR}/payload/synca/rpms/"
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
    python3 - "$cfg" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()
lines = []
skip_synca = False
for line in text.splitlines():
    if line.startswith("label synca-utm"):
        skip_synca = True
        continue
    if skip_synca and line.startswith("label "):
        skip_synca = False
    if skip_synca:
        continue
    stripped = line.lstrip()
    if stripped == "menu default":
        continue
    if stripped.startswith("append "):
        line = re.sub(r"inst\.stage2=\S+", "inst.stage2=hd:LABEL=SYNCA_UTM_9", line)
        line = re.sub(r"\s+inst\.repo=\S+", "", line)
        if "inst.stage2=" in line and "inst.repo=" not in line:
            line += " inst.repo=hd:LABEL=SYNCA_UTM_9"
        if "rd.multipath=0" not in line:
            line += " rd.multipath=0"
        if "inst.nompath" not in line:
            line += " inst.nompath"
    lines.append(line)

synca_block = """\
label synca-utm
  menu label Install SyncA UTM
  menu default
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.ks=hd:LABEL=SYNCA_UTM_9:/ks/synca-utm.ks rd.multipath=0 inst.nompath quiet
"""
for idx, line in enumerate(lines):
    if line.startswith("label "):
        lines[idx:idx] = synca_block.rstrip("\n").splitlines() + [""]
        break
else:
    lines.extend([""] + synca_block.rstrip("\n").splitlines())
path.write_text("\n".join(lines) + "\n")
PY
}

patch_grub() {
    local cfg="${BUILD_DIR}/bootcfg/EFI/BOOT/grub.cfg"
    [[ -f "$cfg" ]] || return 0
    python3 - "$cfg" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()
lines = []
skip_synca = False
brace_depth = 0
for line in text.splitlines():
    stripped = line.lstrip()
    if not skip_synca and "menuentry 'Install SyncA UTM'" in line:
        skip_synca = True
        brace_depth = line.count("{") - line.count("}")
        continue
    if skip_synca:
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            skip_synca = False
        continue
    if stripped.startswith("set default="):
        line = 'set default="synca-utm"'
    if "search --no-floppy --set=root -l " in line:
        line = "search --no-floppy --set=root -l 'SYNCA_UTM_9'"
    if stripped.startswith(("linux ", "linuxefi ")):
        line = re.sub(r"inst\.stage2=\S+", "inst.stage2=hd:LABEL=SYNCA_UTM_9", line)
        line = re.sub(r"\s+inst\.repo=\S+", "", line)
        if "inst.stage2=" in line and "inst.repo=" not in line:
            line += " inst.repo=hd:LABEL=SYNCA_UTM_9"
        if "rd.multipath=0" not in line:
            line += " rd.multipath=0"
        if "inst.nompath" not in line:
            line += " inst.nompath"
    lines.append(line)

if not any(line.lstrip().startswith("set default=") for line in lines):
    lines.insert(0, 'set default="synca-utm"')

synca_block = """\
menuentry 'Install SyncA UTM' --id synca-utm --class fedora --class gnu-linux --class gnu --class os {
    linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.ks=hd:LABEL=SYNCA_UTM_9:/ks/synca-utm.ks rd.multipath=0 inst.nompath quiet
    initrdefi /images/pxeboot/initrd.img
}
"""
for idx, line in enumerate(lines):
    if "menuentry " in line:
        lines[idx:idx] = synca_block.rstrip("\n").splitlines() + [""]
        break
else:
    lines.extend([""] + synca_block.rstrip("\n").splitlines())
path.write_text("\n".join(lines) + "\n")
PY
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
    if [[ "$SYNC_PRUNE_DVD_REPOS" == "1" && -n "$RPM_DIR_SRC" ]]; then
        if [[ ! -d "${RPM_DIR_SRC%/}/BaseOS" || ! -d "${RPM_DIR_SRC%/}/AppStream" ]]; then
            echo "SYNC_PRUNE_DVD_REPOS=1 requires RPM_DIR_SRC with BaseOS and AppStream directories." >&2
            exit 1
        fi
        cmd+=(
            -rm_r /BaseOS /AppStream --
            -map "${RPM_DIR_SRC%/}/BaseOS" /BaseOS
            -map "${RPM_DIR_SRC%/}/AppStream" /AppStream
        )
    fi
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
