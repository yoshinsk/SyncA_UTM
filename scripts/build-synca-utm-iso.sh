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
SYNCA_PRIVATE_FIRSTBOOT_ENV="${SYNCA_PRIVATE_FIRSTBOOT_ENV:-}"
SYNCA_INITIAL_ADMIN_USER="${SYNCA_INITIAL_ADMIN_USER:-}"
SYNCA_INITIAL_ADMIN_PASSWORD="${SYNCA_INITIAL_ADMIN_PASSWORD:-}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required tool not found: $1" >&2
        exit 1
    fi
}

normalize_lf_text_tree() {
    # Build inputs can include private env/drop-in files prepared on Windows.
    # Normalize only known text files so offline RPMs, wheels, archives, fonts,
    # and bundled binaries remain byte-for-byte intact.
    local root="$1"
    [[ -d "$root" ]] || return 0
    find "$root" -type f \( \
        -name '*.sh' -o -name '*.ks' -o -name '*.env' -o -name '*.conf' \
        -o -name '*.service' -o -name '*.timer' -o -name '*.json' \
        -o -name '*.py' -o -name '*.html' -o -name '*.css' -o -name '*.js' \
        -o -name '*.txt' -o -name '*.md' -o -name '*.ini' \
        -o -name '*.yaml' -o -name '*.yml' -o -name '*.xml' -o -name '*.j2' \
    \) -exec sed -i 's/\r$//' {} +
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
    if [[ -n "$SYNCA_INITIAL_ADMIN_USER" || -n "$SYNCA_INITIAL_ADMIN_PASSWORD" ]]; then
        if [[ -z "$SYNCA_INITIAL_ADMIN_USER" || -z "$SYNCA_INITIAL_ADMIN_PASSWORD" ]]; then
            echo "SYNCA_INITIAL_ADMIN_USER and SYNCA_INITIAL_ADMIN_PASSWORD must be set together." >&2
            exit 1
        fi
        python3 - "${BUILD_DIR}/payload/ks/synca-utm.ks" \
            "$SYNCA_INITIAL_ADMIN_USER" "$SYNCA_INITIAL_ADMIN_PASSWORD" <<'PY'
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
user = shlex.quote(sys.argv[2])
password = shlex.quote(sys.argv[3])
text = path.read_text()
marker = "%post --log=/root/synca-utm-post.log\nset -euxo pipefail\n"
block = f"""set -euxo pipefail
if ! id {user} >/dev/null 2>&1; then
    useradd -m -G wheel {user}
fi
printf '%s:%s\\n' {user} {password} | chpasswd
install -d -m 0750 /etc/sudoers.d
echo "%wheel ALL=(ALL) ALL" > /etc/sudoers.d/10-synca-wheel
chmod 0440 /etc/sudoers.d/10-synca-wheel
"""
if marker not in text:
    raise SystemExit("kickstart post marker not found")
path.write_text(text.replace(marker, "%post --log=/root/synca-utm-post.log\n" + block, 1))
PY
        echo "Included initial admin user for internal ISO."
    fi
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
    if [[ -n "$SYNCA_PRIVATE_FIRSTBOOT_ENV" ]]; then
        if [[ ! -f "$SYNCA_PRIVATE_FIRSTBOOT_ENV" ]]; then
            echo "SYNCA_PRIVATE_FIRSTBOOT_ENV does not exist: $SYNCA_PRIVATE_FIRSTBOOT_ENV" >&2
            exit 1
        fi
        mkdir -p "${BUILD_DIR}/payload/synca/private"
        install -m 0600 "$SYNCA_PRIVATE_FIRSTBOOT_ENV" \
            "${BUILD_DIR}/payload/synca/private/firstboot.env"
        echo "Included private firstboot environment for internal ISO."
    fi
    if [[ -n "$WGUI_BINARY" ]]; then
        install -m 0755 "$WGUI_BINARY" "${BUILD_DIR}/payload/synca/wireguard-ui"
    fi
    if [[ -n "$RPM_DIR_SRC" && -d "${RPM_DIR_SRC%/}/SyncA-Extra" ]]; then
        mkdir -p "${BUILD_DIR}/payload/synca/rpms"
        rsync -a "${RPM_DIR_SRC%/}/SyncA-Extra/" "${BUILD_DIR}/payload/synca/rpms/"
    fi
    normalize_lf_text_tree "${BUILD_DIR}/payload"
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
header = []
for line in text.splitlines():
    stripped = line.lstrip()
    if line.startswith(("label ", "menu begin ")):
        break
    if stripped.startswith("timeout "):
        line = "timeout 150"
    if stripped.startswith("menu title "):
        line = "menu title SyncA UTM Installer"
    header.append(line)

menu_block = """\
label synca-utm
  menu label Install SyncA UTM
  menu default
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.ks=hd:LABEL=SYNCA_UTM_9:/ks/synca-utm.ks rd.multipath=0 inst.nompath quiet

menu begin ^Troubleshooting
  menu title Troubleshooting

label text
  menu label Install SyncA UTM using ^text mode
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.ks=hd:LABEL=SYNCA_UTM_9:/ks/synca-utm.ks inst.text rd.multipath=0 inst.nompath quiet

label rescue
  menu label ^Rescue an installed system
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.rescue rd.multipath=0 inst.nompath quiet

label local
  menu label Boot from ^local drive
  localboot 0xffff

label returntomain
  menu label Return to ^main menu
  menu exit

menu end
"""
while header and not header[-1].strip():
    header.pop()
path.write_text("\n".join(header) + "\n\n" + menu_block.rstrip("\n") + "\n")
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
skipping_entry = False
skipping_submenu = False
brace_depth = 0
for line in text.splitlines():
    stripped = line.lstrip()
    if stripped.startswith(("menuentry ", "submenu ")):
        skipping_entry = stripped.startswith("menuentry ")
        skipping_submenu = stripped.startswith("submenu ")
        brace_depth = line.count("{") - line.count("}")
        continue
    if skipping_entry or skipping_submenu:
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            skipping_entry = False
            skipping_submenu = False
        continue
    if stripped.startswith("set default="):
        line = 'set default="synca-utm"'
    if stripped.startswith("set timeout="):
        line = "set timeout=15"
    if "search --no-floppy --set=root -l " in line:
        line = "search --no-floppy --set=root -l 'SYNCA_UTM_9'"
    lines.append(line)

if not any(line.lstrip().startswith("set default=") for line in lines):
    lines.insert(0, 'set default="synca-utm"')

menu_block = """\
menuentry 'Install SyncA UTM' --id synca-utm --class fedora --class gnu-linux --class gnu --class os {
    linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.ks=hd:LABEL=SYNCA_UTM_9:/ks/synca-utm.ks rd.multipath=0 inst.nompath quiet
    initrdefi /images/pxeboot/initrd.img
}

submenu 'Troubleshooting' {
    menuentry 'Install SyncA UTM using text mode' --class fedora --class gnu-linux --class gnu --class os {
        linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.ks=hd:LABEL=SYNCA_UTM_9:/ks/synca-utm.ks inst.text rd.multipath=0 inst.nompath quiet
        initrdefi /images/pxeboot/initrd.img
    }
    menuentry 'Rescue an installed system' --class fedora --class gnu-linux --class gnu --class os {
        linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=SYNCA_UTM_9 inst.repo=hd:LABEL=SYNCA_UTM_9 inst.rescue rd.multipath=0 inst.nompath quiet
        initrdefi /images/pxeboot/initrd.img
    }
}
"""
while lines and not lines[-1].strip():
    lines.pop()
path.write_text("\n".join(lines) + "\n\n" + menu_block.rstrip("\n") + "\n")
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
    normalize_lf_text_tree "${BUILD_DIR}/bootcfg"
    build_iso
    echo "ISO created: $OUTPUT_ISO"
}

main "$@"
