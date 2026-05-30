# iso/README.md
# SyncA UTM ISO build workflow

This directory contains the installer payload used to build a SyncA UTM
installation ISO from an AlmaLinux 9.x DVD ISO. Extra RPMs are optional and
should be limited to packages that are not present on the DVD.

The Anaconda installer screen intentionally uses ASCII English labels. Some
bare-metal installer consoles cannot render Japanese reliably before the OS
font and locale packages are installed. Japanese is used after first boot in
the web GUI.

## Build

Run from WSL or another Linux environment:

```bash
./scripts/build-synca-utm-iso.sh
```

Useful environment variables:

- `ALMA_ISO`: local AlmaLinux DVD ISO path.
- `ALMA_ISO_URL`: source URL used when `ALMA_ISO` does not exist.
- `BUILD_DIR`: build workspace. Default: `output/iso-build`.
- `OUTPUT_ISO`: generated ISO path. Default: `output/SyncA-UTM-AlmaLinux-9.iso`.
- `SYNC_BUILD_WHEELHOUSE=1`: download Python wheels for `server-gui`.
- `WHEELHOUSE_SRC`: copy a prebuilt Python wheelhouse directory.
- `RPM_DIR_SRC`: copy additional RPMs that are not present on the DVD.
- `WGUI_BINARY`: optional local `wireguard-ui` binary to include.
- `SYNC_PREPARE_ONLY=1`: prepare payload files without downloading or writing an ISO.

## Install Flow

1. Boot the generated ISO.
2. Select `Install SyncA UTM`.
3. AlmaLinux installs with the embedded Kickstart.
4. On first boot, `synca-firstboot.service` starts an ASCII console setup.
5. Enter WAN/LAN/admin/VPN values.
6. The management GUI starts at `https://<LAN-IP>:4444/`.

DDNS registration is not created during install. Register DDNS from the GUI
after the first WAN connection is confirmed.
