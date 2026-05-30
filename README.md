# SyncA UTM

SyncA UTM is an AlmaLinux 9 based UTM/router appliance project. It provides a local management GUI for network, firewall, VPN, DNS/DHCP, DDNS, certificates, backup, fail2ban, and Nginx reverse proxy operations.

## Status

This repository is prepared as the public update source for SyncA UTM appliances and as the source tree for building an installable offline ISO.

Validated target baseline:

- AlmaLinux 9.x, currently validated on AlmaLinux 9.8.
- Offline install ISO based on `AlmaLinux-9-latest-x86_64-dvd.iso`.
- First boot console setup for administrator, WAN, LAN, DHCP, WireGuard, and DDNS host label.
- Initial access to the management GUI from both WAN and LAN when firewalld policy allows it.

## Main Features

### Network

- WAN modes: DHCP client, Static IP, and PPPoE.
- LAN address and DHCP range setup.
- Static routes.
- Secondary IP addresses on WAN and LAN interfaces.
- VLAN tagged interfaces.
- Multi-NIC bridge setup with STP control for LAN switching use cases.
- PPPoE MTU/MSS handling for black-hole avoidance.

### Firewall

- firewalld based routing and filtering.
- NAT/masquerade for LAN to WAN internet access.
- Country IP set preparation for Japan on first successful internet access.
- Template based firewalld profiles for ISO installation.
- GUI support for easier rule management, including custom rule preservation.
- VPN tunnel creation can add required firewall allowances for peer networks.

### VPN

- WireGuard server and client management.
- strongSwan site-to-site IPsec management.
- Automatic firewall opening for site-to-site peer networks where possible.

### DNS and DHCP

- dnsmasq based LAN DNS/DHCP.
- DHCP options import and preview support.
- Local DHCP scope management from the GUI.

### DDNS and Certificates

- `ddnsft.com` DDNS host label management.
- Existing host detection before registration.
- 4 digit PIN based overwrite approval for existing DDNS host labels.
- PIN email delivery through build-time or runtime SMTP configuration.
- Let's Encrypt certificate issuance and renewal.

### Nginx Reverse Proxy and WAF

- Nginx SSL acceleration / reverse proxy management.
- Let's Encrypt challenge path handling.
- ModSecurity / WAF controls when the module is installed.
- ISO package set includes the modules needed to avoid missing WAF dependency warnings.
- Large XML upload support for Sophos import preview.

### fail2ban

- Public service discovery and jail synchronization.
- Ban list display with reason where available.
- Unban operation.
- Move banned IP addresses into ignore IP.
- Japanese status messages for unsupported automatic filters.

### Backup

- Appliance backup from the GUI.
- Default retention: 10 generations or 2 GiB total, deleting older backups first.

### Sophos SG UTM Import

- Sophos SG UTM XML import preview.
- Remote access settings are intentionally excluded from automatic restoration.
- Import preview maps supported settings into SyncA UTM forms:
  - interfaces
  - static routes
  - DHCP server settings
  - DHCP options
  - site-to-site VPN values for strongSwan
  - Nginx reverse proxy values
  - DDNS related FQDN candidates
  - certificates and private key material where useful
- WebAdmin and local user X509 certificates are filtered out because they are not needed for SyncA UTM restoration.

## Repository Layout

- `payload/server-gui/`: SyncA UTM management GUI application and helper scripts.
- `payload/firewalld-profiles/`: variable-based firewalld profile templates for ISO installation.
- `iso/`: Kickstart and installer payload used by the offline ISO.
- `scripts/`: bootstrap, verification, and ISO build scripts.
- `docs/`: public design notes and ISO requirements.

Local investigation artifacts, captured server state, credentials, private keys, logs, screenshots, generated bundles, and test outputs are intentionally excluded from Git.

## ISO Build

The public build path does not contain private SMTP, DDNS, certificate, VPN, or appliance credentials.

Internal ISO builds can inject private SMTP settings at build time by passing a local systemd drop-in file through `SYNCA_PRIVATE_SMTP_DROPIN`. The drop-in is copied into the ISO payload and installed under:

```text
/etc/systemd/system/server-gui.service.d/30-ddns-pin-smtp.conf
/etc/systemd/system/server-gui-ddns.service.d/30-ddns-pin-smtp.conf
```

Example build variables:

```bash
SYNCA_PRIVATE_SMTP_DROPIN=/root/synca-internal-smtp/server-gui-ddns-smtp.conf \
RPM_DIR_SRC=/root/synca-install-repos \
SYNC_PRUNE_DVD_REPOS=1 \
SYNC_BUILD_WHEELHOUSE=1 \
ALMA_ISO=/root/SyncA_UTM_build/output/iso-build/AlmaLinux-9-latest-x86_64-dvd.iso \
OUTPUT_ISO=/root/SyncA-UTM-AlmaLinux-9-internal.iso \
./scripts/build-synca-utm-iso.sh
```

## Public Update Source

Installed appliances use this repository as their default update source:

```text
https://github.com/yoshinsk/SyncA_UTM
```

The management GUI checks the configured branch, downloads the GitHub archive, and updates the deployed `server_gui` package from `payload/server-gui/server_gui`.

## Security

Do not commit appliance backups, `evidence/`, `/etc/server-gui`, WireGuard keys, IPsec PSKs, DDNS credentials, SMTP credentials, Let's Encrypt private keys, NetworkManager connection secrets, or server logs.

The `.gitignore` excludes generated ISO output and common private credential file types. Keep internal ISO-only materials outside the repository or under ignored local paths.

If this repository was previously private and contained real appliance artifacts, rotate any credentials that were ever committed before making the repository public.

## License

License is currently proprietary unless a separate license file is added.
