# SyncA UTM

SyncA UTM is an AlmaLinux 9 based UTM/router appliance project. It provides a local management GUI for network, firewall, VPN, DNS/DHCP, DDNS, certificate, backup, fail2ban, and Nginx reverse proxy operations.

## Current Status

This repository is being prepared for an installable offline ISO. The current tree contains the server GUI payload and implementation notes needed to reproduce the manually validated appliance behavior.

Validated target baseline:

- AlmaLinux 9.x, currently validated on AlmaLinux 9.8.
- WAN modes: DHCP, Static IP, PPPoE.
- LAN DHCP/DNS and NAT through Firewalld.
- WireGuard and strongSwan management.
- DDNS with `ddnsft.com`.
- Let's Encrypt certificate issuance and renewal.
- Nginx reverse proxy with optional WAF controls.
- fail2ban status, jail synchronization, unban, and ignore IP management.
- Offline Bootstrap and Bootstrap Icons assets.

## Repository Layout

- `payload/server-gui/`: SyncA UTM management GUI application and helper scripts.
- `payload/firewalld-profiles/`: variable-based Firewalld profile templates for ISO installation.
- `scripts/`: bootstrap and verification scripts used while preparing the ISO installer.
- `docs/`: public design notes and ISO requirements.

Local investigation artifacts, captured server state, credentials, private keys, logs, screenshots, generated bundles, and test outputs are intentionally excluded from Git.

## Public Update Source

Installed appliances use this repository as their default update source:

```text
https://github.com/yoshinsk/SyncA_UTM
```

The management GUI checks the configured branch, downloads the GitHub archive, and updates the deployed `server_gui` package from `payload/server-gui/server_gui`.

## Security

Do not commit appliance backups, `evidence/`, `/etc/server-gui`, WireGuard keys, IPsec PSKs, DDNS credentials, Let's Encrypt private keys, NetworkManager connection secrets, or server logs.

If this repository was previously private and contained real appliance artifacts, rotate any credentials that were ever committed before making the repository public.

## License

License is currently proprietary unless a separate license file is added.
