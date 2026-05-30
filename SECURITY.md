# SECURITY.md

## Supported Security Boundary

SyncA UTM manages firewall, VPN, DDNS, certificate, and reverse proxy settings. Treat all appliance backups and runtime configuration as secret material.

Never publish:

- `/etc/server-gui`
- `/etc/wireguard`
- `/etc/swanctl` or `/etc/strongswan` secrets
- `/etc/letsencrypt`
- `/etc/NetworkManager/system-connections`
- `/var/lib/server-gui/backups`
- DDNS credentials
- IPsec PSKs
- WireGuard private keys and preshared keys
- GUI credential hashes
- captured production logs

## Reporting

For now, report security issues privately to the repository owner. Do not open a public issue containing exploit details or secrets.
