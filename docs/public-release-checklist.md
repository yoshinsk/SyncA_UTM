# docs/public-release-checklist.md
# Public Repository Release Checklist

## Required Before Changing Visibility

- Remove `evidence/` and generated test output from Git tracking.
- Ensure `.gitignore` excludes local investigation artifacts and appliance backups.
- Remove hardcoded DDNS, GUI, PPPoE, SSH, IPsec, and WireGuard credentials.
- Ensure default GitHub update URL is `https://github.com/yoshinsk/SyncA_UTM`.
- Verify update code can consume the public repository archive layout.
- Rewrite public branch history if real secrets were committed while the repository was private.
- Confirm no tags or extra remote branches point to the old private history.

## Runtime Secrets

The installer must collect or generate these values locally:

- Linux and GUI administrator password.
- DDNSFT authentication user and password.
- PPPoE credentials.
- WireGuard private keys and preshared keys.
- IPsec PSKs or certificate credentials.
- Flask session secret.
- Let's Encrypt account and private keys.

These values must never be stored in the public repository.
