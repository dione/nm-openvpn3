# nm-openvpn3 fork notes

This repository is a fork of GNOME/NetworkManager-openvpn (1.12.5,
upstream commit 9514bde) adapted to act as a NetworkManager VPN
plugin for the OpenVPN 3 Linux D-Bus stack (net.openvpn.v3.*).

## Differences from upstream

- Plugin D-Bus name: `org.freedesktop.NetworkManager.openvpn3`
- Binaries: `nm-openvpn3-service`, `nm-openvpn3-auth-dialog`,
  `libnm-vpn-plugin-openvpn3.so`, `libnm-openvpn3-properties.so`
- System user: `nm-openvpn3` (chroot under `/var/lib/openvpn3/chroot`)
- Connect path: proxies to `net.openvpn.v3.sessions` via D-Bus
  instead of fork+exec'ing the `openvpn` v2 binary

## Maintaining against upstream

`upstream` remote tracks `gitlab.gnome.org/GNOME/NetworkManager-openvpn`.
To pull future upstream fixes:

    git fetch upstream
    git merge upstream/master   # or rebase; expect conflicts in rename hot spots

Renames live in `git log --diff-filter=R` and are easy to follow because
the openvpn3 prefix is applied uniformly.

## Roadmap

- Plan 0 (this) — fork skeleton, no functional Connect
- Plan 1 — service translator to net.openvpn.v3.sessions
- Plan 2 — auth-dialog rewrite for OpenVPN 3 challenge-response
- Plan 3 — UI plugin (.so) for nm-connection-editor + GNOME Settings
