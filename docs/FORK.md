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

- Plan 0 (done, v0.1.0-skeleton) — fork skeleton, Connect stubbed
- Plan 1 (done, v0.2.0-mvp) — TLS-cert Connect/Disconnect happy path via net.openvpn.v3.*
- Plan 1b (done, v0.3.0) — DNS + search domains via netcfg device
- Plan 1c (done, v0.3.1) — VPN routes forwarded to NM for display
- Plan 1d/1e (done, v0.3.2/v0.3.3) — D-Bus retry, session ACL, split-tunnel, watchdog
- Plan 3 (done, v0.4.0) — UI plugin appears in nm-connection-editor (libdir multiarch + GObject type rename)
- Plan 3b (done, v0.4.1) — UI plugin: hide openvpn2-only advanced-dialog widgets (LZO compress, legacy keysize, cipher-fallback / no-cipher-nego, ns-cert-type, TLS cipher string, push-peer-info)
- Plan 3c (done, v0.4.2) — UI plugin: excise openvpn2-only widget code paths + .ui defs (read/write paths in advanced_dialog_new(), 13 widget defs from nm-openvpn3-dialog.ui, dead helpers); vpn.data keys + service args + import-export round-trip retained for raw .ovpn compat
- Plan 2 — auth-dialog around AttentionRequired / UserInputQueue
- Plan 3d — UI plugin: surface openvpn3 SetOverride keys (allow-compression, dco, etc.); drop dead service args builders if confirmed unreachable
