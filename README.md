# nm-openvpn3

NetworkManager VPN plugin for the OpenVPN 3 Linux D-Bus stack
(`net.openvpn.v3.*`).

[![CI](https://github.com/dione/nm-openvpn3/actions/workflows/ci.yml/badge.svg)](https://github.com/dione/nm-openvpn3/actions/workflows/ci.yml)

This is a fork of [GNOME/NetworkManager-openvpn][upstream] (1.12.5,
upstream commit 9514bde) rewired to drive
[OpenVPN/openvpn3-linux][ovpn3] via D-Bus instead of the legacy
`openvpn` v2 fork+exec path.  Upstream still talks to a management
socket; this fork talks to `net.openvpn.v3.configuration`,
`net.openvpn.v3.sessions`, and `net.openvpn.v3.netcfg`.

[upstream]: https://gitlab.gnome.org/GNOME/NetworkManager-openvpn
[ovpn3]: https://github.com/OpenVPN/openvpn3-linux

## What you get

- **VPN type "OpenVPN 3"** in `nm-connection-editor` next to the regular
  OpenVPN entry.  Same dialog layout, fewer openvpn2-only fields.
- **`.ovpn` profile file chooser** on the main tab — point at a verbatim
  config and `openvpn3` interprets it directly.  Preserves
  `tls-crypt-v2`, `peer-fingerprint`, `data-ciphers`, and other modern
  syntax the upstream token parser drops.
- **Five SetOverride toggles** in the Misc tab (route-nopull,
  force-default-gateway, block-ipv6, dns-setup-disabled, dco) that map
  to `net.openvpn.v3.configuration.SetOverride` after Import.
- **Live DNS + routes** pushed from `openvpn3`'s netcfg device into
  NetworkManager via the standard SetIp4Config bundle.
- **Split-tunnel detection**: if the profile does not redirect default
  gateway, NM gets `NEVER_DEFAULT=TRUE` so it does not promote the VPN
  to the system default route.
- **Periodic session statistics** (bytes / packets, every 30 s) emitted
  to the journal under `SYSLOG_IDENTIFIER=nm-openvpn3-service`.
- **AttentionRequired / UserInputQueue** plumbing (v0.6.0-alpha,
  untested end-to-end — needs a password-protected openvpn3 server to
  smoke test; see `docs/PLAN-2-SMOKE-TEST.md`).

## Build & install

Build dependencies (Fedora package names; Debian / Ubuntu equivalents
in parens):

    autoconf, automake, autopoint, gettext-devel (gettext)
    libtool, pkg-config
    glib2-devel (libglib2.0-dev)
    gtk3-devel (libgtk-3-dev)
    gtk4-devel (libgtk-4-dev)            — needed for --with-gtk4
    libsecret-devel (libsecret-1-dev)
    libnma-devel (libnma-dev)
    libnma-gtk4-devel (libnma-gtk4-dev)  — needed for --with-gtk4
    NetworkManager-libnm-devel (libnm-dev), libnm >= 1.52.2

Build:

    autoreconf -fis
    ./configure --prefix=/usr --libexecdir=/usr/libexec --sysconfdir=/etc \
                --with-gnome --with-gtk4
    make
    sudo make install

Reload the system bus so NetworkManager picks up the new
`.name` file and `.so` plugins:

    sudo systemctl reload dbus

If you build with the default `--prefix=/usr/local`, the binaries land
under `/usr/local/libexec/` but NetworkManager still looks for them
under `/usr/libexec/`.  Use the prefix line above.

## Usage

### Via the GUI

1. Open `nm-connection-editor`.
2. **+** → **OpenVPN 3** → **Create…**
3. **Brama**: paste your remote (host[:port[:proto]]).
4. **OVPN profile file**: click **Browse…**, point at the `.ovpn`.
   Keeps the file readable by the `nm-openvpn3` service uid.
5. **Save** and activate from the NM applet.

### Via nmcli

    nmcli connection add type vpn vpn-type openvpn3 con-name my-vpn \
        vpn.data 'nm-openvpn3-profile=/path/to/profile.ovpn,connection-type=tls'
    nmcli connection up my-vpn

For the legacy token-import flow:

    nmcli connection import type openvpn3 file /path/to/profile.ovpn

This route walks the upstream `do_import()` parser, which has known gaps
for modern openvpn3 syntax (`peer-fingerprint`, recent `--data-cipher`
forms).  Prefer the profile-file path above unless you specifically
need to edit individual options through the UI.

## Diagnostics

    journalctl -t nm-openvpn3-service -f
    journalctl _COMM=nm-openvpn3-ser --since '5 min ago' | grep stats

Stats lines emit every 30 s under the `stats:` tag; counters are read
from `net.openvpn.v3.sessions.statistics`.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the D-Bus topology,
component map, and connect / disconnect / auth flows.

## Roadmap

The full project history lives in [docs/FORK.md](docs/FORK.md).
At a glance:

- v0.1.0 — fork skeleton
- v0.2.0 — TLS-cert Connect/Disconnect
- v0.3.x — DNS + routes + ACL + split-tunnel + watchdog
- v0.4.x — UI plugin in nm-connection-editor + advanced-dialog trim
- v0.5.x — profile file chooser, SetOverride toggles, service cleanup,
  StatusChange signal, CI + ASAN, session statistics, auth-dialog +
  editor.c simplifier passes
- v0.6.0-alpha — interactive auth (AttentionRequired / UserInputQueue),
  awaiting smoke test against a password-protected openvpn3 server.

## License

GPL-2.0-or-later, inherited from upstream.  See `COPYING`.
