# nm-openvpn3 — Rust port

Rust rewrite of the NetworkManager VPN service for OpenVPN 3 Linux.
Lives side-by-side with the C plugin so a single host can run both
during development; NM dispatches per-connection based on the
`vpn-type` field, so the two never compete.

## Side-by-side identifiers

| Field | C plugin | Rust port |
|---|---|---|
| service bus name | `org.freedesktop.NetworkManager.openvpn3` | `org.freedesktop.NetworkManager.openvpn3.rust` |
| binary | `/usr/libexec/nm-openvpn3-service` | `/usr/libexec/nm-openvpn3-rust-service` |
| auth-dialog binary | `/usr/libexec/nm-openvpn3-auth-dialog` | `/usr/libexec/nm-openvpn3-rust-auth-dialog` |
| `.name` file | `nm-openvpn3-service.name` | `nm-openvpn3-rust-service.name` |
| `vpn-type=` | `openvpn3` | `openvpn3.rust` |

The dot in `openvpn3.rust` is intentional — D-Bus `own_prefix` policy
matches on dot boundaries, so the Rust service needs the dot for its
bus name to be allowed.  `openvpn3rust` (no dot) would be rejected by
the system bus.

## Workspace layout

- `ovpn3-client` — async zbus 5 client for the openvpn3-linux D-Bus
  stack (configuration manager, sessions manager, session,
  netcfg-device).
- `nm-openvpn3-service` — the `NMVpnServicePlugin` interface
  implementation.  Status poller + StatusChange listener,
  AttentionRequired (Plan 2) auto-provide + NewSecrets dispatch,
  Ip4Config emit, stats timer.
- `nm-openvpn3-auth-dialog` — external-UI-mode-only auth-dialog
  binary.  No GTK / libsecret deps — emits the GKeyFile NM agents
  (gnome-shell, plasma-nm, nm-applet) consume.

## Status

End-to-end working against openvpn3-linux v27:

- Connect / Disconnect flow drives openvpn3 + emits the
  StateChanged, Config, Ip4Config, Failure, SecretsRequired,
  LoginBanner signals NM listens for.
- Status poller handles the unicast-StatusChange gap with a
  device-name fallback probe.
- Plan 2 auth: AttentionRequired listener drains
  UserInputQueue, auto-provides credentials persisted in
  vpn.data / vpn.secrets, asks NM for the rest, and feeds the
  reply back via ProvideInput.
- Auth-dialog covers the external-UI-mode contract NM uses in
  every modern desktop integration.

The `.name` file deliberately does not point at the C tree's
`libnm-vpn-plugin-openvpn3.so` / `libnm-vpn-plugin-openvpn3-editor.so`
— those libraries hard-code the C service name, so loading them
under the Rust service-type makes gnome-control-center log
"invalid service name".  The runtime path is unaffected (NM
spawns the auth-dialog binary directly from `[GNOME]
auth-dialog=`); the GUI editor just lists the plugin without
property pages until a Rust libnm-vpn-plugin cdylib lands.

## Build + install

    cd rust
    cargo build --release
    bash install-test.sh

`install-test.sh` auto-detects the NetworkManager plugin directory
(`gcc -dumpmachine` for the multiarch triplet, falls back to
`/usr/lib64/NetworkManager` and `/usr/lib/NetworkManager`),
installs the service + auth-dialog binaries to `/usr/libexec`,
renders the `.name` file with the right paths, and reloads dbus.

Create a test connection (replace `<path>` with a profile path):

    nmcli connection add type vpn vpn-type openvpn3.rust \
        con-name ovpn3-rust-test \
        vpn.data 'nm-openvpn3-profile=<path>,connection-type=tls'

Activate + tail the journal:

    nmcli connection up ovpn3-rust-test
    # Kernel truncates comm to TASK_COMM_LEN=16, so `nm-openvpn3-rust-service`
    # shows up in journald as `nm-openvpn3-rus` (15 chars).
    journalctl --since '1 min ago' _COMM=nm-openvpn3-rus
