# nm-openvpn3 — Rust port

Experimental Rust rewrite of the service binary
(`/usr/libexec/nm-openvpn3-service` in the C tree).  Lives side-by-side
with the C plugin so a single host can run both during development:

| C plugin                                          | Rust port                                              |
|---------------------------------------------------|--------------------------------------------------------|
| service bus name `org.freedesktop.NetworkManager.openvpn3`     | `org.freedesktop.NetworkManager.openvpn3rust`          |
| binary `/usr/libexec/nm-openvpn3-service`                       | `/usr/libexec/nm-openvpn3-rust-service`                |
| `.name` file `nm-openvpn3-service.name`                         | `nm-openvpn3-rust-service.name`                        |
| `vpn-type=openvpn3` connections                                 | `vpn-type=openvpn3rust` connections                    |

`vpn-type` differs, so NM dispatches each connection to whichever
plugin its `vpn.service-type` matches.  The two never compete for the
same connection.

The Rust port reuses the C tree's editor `.so` files (libnm-vpn-plugin
GObject world; porting those is Phase 4 work), so for now a Rust-typed
connection is created by hand-editing the `.nmconnection` file or via
`nmcli`.

## Phases

- **Phase 1** (shipped) — Cargo workspace, zbus-based openvpn3-linux
  client, skeleton main loop.
- **Phase 2** (this commit) — NMVpnPlugin D-Bus interface (methods
  only: Connect / ConnectInteractive / NeedSecrets / Disconnect /
  NewSecrets), Connect dispatcher (read profile → Import →
  SetOverrides → NewTunnel → wait_ready → Connect), Disconnect
  teardown.  No outbound signals yet (StateChanged / Ip4Config /
  Failure / SecretsRequired) — NM sees method calls succeed but
  cannot promote the connection to ACTIVATED.
- **Phase 3** (future) — wire StatusChange subscription, emit
  Ip4Config + StateChanged + Failure so NM completes the activation.
  Port poll_status_cb + emit_started_ip4_config + stats timer.
- **Phase 4** (future) — Plan 2 (AttentionRequired / UserInputQueue).
- **Phase 5** (future) — port editor `.so` (libnm-vpn-plugin GObject,
  needs libnm-glib bindings or a thin C bridge).

## Build

    cd rust
    cargo build --release
    # Binary: rust/target/release/nm-openvpn3-service

## Install (manual, for testing)

    sudo install -m 0755 target/release/nm-openvpn3-service \
        /usr/libexec/nm-openvpn3-rust-service
    sudo sed -e "s|@LIBEXECDIR@|/usr/libexec|g" \
             -e "s|@PLUGINDIR@|/usr/lib/x86_64-linux-gnu/NetworkManager|g" \
             nm-openvpn3-rust-service.name \
        > /tmp/nm-openvpn3-rust-service.name
    sudo install -m 0644 /tmp/nm-openvpn3-rust-service.name \
        /usr/lib/NetworkManager/VPN/nm-openvpn3-rust-service.name
    sudo systemctl reload dbus

Create a test connection (replace `<path>` with a profile file path):

    nmcli connection add type vpn vpn-type openvpn3rust \
        con-name ovpn3-rust-test \
        vpn.data 'nm-openvpn3-profile=<path>,connection-type=tls'

## Status

Phase 2 binary claims its bus name, NM enumerates the plugin (visible
in `nm-connection-editor`'s VPN list once the editor `.so` is taught
about the new service type — for now invisible there), and Connect /
Disconnect method calls reach openvpn3-linux through `zbus`.  Without
StateChanged / Ip4Config signals NM will time out the activation.
