# Architecture

`nm-openvpn3` is a NetworkManager VPN plugin that drives the OpenVPN 3
Linux D-Bus stack instead of forking the legacy `openvpn` v2 binary.
This document describes the component layout, the D-Bus topology, and
the lifetime of a single VPN activation.

## Component map

```
┌─────────────────────────────────────────────────────────────────────┐
│ User session                                                        │
│                                                                     │
│  nm-connection-editor   nm-applet / nmcli                           │
│         │                       │                                   │
│         │ (libnm)                │ (NM D-Bus)                       │
│         ▼                       ▼                                   │
│  libnm-vpn-plugin-openvpn3-editor.so       (UI plugin, in-process)  │
│         │                                                           │
└─────────┼───────────────────────┬───────────────────────────────────┘
          │                       │
          │ ┌─────────────────────┴────────────────────────────────┐
          │ │ NetworkManager (system, uid 0)                       │
          │ │                                                      │
          │ │  spawns on demand:                                   │
          │ │    /usr/libexec/nm-openvpn3-service   (us)           │
          │ │    /usr/libexec/nm-openvpn3-auth-dialog (secrets)    │
          │ │                                                      │
          │ └──────────┬─────────────────────────┬─────────────────┘
          │            │ (system bus)            │ (system bus)
          │            ▼                         ▼
          │  org.freedesktop.NetworkManager.openvpn3
          │            │                         │
          │            │ (talks to openvpn3 via system bus)
          │            ▼
┌─────────┴────────────────────────────────────────────────────────────┐
│ openvpn3-linux daemons (auto-activated by D-Bus)                     │
│                                                                      │
│  net.openvpn.v3.configuration   (configmgr)                          │
│  net.openvpn.v3.sessions        (sessmgr → backend client per VPN)   │
│  net.openvpn.v3.netcfg          (network setup, DNS via resolved)    │
│  net.openvpn.v3.log             (log relay)                          │
└──────────────────────────────────────────────────────────────────────┘
```

### Binaries we install

| Path                                                       | Purpose                                                  |
|------------------------------------------------------------|----------------------------------------------------------|
| `/usr/libexec/nm-openvpn3-service`                         | NMVpnServicePlugin worker. Spawned by NM per activation. |
| `/usr/libexec/nm-openvpn3-service-helper`                  | Helper invoked by the service to push Ip4Config to NM.   |
| `/usr/libexec/nm-openvpn3-auth-dialog`                     | Secret collection (libsecret + libnma password dialog).  |
| `/usr/lib/.../NetworkManager/libnm-vpn-plugin-openvpn3.so` | libnm-side editor plugin loader.                         |
| `/usr/lib/.../NetworkManager/libnm-vpn-plugin-openvpn3-editor.so` | GTK3 editor widgets for nm-connection-editor.      |
| `/usr/lib/.../NetworkManager/libnm-gtk4-vpn-plugin-openvpn3-editor.so` | GTK4 variant.                                  |
| `/usr/lib/NetworkManager/VPN/nm-openvpn3-service.name`     | Plugin manifest read by libnm.                           |

## Connect flow

```
nmcli connection up my-vpn
    │
    ▼
NetworkManager: pick plugin matching vpn.service-type
    │
    ▼
spawn /usr/libexec/nm-openvpn3-service ─────────────► (we run here)
    │                                                  │
    │ (NM D-Bus interface)                             │
    │                                                  │
    ├─► need_secrets ──────────────────────────────►   check_need_secrets()
    │     ▲   │                                        returns ctype + need_secrets bool
    │     │   ▼
    │     │ ┌────────────────────────────────────┐
    │     │ │ NM spawns nm-openvpn3-auth-dialog  │
    │     │ │   ↳ libsecret lookup or GTK prompt │
    │     │ │   ↳ writes vpn.secrets to stdout   │
    │     │ └────────────────────────────────────┘
    │     │   │
    │     │   ▼
    │     └─◀ vpn.secrets injected
    │
    ├─► connect(connection) ──────────────────────►    real_connect():
    │                                                    1. build_profile_string()
    │                                                       reads vpn.data["nm-openvpn3-profile"]
    │                                                       verbatim, or falls back to do_export
    │                                                    2. configmgr.Import(name, profile)
    │                                                       → config_path
    │                                                    3. SetOverride(name, value) per
    │                                                       enabled override-* vpn.data key
    │                                                    4. sessmgr.NewTunnel(config_path)
    │                                                       → session_path
    │                                                    5. session.Ready (poll until backend
    │                                                       registers)
    │                                                    6. subscribe StatusChange (Plan 3g)
    │                                                       subscribe AttentionRequired (Plan 2)
    │                                                    7. SetPublicAccess(TRUE) + AccessGrant(uid)
    │                                                    8. session.Connect()
    │                                                    9. arm 500 ms fast-poll + 30 s stats timer
    │
    ▼
[backend client process runs openvpn3 handshake against the remote]
    │
    ▼
StatusChange (MAJOR_CONNECTION, MINOR_CONN_CONNECTED) signal ──►
                                                       status_change_signal_cb
                                                          ↳ status_handle_state(STARTED)
                                                            ↳ emit_started_ip4_config():
                                                              - ifaddrs → tun IPv4
                                                              - sessmgr.connected_to → ext-gw
                                                              - netcfg.dns_name_servers
                                                              - /proc/net/route → split-tunnel
                                                              - SetConfig + SetIp4Config to NM
                                                              - re-arm 5 s watchdog
    │
    ▼
NM: state = ACTIVATED, dispatcher.d/* runs, applications see VPN up
```

### Statistics & disconnect

Every 30 s `stats_timer_cb` reads `session.statistics` (an `a{sx}` of
`BYTES_IN` / `BYTES_OUT` / `PACKETS_IN` / `PACKETS_OUT` plus `TUN_*`
variants) and emits a line at MESSAGE level via `ovpn3_trace()`.

`real_disconnect()` calls `session.Disconnect`, unsubscribes the two
signals, kills the timers, frees the slot list and connection ref, and
clears `session_path` / `config_path`.

If the session vanishes externally (e.g. `openvpn3 session-manage
--disconnect` from another process), the watchdog's next `get_status`
call fails; the plugin propagates `NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED`
to NM so the UI no longer shows ACTIVATED for a dead tunnel.

## Interactive authentication (Plan 2)

```
openvpn3 backend needs username/password/2FA
    │
    ▼
AttentionRequired(type, group, msg) signal ──►       attention_required_cb:
                                                       1. fetch_input_slots() walks
                                                          UserInputQueueGetTypeGroup →
                                                          UserInputQueueCheck →
                                                          UserInputQueueFetch
                                                       2. auto_provide_known_slots()
                                                          pushes anything already in
                                                          vpn.data (username) or
                                                          vpn.secrets via
                                                          UserInputProvide
                                                       3. stash remaining slots in
                                                          priv->pending_slots
                                                       4. nm_vpn_service_plugin_secrets_required(
                                                            plugin, msg, hints[])
    │
    ▼
NM popups inline prompt (or spawns auth-dialog)
    │
    ▼
NM.new_secrets(vpn.secrets) ─────────────────►       real_new_secrets():
                                                       walk priv->pending_slots, look up
                                                       each slot's value by the mapped
                                                       NM_OPENVPN3_KEY_* and call
                                                       ovpn3_session_provide_input()
    │
    ▼
openvpn3 backend continues handshake → STARTED
```

## Key vpn.data / vpn.secrets

Non-exhaustive; full list in `shared/nm-service-defines.h`.

| Key                              | Source         | Purpose                                          |
|----------------------------------|----------------|--------------------------------------------------|
| `nm-openvpn3-profile`            | vpn.data       | Path to verbatim `.ovpn`; consumed by build_profile_string. |
| `connection-type`                | vpn.data       | tls / password / password-tls / static-key       |
| `remote`                         | vpn.data       | `host[:port[:proto]]`, multi-remote allowed       |
| `ca` / `cert` / `key`            | vpn.data       | Cert chain paths (file paths after libnma extraction). |
| `password` / `cert-pass` / `challenge-response` | vpn.secrets | Interactive auth values.            |
| `override-route-nopull`          | vpn.data       | Toggle: openvpn3 SetOverride `route-nopull`.     |
| `override-force-default-gateway` | vpn.data       | Toggle: openvpn3 SetOverride.                    |
| `override-block-ipv6`            | vpn.data       | Toggle.                                          |
| `override-dns-setup-disabled`    | vpn.data       | Toggle (lets NM keep DNS control).               |
| `override-dco`                   | vpn.data       | Toggle (Data Channel Offload).                   |

## Threading

Everything runs on the main GLib thread:

- NM invokes `real_connect` / `real_disconnect` / `real_need_secrets` /
  `real_new_secrets` as standard D-Bus method handlers.
- `g_dbus_proxy_call_sync` blocks the main loop for the call duration.
  We use `dbus_call_with_retry()` to absorb auto-activation races with
  the openvpn3 daemons.
- `g_dbus_connection_signal_subscribe` callbacks (StatusChange,
  AttentionRequired) fire on the same main loop.
- Timers (poll, stats) come from `g_timeout_add`, also main-loop bound.

No background threads, no locks.  Side effects are serialized by the
GLib event queue.

## File / install layout (after `make install` with `--prefix=/usr`)

    /usr/libexec/
        nm-openvpn3-service
        nm-openvpn3-service-helper
        nm-openvpn3-auth-dialog
    /usr/lib/x86_64-linux-gnu/NetworkManager/
        libnm-vpn-plugin-openvpn3.so
        libnm-vpn-plugin-openvpn3-editor.so
        libnm-gtk4-vpn-plugin-openvpn3-editor.so
    /usr/lib/NetworkManager/VPN/
        nm-openvpn3-service.name
    /usr/share/locale/<lang>/LC_MESSAGES/
        NetworkManager-openvpn3.mo
    ~/.cert/nm-openvpn3/                  (per-user; certs from .ovpn imports)
        <connection-id>-ca.pem
        <connection-id>-cert.pem
        ...

`NM_PLUGIN_DIR` is detected at `configure` time by inspecting libnm's
hard-coded multiarch directory; the build does not rely on Autotools
defaults for that path (see configure.ac).

## Diagnostics

| Tag / unit                                          | What it shows                                 |
|-----------------------------------------------------|-----------------------------------------------|
| `journalctl _COMM=nm-openvpn3-ser`                  | The whole service log stream.                 |
| `journalctl -t nm-openvpn3-service`                 | Same, filtered by SYSLOG_IDENTIFIER.          |
| `journalctl _COMM=NetworkManager`                   | The NM-side view (connect/disconnect timeline). |
| `openvpn3 sessions-list`                            | Live sessions per uid.                        |
| `openvpn3 session-stats --path <session>`           | Counters direct from the backend.             |
| `gdbus introspect --system --dest net.openvpn.v3.sessions --object-path <session>` | Property + method inventory.    |

Trace lines emitted by `ovpn3_trace()` carry the
`SYSLOG_IDENTIFIER=nm-openvpn3-service` ident; everything else is
NM's own logging.

## See also

- [`docs/FORK.md`](FORK.md) — roadmap history, plan-by-plan.
- [`docs/PLAN-2-SMOKE-TEST.md`](PLAN-2-SMOKE-TEST.md) — runbook for
  validating interactive auth once a password-protected openvpn3 server
  is available.
