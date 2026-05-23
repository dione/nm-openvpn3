# nm-openvpn3 — Rust implementation

NetworkManager VPN service plugin for [OpenVPN 3 Linux](https://github.com/OpenVPN/openvpn3-linux), written in async Rust on top of zbus.

This branch (`rust/main`) is the Rust-only tree.  The original C implementation lives on the [`fork/openvpn3-skeleton`](../../tree/fork/openvpn3-skeleton) branch — pick the branch matching the language you want to work on.

## Layout

```
.
├── ovpn3-client/             # async zbus client for openvpn3-linux
├── nm-openvpn3-service/      # NMVpnServicePlugin D-Bus service
├── nm-openvpn3-auth-dialog/  # external-UI-mode auth-dialog binary
├── data/
│   ├── dbus-1/               # system bus policy
│   ├── NetworkManager-VPN/   # NM .name file (vpn-type discovery)
│   └── systemd/              # sysusers / tmpfiles
├── docs/                     # architecture + phase notes
├── debian/                   # Debian source-package for Ubuntu PPA
├── scripts/                  # install-test.sh, uninstall-test.sh, ovpn-to-nmcli, …
└── Makefile                  # canonical install entry-point for packagers
```

## Identifiers

| Field | Value |
|---|---|
| Service bus name | `org.freedesktop.NetworkManager.openvpn3` |
| `vpn-type=` | `openvpn3` |
| Service binary | `/usr/libexec/nm-openvpn3-service` |
| Auth-dialog binary | `/usr/libexec/nm-openvpn3-auth-dialog` |
| `.name` file | `nm-openvpn3-service.name` (rendered from `.name.in`) |

The `.name` file does **not** point at a libnm-vpn-plugin cdylib yet — the editor/properties side has not been ported.  GUI applications (gnome-control-center, nm-applet) will list the plugin without property pages until a Rust libnm-vpn-plugin lands.  The runtime path is unaffected: NM spawns the auth-dialog binary directly from `[GNOME] auth-dialog=`.

## Status

End-to-end working against openvpn3-linux v27:

- Connect / Disconnect drives the openvpn3 sessions manager and emits the `StateChanged`, `Config`, `Ip4Config`, `Failure`, `SecretsRequired`, and `LoginBanner` signals NM consumes.
- Status poller handles the unicast `StatusChange` gap in openvpn3 v27 with a device-name fallback probe.
- AttentionRequired listener drains `UserInputQueue`, auto-provides credentials persisted in `vpn.data` / `vpn.secrets`, asks NM for the rest via `SecretsRequired`, and feeds the reply back via `ProvideInput`.
- Auth-dialog implements the external-UI-mode contract NM uses in every modern desktop integration — no GTK / libsecret deps.

## Build + install

```sh
cargo build --release
bash scripts/install-test.sh
```

`scripts/install-test.sh` auto-detects the NM plugin directory (`gcc -dumpmachine` for the multiarch triplet, falls back to `/usr/lib64/NetworkManager` and `/usr/lib/NetworkManager`), installs the service + auth-dialog binaries to `/usr/libexec`, renders the `.name.in` template, and reloads dbus.

For .deb packaging (Ubuntu PPA / local install via `dpkg -i`) see [docs/PACKAGING.md](docs/PACKAGING.md).  `scripts/uninstall-test.sh` reverses an `install-test.sh` run before switching to a `.deb`-managed install.

Create a test connection (replace `<path>` with a real profile path):

```sh
nmcli connection add type vpn vpn-type openvpn3 \
    con-name ovpn3-test \
    vpn.data 'nm-openvpn3-profile=<path>,connection-type=tls'
```

Activate + tail the journal:

```sh
nmcli connection up ovpn3-test
# TASK_COMM_LEN=16 truncates `nm-openvpn3-service` to `nm-openvpn3-ser`.
journalctl --since '1 min ago' _COMM=nm-openvpn3-ser
```
