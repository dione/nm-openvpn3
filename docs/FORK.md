# Fork notes

This repository is a fork of [GNOME/NetworkManager-openvpn](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) (1.12.5, upstream commit `9514bde`), adapted to drive the OpenVPN 3 Linux D-Bus stack (`net.openvpn.v3.*`) instead of fork+exec'ing the legacy `openvpn` v2 binary.

## Branch layout

Two sibling branches diverge from the upstream baseline:

| Branch | Language | Purpose |
|---|---|---|
| [`fork/openvpn3-skeleton`](../../tree/fork/openvpn3-skeleton) | C (GLib + GTK3/4) | Original C plugin adapted to openvpn3-linux. Autotools build, full editor with GtkBuilder UI, 60+ gettext catalogs. |
| `rust/main` (**this branch**) | Rust | From-scratch port of the C plugin. Cargo workspace, libadwaita + GTK4 editor, hand-rolled libnm FFI, async zbus client. |

Pick the branch matching the language you want to work on. They are not meant to merge; they are alternative implementations.

## Differences from upstream

| | Upstream | `rust/main` |
|---|---|---|
| Backend | fork/exec `/usr/sbin/openvpn` | openvpn3-linux D-Bus (`net.openvpn.v3.*`) |
| Service bus name | `org.freedesktop.NetworkManager.openvpn` | `org.freedesktop.NetworkManager.openvpn3` |
| System user | `nm-openvpn` | `nm-openvpn3` |
| Service language | C + GLib | async Rust + zbus |
| Editor language | C + GTK3 | Rust + GTK4 + libadwaita |
| .ovpn parser | hand-rolled C | hand-rolled Rust (`nm-openvpn3-properties` rlib) |
| Build system | autotools | Cargo workspace |
| Translations | 60+ catalogs (full coverage) | Polish complete + 59 partial (msgmerge from upstream) |

## Workspace layout (this branch)

```
.
├── Cargo.toml                workspace root
├── ovpn3-client/             async zbus client for openvpn3-linux
├── nm-openvpn3-service/      NMVpnServicePlugin D-Bus service
├── nm-openvpn3-auth-dialog/  external-UI-mode auth-dialog binary
├── nm-openvpn3-properties/   libnm cdylib (libnm-vpn-plugin-openvpn3.so) +
│                             pure-Rust .ovpn parser/emitter rlib
├── nm-openvpn3-editor/       GTK editor cdylib
│                             (libnm-vpn-plugin-openvpn3-editor.so)
├── data/                     .name template, dbus policy, sysusers, tmpfiles
├── docs/                     ARCHITECTURE, FORK, UI-PORT
├── po/                       translations (POT + 60 catalogs)
└── scripts/install-test.sh           local smoke-test installer
```

## Maintaining against upstream

The `upstream` remote tracks `gitlab.gnome.org/GNOME/NetworkManager-openvpn`.  Upstream changes to the C plugin can be cherry-picked into `fork/openvpn3-skeleton`; they rarely apply directly to `rust/main` because the layout and language differ.

For translations, `scripts/import-upstream-translations.sh` re-merges upstream's `.po` catalogs against this tree's POT (exact-match only — fuzzy gets dropped). Run after upstream gains new translations or our POT grows.

## Status

`rust/main` carries the runtime + editor + import/export end-to-end against openvpn3-linux v27 / libnm 1.54. Runtime-tested under gnome-control-center v49.  Deferred for future rounds: IPv6 emit, NMSettingIPConfig route emission in `build_profile`, HTTP-proxy authfile, native-speaker translation review.
