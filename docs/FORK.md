# Fork notes

This repository is a fork of [GNOME/NetworkManager-openvpn](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) (1.12.5, upstream commit `9514bde`), adapted to drive the OpenVPN 3 Linux D-Bus stack (`net.openvpn.v3.*`) instead of fork+exec'ing the legacy `openvpn` v2 binary.

## Branch layout

Three sibling branches diverge from the upstream baseline:

| Branch | Language | Purpose |
|---|---|---|
| [`rust/main`](../../tree/rust/main) (**default**) | Rust | From-scratch port of the C plugin.  Cargo workspace pinned to the **Ubuntu / Debian archive's `librust-*-dev` versions** (`gtk4 = "0.10"`, `libadwaita = "0.8"`, `glib = "0.21"`).  `debian/` packaging uses the dh-cargo path. |
| [`rust/upstream-deps`](../../tree/rust/upstream-deps) | Rust | Same Rust workspace, **newest crates.io minors** (`gtk4 = "0.11"`, `libadwaita = "0.9"`, `glib = "0.22"`).  `debian/` packaging uses a vendored-cargo orig-vendor tarball (PPA-bound; no archive coupling). |
| [`c/main`](../../tree/c/main) | C (GLib + GTK3/4) | Original C plugin adapted to openvpn3-linux.  Autotools build, full editor with GtkBuilder UI, 60+ gettext catalogs.  Frozen reference — new work happens on the Rust side. |

The two Rust branches are not meant to merge — they target different packaging worlds.  Pick `rust/main` for Ubuntu / Debian archive-aligned builds; pick `rust/upstream-deps` if you want the newest libadwaita / gtk4 rust bindings via a vendored PPA tarball.  `c/main` exists for git-blame / msgmerge purposes against the upstream C tree.

## Differences from upstream

| | Upstream C | `rust/main` |
|---|---|---|
| Backend | fork/exec `/usr/sbin/openvpn` | openvpn3-linux D-Bus (`net.openvpn.v3.*`) |
| Service bus name | `org.freedesktop.NetworkManager.openvpn` | `org.freedesktop.NetworkManager.openvpn3` |
| System user | `nm-openvpn` | `nm-openvpn3` |
| Service language | C + GLib | async Rust + zbus |
| Editor language | C + GTK3 | Rust + GTK4 + libadwaita |
| .ovpn parser | hand-rolled C | hand-rolled Rust (`nm-openvpn3-properties` rlib) |
| Build system | autotools | Cargo workspace + Makefile + `debian/` |
| Translations | 60+ catalogs (full coverage) | Polish complete + 59 partial (msgmerge from `c/main`) |

## Workspace layout (Rust branches)

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
├── docs/                     ARCHITECTURE, FORK, UI-PORT, PACKAGING
├── po/                       translations (POT + 60 catalogs)
├── debian/                   Debian source-package (dh-cargo on rust/main,
│                             vendored on rust/upstream-deps)
├── debian-vendored/          (rust/main only) sibling vendored layout
│                             preserved for comparison / fallback
├── Makefile                  canonical DESTDIR install entry-point
└── scripts/                  install-test.sh, uninstall-test.sh,
                              make-orig-tarballs.sh, ovpn-to-nmcli.py, …
```

## Maintaining against upstream

The `upstream` remote tracks `gitlab.gnome.org/GNOME/NetworkManager-openvpn`.  Upstream changes to the C plugin can be cherry-picked into `c/main`; they rarely apply directly to either Rust branch because the layout and language differ.

For translations, `scripts/import-upstream-translations.sh` re-merges `c/main`'s `.po` catalogs against this tree's POT (exact-match only — fuzzy gets dropped).  Run after upstream gains new translations or our POT grows.

## Status

`rust/main` carries the runtime + editor + import/export end-to-end against openvpn3-linux v27 / libnm 1.54.  Runtime-tested under gnome-control-center v49.  Deferred for future rounds: IPv6 emit, NMSettingIPConfig route emission in `build_profile`, HTTP-proxy authfile, native-speaker translation review.

See [`docs/PACKAGING.md`](PACKAGING.md) for the Debian / Ubuntu `.deb` build workflow and the per-branch packaging trade-offs.
