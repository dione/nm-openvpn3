# `debian/` — dh-cargo experimental packaging (this branch)

This is the **`packaging/dh-cargo`** branch.  The `debian/` tree here
builds against `librust-*-dev` packages from the Ubuntu / Debian
archive instead of the vendored-cargo tarball used on `rust/main`.
The canonical vendored layout is preserved under `debian-vendored/`
for direct comparison.

## Status: builds on Ubuntu 26.04 noble

Workspace Cargo.toml is downgraded on this branch to match the
versions Ubuntu 26.04 ships:

| Crate        | rust/main (Cargo.lock) | this branch (apt) |
|--------------|-----------------------:|------------------:|
| `tokio`      | 1.52.3                 | 1.48.0            |
| `zbus`       | 5.15.0                 | 5.13.2            |
| `gtk4`       | 0.11.3                 | **0.10.3**        |
| `libadwaita` | 0.9.1                  | **0.8.1**         |
| `glib`       | 0.22.7                 | **0.21.5**        |
| `if-addrs`   | 0.15.0                 | **0.13.3**        |
| `clap`       | 4.6.1                  | 4.5.53            |

`tokio`, `zbus`, `clap`, `anyhow`, `tracing*`, `base64` etc. stay on
the same Cargo.toml constraints (`"1"`, `"5"`, `"4"`) — Cargo resolves
those against the older archive patches automatically.

The four 0.x crates **cannot** be left at `"0.11"`/`"0.9"`/`"0.22"`/
`"0.15"`; Cargo treats every 0.x minor as a breaking change.  The
workspace + per-crate Cargo.toml entries on this branch pin
`"0.10"`/`"0.8"`/`"0.21"`/`"0.13"` to match the archive.

No API breakage in `editor.rs` / properties FFI — AdwComboRow,
AdwSpinRow, AdwSwitchRow, file-dialog conversions all exist in
libadwaita 0.8 / gtk4 0.10.

## How to build

```sh
# 1. Install Build-Depends (~218 packages incl. dh-cargo, librust-*-dev,
#    libgtk-4-dev, libadwaita-1-dev).
sudo apt-get build-dep .

# 2. Build .deb's.
dpkg-buildpackage -b -us -uc

# 3. Lintian-verify.
lintian ../network-manager-openvpn3_*_amd64.changes   # exit 0
```

To switch back to the vendored layout (eg. for a PPA upload), check
out `rust/main`.

## Why this branch is not the default

The vendored layout stays the canonical PPA path because:

* **Reproducibility** — the orig-vendor tarball locks Rust dep
  versions across every build.  dh-cargo's reproducibility lives in
  the apt archive snapshot, which moves under us.
* **Archive coupling** — every Ubuntu release ships a different
  set of `librust-*-dev` versions.  This branch builds on noble;
  jammy / oracular would need different Cargo.toml pins.
* **gtk4 / libadwaita lag** — the apt archive is one release cycle
  behind crates.io for GTK4 bindings.  Vendored builds the newer
  matrix without backporting.

dh-cargo path becomes attractive **if the eventual target is the
Debian main archive** (not a PPA) — Debian-NEW review requires
either the dh-cargo route or a per-crate debcargo source-package
campaign.  This branch documents the dh-cargo alternative for that
eventuality.

## `debian/rules` quirks

`--buildsystem cargo` is **omitted** on purpose — dh-cargo's default
flow assumes a single-crate source package shipped with
`debian/cargo-checksum.json` (the layout `debcargo` produces).  Our
workspace builds two bins + two cdylibs from one source tree, so the
rules file drives cargo through the workspace Makefile and only
borrows dh-cargo's apt-installed crate registry under
`/usr/share/cargo/registry`.

`Cargo.lock` is deleted before the `cargo build` step — the archive
ships patch-level-older crates (eg. `anyhow 1.0.101` vs locked
`1.0.102`) and `--locked` would reject the resolution.  The lockfile
is restored from git at `dh_auto_clean` time so the working tree
stays consistent after a build.

## Files

Same set as the canonical layout, but:

* `control` — Build-Depends carries 20× `librust-*-dev` (feature
  flags via `librust-<crate>-<ver>+<feature>-dev`; apt's `Provides:`
  metapackages resolve them).
* `rules` — no `--buildsystem cargo`; cargo-config injected into
  `$CARGO_HOME/config.toml` pointing at `/usr/share/cargo/registry`.
* `source/options` — `extend-diff-ignore` drops `vendor/` (no vendor
  tree here).
* No `cargo-config.toml.in`, no `clean` file — both belong to the
  vendored flow and live under `debian-vendored/`.

Lintian-overrides for `appstream-metadata-validation-failed` /
`initial-upload-closes-no-bugs` carry over verbatim from the
canonical layout; the `source-contains-prebuilt-binary
[vendor/winapi-…]` overrides drop out because there is no vendor/
tree here.
