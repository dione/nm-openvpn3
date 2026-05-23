# Packaging — Ubuntu / Debian (.deb)

This tree ships a `debian/` directory ready for Ubuntu PPA uploads.
The packaging follows the same source-package layout as upstream
`network-manager-openvpn`: one source package
(`network-manager-openvpn3`) producing two binary packages —

| Binary package                       | Contents                                                           |
| ------------------------------------ | ------------------------------------------------------------------ |
| `network-manager-openvpn3`           | service + auth-dialog binaries, `.name` discovery file, dbus policy |
| `network-manager-openvpn3-gnome`     | `libnm-vpn-plugin-openvpn3{,-editor}.so` cdylibs, AppStream metainfo, locale catalogs |

Package names follow the Debian `network-manager-<vpn>` convention
(network-manager-openvpn, -pptp, -vpnc, -strongswan, …).  Runtime
identifiers — binary paths under `/usr/libexec/`, the `.name` discovery
file, the D-Bus service name, the gettext domain — keep the upstream
short form `nm-openvpn3`; only the .deb wrapping uses the long name.

Headless / CLI-only users install `network-manager-openvpn3` and avoid
pulling in GTK4 + libadwaita transitively.

## Source format

`3.0 (quilt)` with a **component orig-vendor tarball** — cargo deps
are vendored at orig-tarball-creation time and shipped as
`network-manager-openvpn3_<ver>.orig-vendor.tar.xz` next to the
upstream `network-manager-openvpn3_<ver>.orig.tar.xz`.  Launchpad
builders run with no network reach, so the build must not touch
crates.io; the `debian/cargo-config.toml` injected into `$CARGO_HOME`
at build time also sets `[net] offline = true` as defence in depth.

Vendor/ is **not** committed to git — the working repo stays clean.
`scripts/make-orig-tarballs.sh` regenerates both tarballs on demand.

## Build workflow

### Local (workstation .deb, no signing)

```sh
# 1. Generate both orig tarballs (writes to ../)
./scripts/make-orig-tarballs.sh

# 2. Build the .deb's
debuild -us -uc -b

# 3. Inspect
ls ../*.deb
lintian -i ../*.changes   # current tree: exit 0, no findings
```

Lintian status after the last `dpkg-buildpackage -b`: **clean** (zero
errors / warnings / info).  Three warning classes are silenced via
explicit overrides — see
`debian/network-manager-openvpn3{,-gnome}.lintian-overrides` for which
checks and why.

### PPA upload (source-only)

```sh
# 1. Bump debian/changelog (one entry per upload, Ubuntu series in the
#    distribution field — e.g. `noble`, `oracular`).
dch -i

# 2. Regenerate tarballs (Cargo.lock change → vendor tree change).
./scripts/make-orig-tarballs.sh

# 3. Source-only build, signed.
debuild -S -sa

# 4. Upload.
dput ppa:<owner>/<ppa> ../network-manager-openvpn3_<ver>_source.changes
```

Launchpad rebuilds binaries for every supported architecture.

## Variable contract

`Makefile` is the canonical install entry-point — `debian/rules` calls
`make install DESTDIR=...` with the multiarch library directory
overridden:

| Variable       | Default          | `debian/rules` override         |
| -------------- | ---------------- | ------------------------------- |
| `prefix`       | `/usr`           | (unchanged)                     |
| `libdir`       | `$(prefix)/lib`  | `/usr/lib/$(DEB_HOST_MULTIARCH)`|
| `libexecdir`   | `$(prefix)/libexec` | (unchanged)                  |
| `pluginlibdir` | `$(libdir)/NetworkManager` | `…/NetworkManager`    |
| `namedir`      | `/usr/lib/NetworkManager/VPN` | (unchanged — NM scans only the non-multiarch path) |
| `dbusconfdir`  | `$(prefix)/share/dbus-1/system.d` | (unchanged)        |
| `localedir`    | `$(prefix)/share/locale` | (unchanged)               |
| `metainfodir`  | `$(prefix)/share/metainfo` | (unchanged)             |
| `DESTDIR`      | _empty_          | `debian/tmp/`                   |

A non-Debian distro (RPM, Arch, NixOS) can re-use `Makefile install`
with its own variable overrides; nothing in there is Debian-specific.

## Out of scope / known mismatches

These show up in the tree but are deliberately **not** wired into the
.deb until follow-up work resolves them:

1. **`data/systemd/nm-openvpn3-sysusers.conf.in` and
   `nm-openvpn3-tmpfiles.conf.in`** create a `nm-openvpn3` system user
   and chown a chroot directory to it — but `data/dbus-1/nm-openvpn3-service.conf`
   restricts bus name ownership to `root` and `install-test.sh` never
   installs the sysusers / tmpfiles.  Until the service either runs as
   `nm-openvpn3` (and the dbus policy switches) or the sysusers file
   is deleted, these stay out of the .deb.

2. **`appdata/network-manager-openvpn3.metainfo.xml.in` declares
   `<translation type="gettext">NetworkManager-openvpn3</translation>`,**
   but the editor's runtime `bindtextdomain` call uses domain
   `nm-openvpn3`.  AppStream UI translations (the visible
   `<name>`/`<summary>`) silently fall back to English on every desktop
   even though all the strings already live in `po/`.  Cosmetic
   mismatch; tracked separately.

3. **`cargo test`** is skipped on the PPA builder (`override_dh_auto_test`
   short-circuits).  GTK cdylib smoke tests need `xvfb` + a real D-Bus
   session, neither of which Launchpad sandboxes provide.  Run
   `cargo test --workspace --offline` locally if needed.

4. **Ubuntu LTS support.**  `libadwaita-1-dev (>= 1.4)` is the floor;
   that ships in Ubuntu 24.04 (`noble`) and newer.  Jammy (22.04) has
   libadwaita 1.0 and would need either a backport PPA dependency or
   the editor cdylib excluded.  PPA `Distribution:` field starts at
   `noble`.

5. **AppStream component-id is not reverse-DNS.**  Upstream `<id>` is
   `network-manager-openvpn3` (inherited from the C plugin), which
   modern AppStream rejects (`cid-is-not-rdns`).  Lintian-overridden in
   `debian/network-manager-openvpn3-gnome.lintian-overrides`; the real
   fix is an upstream id rename to e.g. `io.github.dione.NmOpenvpn3`
   (also renames the metainfo filename — downstream packagers re-pin
   via `debian/network-manager-openvpn3-gnome.install`).

## Updating to a new upstream version

```sh
# 1. Bump Cargo.toml workspace.version, refresh Cargo.lock.
$EDITOR Cargo.toml && cargo update --workspace

# 2. New debian/changelog entry (Cargo's `0.6.0-rc.1` → Debian `0.6.0~rc.1-1`).
dch -v 0.6.0~rc.1-1 'New upstream prerelease.'

# 3. Commit, tag.
git commit -am 'release: 0.6.0-rc.1' && git tag v0.6.0-rc.1

# 4. Regenerate tarballs (script reads the version from Cargo.toml).
./scripts/make-orig-tarballs.sh

# 5. Build + upload as above.
```

The `-` → `~` translation in `make-orig-tarballs.sh` keeps Debian's
version ordering aligned with semver pre-releases —
`0.6.0~alpha.1 < 0.6.0~rc.1 < 0.6.0`.
