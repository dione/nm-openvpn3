#!/usr/bin/env bash
# Generate the two orig tarballs Debian's `3.0 (quilt)` source format
# consumes for a vendored Rust build:
#
#   ../nm-openvpn3_<ver>.orig.tar.xz         — `git archive HEAD`
#   ../nm-openvpn3_<ver>.orig-vendor.tar.xz  — `cargo vendor` output
#
# Run from a clean checkout (no uncommitted changes — the archive comes
# from HEAD, not the working tree).  Both tarballs land in ../  so a
# subsequent `debuild -S -sa` from inside the source dir picks them up.
#
# Re-running is safe: existing tarballs are overwritten.

set -euo pipefail
cd "$(dirname "$0")/.."

# Translate Cargo's pre-release marker (0.6.0-alpha.1) into the Debian
# upstream-version convention (0.6.0~alpha.1) so apt orders prereleases
# strictly below the eventual stable 0.6.0 release.
RAW_VER=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
if [ -z "$RAW_VER" ]; then
    echo "error: failed to extract version from Cargo.toml" >&2
    echo "       (expected a line matching '^version = \"...\"')" >&2
    exit 1
fi
VER=${RAW_VER//-/\~}

PKG=network-manager-openvpn3
DEST=${DEST:-..}
mkdir -p "$DEST"

echo "Packaging ${PKG} ${VER} (upstream version ${RAW_VER})"

# Upstream source: git archive HEAD.  Use a prefix so the tarball
# extracts into network-manager-openvpn3-${VER}/ as Debian convention
# requires (orig tarball prefix must match the source package name).
git archive --format=tar --prefix="${PKG}-${VER}/" HEAD \
    | xz -T0 -c > "${DEST}/${PKG}_${VER}.orig.tar.xz"

# Vendor tree: cargo vendor into a temp dir, tar that.  We do NOT put
# vendor/ inside the upstream tarball because the orig-vendor component
# tarball is the conventional Debian way of shipping vendored deps —
# dpkg-source recognises the `orig-<component>` suffix and unpacks it
# into the source tree alongside the main orig tree at build time.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Hit crates.io here (the only place network access matters); the
# resulting vendor/ tree is what builders consume offline.
cargo vendor --quiet "${TMP}/vendor" >/dev/null

tar -C "$TMP" --owner=0 --group=0 --sort=name -cf - vendor \
    | xz -T0 -c > "${DEST}/${PKG}_${VER}.orig-vendor.tar.xz"

echo
echo "Generated tarballs:"
ls -lh "${DEST}/${PKG}_${VER}.orig.tar.xz" "${DEST}/${PKG}_${VER}.orig-vendor.tar.xz"
echo
echo "Next: from inside the source tree run"
echo "  debuild -S -sa             # source-only upload to PPA"
echo "  debuild -us -uc -b         # local binary build (skip signing)"
