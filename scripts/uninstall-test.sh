#!/usr/bin/env bash
# Reverse of install-test.sh — wipe every file the workstation smoke
# test placed on the system, plus the legacy rust/skeleton artefacts
# install-test.sh itself sweeps.  Idempotent: missing files are
# silently skipped (rm -f).
#
# Run this before `dpkg -i ../nm-openvpn3*.deb` so the package's
# postinst sees a clean tree — install-test.sh files are not in the
# dpkg manifest, so dpkg would silently overwrite them but they stay
# orphaned on uninstall.

set -euo pipefail

cd "$(dirname "$0")/.."

detect_dir() {
    local subdir="$1"
    local triplet candidates d
    triplet=$(gcc -dumpmachine 2>/dev/null \
              || dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
              || true)
    candidates=()
    if [ -n "$triplet" ]; then
        candidates+=("/usr/lib/${triplet}/NetworkManager${subdir}")
    fi
    candidates+=(
        "/usr/lib64/NetworkManager${subdir}"
        "/usr/lib/NetworkManager${subdir}"
    )
    for d in "${candidates[@]}"; do
        if [ -d "$d" ]; then
            printf '%s\n' "$d"
            return 0
        fi
    done
    printf '/usr/lib/NetworkManager%s\n' "$subdir"
}
PLUGINDIR=$(detect_dir "")
NAMEDIR=$(detect_dir "/VPN")
LIBEXECDIR=/usr/libexec
DBUSDIR=/usr/share/dbus-1/system.d
LOCALEDIR=/usr/share/locale
METAINFODIR=/usr/share/metainfo

# Multiarch + non-multiarch NM plugin dirs.  install-test.sh on this
# branch installs under multiarch; the C autotools tree (`fork/openvpn3-skeleton`)
# defaulted to `--libdir=/usr/lib`.  A workstation that built both
# branches has live files under both — sweep both, regardless of which
# one was the "current" install.
ALT_PLUGINDIR=/usr/lib/NetworkManager
ALT_NAMEDIR=/usr/lib/NetworkManager/VPN

echo "PLUGINDIR=$PLUGINDIR"
echo "NAMEDIR=$NAMEDIR"
echo "ALT_PLUGINDIR=$ALT_PLUGINDIR (legacy non-multiarch path)"

echo "Removing current install-test.sh artefacts ..."
sudo rm -f \
    "$LIBEXECDIR/nm-openvpn3-service" \
    "$LIBEXECDIR/nm-openvpn3-auth-dialog" \
    "$LIBEXECDIR/nm-openvpn3-service-helper" \
    "$PLUGINDIR/libnm-vpn-plugin-openvpn3.so" \
    "$PLUGINDIR/libnm-vpn-plugin-openvpn3-editor.so" \
    "$PLUGINDIR/libnm-vpn-plugin-openvpn3.la" \
    "$PLUGINDIR/libnm-vpn-plugin-openvpn3-editor.la" \
    "$NAMEDIR/nm-openvpn3-service.name" \
    "$DBUSDIR/nm-openvpn3-service.conf" \
    "$METAINFODIR/network-manager-openvpn3.metainfo.xml"

# C-branch autotools install — non-multiarch /usr/lib/NetworkManager.
echo "Removing C-branch autotools leftovers ..."
sudo rm -f \
    "$ALT_PLUGINDIR/libnm-vpn-plugin-openvpn3.so" \
    "$ALT_PLUGINDIR/libnm-vpn-plugin-openvpn3-editor.so" \
    "$ALT_PLUGINDIR/libnm-vpn-plugin-openvpn3.la" \
    "$ALT_PLUGINDIR/libnm-vpn-plugin-openvpn3-editor.la" \
    "$ALT_NAMEDIR/nm-openvpn3-service.name"

# Locale catalogs — install-test.sh shipped one .mo per po/*.po; mirror
# the same iteration so we never leak an orphan catalog into a locale
# directory that may already host translations from unrelated packages.
echo "Removing locale catalogs (nm-openvpn3 domain) ..."
for po in po/*.po; do
    [ -e "$po" ] || continue
    lang=$(basename "$po" .po)
    sudo rm -f "$LOCALEDIR/$lang/LC_MESSAGES/nm-openvpn3.mo"
done

# Legacy rust/skeleton artefacts (vpn-type "openvpn3.rust", `-rust-`
# infix).  install-test.sh sweeps these on every run; keep the same
# list here so a workstation upgraded via this script is clean even if
# install-test.sh was never re-run after the rename.
echo "Removing legacy rust/skeleton artefacts ..."
sudo rm -f \
    "$NAMEDIR/nm-openvpn3-rust-service.name" \
    "$LIBEXECDIR/nm-openvpn3-rust-service" \
    "$LIBEXECDIR/nm-openvpn3-rust-auth-dialog" \
    "$DBUSDIR/nm-openvpn3-rust-service.conf"

sudo systemctl reload dbus
sudo systemctl reload NetworkManager 2>/dev/null \
    || sudo systemctl restart NetworkManager

echo
echo "Uninstalled.  Verify the tree is clean:"
echo "  ls $LIBEXECDIR/nm-openvpn3-* 2>/dev/null || echo '  (libexec clean)'"
echo "  ls $PLUGINDIR/libnm-vpn-plugin-openvpn3* 2>/dev/null \\"
echo "      || echo '  (NM plugin dir clean)'"
echo "  ls $NAMEDIR/nm-openvpn3-*.name 2>/dev/null \\"
echo "      || echo '  (NM .name dir clean)'"
echo
echo "Next: sudo dpkg -i ../nm-openvpn3_*.deb ../nm-openvpn3-gnome_*.deb"
