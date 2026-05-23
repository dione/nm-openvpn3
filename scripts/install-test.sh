#!/usr/bin/env bash
# Build + install the openvpn3 NM VPN plugin (Rust implementation) for
# smoke testing on a workstation.  Idempotent — re-run after every
# rebuild.  For packaging see debian/ + Makefile (the canonical paths
# downstream packagers consume).

set -euo pipefail

# Script lives in scripts/; cargo build + data/ paths sit at the repo
# root, one level up.
cd "$(dirname "$0")/.."

cargo build --release

# Auto-detect the NetworkManager plugin directory.  Debian / Ubuntu
# ship NM plugins under /usr/lib/<multiarch>/NetworkManager, Fedora /
# Arch under /usr/lib/NetworkManager.  Probe candidates in order and
# fall back to the bare path if none match.
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
LIBEXECDIR=/usr/libexec
# NM scans VPN .name files only from /usr/lib/NetworkManager/VPN —
# the non-multiarch path is canonical for VPN service discovery even
# on multiarch distros (every other Debian VPN plugin installs the
# .name there).  Hard-code the path; do NOT derive it from PLUGINDIR.
NAMEDIR=/usr/lib/NetworkManager/VPN
echo "Using PLUGINDIR=$PLUGINDIR"
echo "Using NAMEDIR=$NAMEDIR"

# Clean up artifacts left behind by the rust/skeleton branch — those
# carried a `-rust-` infix in every name and claimed vpn-type
# "openvpn3.rust".  NM still reads the stale .name file from /VPN/
# and tries to load a plugin that no longer exists, which surfaces in
# gnome-control-center as "could not load plugin: missing 'plugin'
# setting".  Safe to remove unconditionally — these paths are only
# ever populated by the legacy install-test.sh from that branch.
echo "Removing stale -rust- artifacts (rust/skeleton branch leftovers) ..."
sudo rm -f \
    "$NAMEDIR/nm-openvpn3-rust-service.name" \
    "$LIBEXECDIR/nm-openvpn3-rust-service" \
    "$LIBEXECDIR/nm-openvpn3-rust-auth-dialog" \
    /usr/share/dbus-1/system.d/nm-openvpn3-rust-service.conf

sudo install -m 0755 target/release/nm-openvpn3-service \
    "$LIBEXECDIR/nm-openvpn3-service"
sudo install -m 0755 target/release/nm-openvpn3-auth-dialog \
    "$LIBEXECDIR/nm-openvpn3-auth-dialog"

# Properties / editor cdylibs.  The cargo target name is the workspace
# crate's `[lib].name` — Cargo prefixes "lib", so the linker artifact is
# `libnm_vpn_plugin_openvpn3.so`.  NM's [libnm] / [GNOME].properties
# keys point at the more conventional dashed name, so we rename on
# install.  Both files may legitimately be missing on an editor-less
# build; `install` would error, so guard the call.
PROP_SRC=target/release/libnm_vpn_plugin_openvpn3.so
PROP_DEST="$PLUGINDIR/libnm-vpn-plugin-openvpn3.so"
if [ -f "$PROP_SRC" ]; then
    sudo install -m 0644 "$PROP_SRC" "$PROP_DEST"
    echo "Installed $PROP_DEST"
else
    echo "Skipped libnm cdylib — not built (cargo build did not produce $PROP_SRC)."
fi

EDIT_SRC=target/release/libnm_vpn_plugin_openvpn3_editor.so
EDIT_DEST="$PLUGINDIR/libnm-vpn-plugin-openvpn3-editor.so"
if [ -f "$EDIT_SRC" ]; then
    sudo install -m 0644 "$EDIT_SRC" "$EDIT_DEST"
    echo "Installed $EDIT_DEST"
else
    echo "Skipped editor cdylib — not built (cargo build did not produce $EDIT_SRC)."
fi

# Render the @LIBEXECDIR@ / @PLUGINDIR@ placeholders.  Use mktemp so a
# pre-planted symlink in /tmp cannot redirect the install.
RENDERED=$(mktemp -t nm-openvpn3-service.name.XXXXXX)
trap 'rm -f "$RENDERED"' EXIT
sed -e "s|@LIBEXECDIR@|$LIBEXECDIR|g" \
    -e "s|@PLUGINDIR@|$PLUGINDIR|g" \
    data/NetworkManager-VPN/nm-openvpn3-service.name.in \
    > "$RENDERED"
sudo install -m 0644 "$RENDERED" \
    "$NAMEDIR/nm-openvpn3-service.name"

sudo install -m 0644 data/dbus-1/nm-openvpn3-service.conf \
    /usr/share/dbus-1/system.d/nm-openvpn3-service.conf

# Compile + install gettext catalogs.  Editor binds textdomain
# `nm-openvpn3` against /usr/share/locale; without .mo files the
# strings fall through to English (gettext's pass-through behaviour).
# Missing msgfmt is non-fatal — log + skip.
if command -v msgfmt >/dev/null 2>&1; then
    for po in po/*.po; do
        [ -e "$po" ] || continue
        lang=$(basename "$po" .po)
        moroot=/usr/share/locale/$lang/LC_MESSAGES
        sudo install -d "$moroot"
        tmpmo=$(mktemp -t "nm-openvpn3-$lang.mo.XXXXXX")
        # On msgfmt error: scrub the temp file and skip this catalog
        # rather than halting the whole install (set -e would otherwise
        # abort the script and leak the tempfile in /tmp).
        if msgfmt -o "$tmpmo" "$po"; then
            sudo install -m 0644 "$tmpmo" "$moroot/nm-openvpn3.mo"
            echo "Installed translation: $moroot/nm-openvpn3.mo"
        else
            echo "msgfmt failed on $po; skipping ($lang stays in English)."
        fi
        rm -f "$tmpmo"
    done
else
    echo "msgfmt not found; skipping translation install (English only)."
fi

sudo systemctl reload dbus
# Make NM re-scan VPN .name files + drop any stale plugin handle it
# cached from the deleted rust/skeleton install.  Safe (NM picks the
# new files back up on the next nmcli call).
sudo systemctl reload NetworkManager 2>/dev/null \
    || sudo systemctl restart NetworkManager
echo
echo "Installed.  Verify with:"
echo "  stat $LIBEXECDIR/nm-openvpn3-service"
echo "  cat  $NAMEDIR/nm-openvpn3-service.name"
echo
echo "Create a test connection (note vpn-type changed from"
echo "  'openvpn3.rust' on the rust/skeleton branch to 'openvpn3' here):"
echo "  nmcli connection add type vpn vpn-type openvpn3 con-name ovpn3-test \\"
echo "      vpn.data 'nm-openvpn3-profile=/path/to/profile.ovpn,connection-type=tls'"
echo
echo "If you had a connection from rust/skeleton (vpn-type=openvpn3.rust),"
echo "switch its service-type to the new value:"
echo "  nmcli connection modify ovpn3-rust-test \\"
echo "    vpn.service-type org.freedesktop.NetworkManager.openvpn3"
echo "  # (or just nmcli connection delete + re-create with vpn-type openvpn3)"
echo
echo "Activate + watch the journal:"
echo "  nmcli connection up ovpn3-test"
# Kernel truncates comm to TASK_COMM_LEN=16 (15 chars + NUL), so
# "nm-openvpn3-service" surfaces as "nm-openvpn3-ser" in journald.
echo "  journalctl --since '1 min ago' _COMM=nm-openvpn3-ser"
