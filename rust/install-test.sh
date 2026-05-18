#!/usr/bin/env bash
# Install the Rust port side-by-side with the C plugin for smoke
# testing.  Idempotent — re-run after every rebuild.

set -euo pipefail

cd "$(dirname "$0")"

cargo build --release

# Auto-detect the NetworkManager plugin directory.  Debian / Ubuntu
# ship libnm-vpn-plugin-openvpn3.so under /usr/lib/<multiarch>/NetworkManager,
# Fedora / Arch under /usr/lib/NetworkManager.  Probe candidates in
# order and fall back to the bare path if none match.
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
# NM probes the multiarch + lib64 + lib paths in the same priority order
# as the cdylib plugin dir, so pick the matching VPN subdir to avoid
# installing a .name file NM never reads.
NAMEDIR=$(detect_dir "/VPN")
echo "Using PLUGINDIR=$PLUGINDIR"
echo "Using NAMEDIR=$NAMEDIR"

sudo install -m 0755 target/release/nm-openvpn3-service \
    "$LIBEXECDIR/nm-openvpn3-rust-service"
sudo install -m 0755 target/release/nm-openvpn3-auth-dialog \
    "$LIBEXECDIR/nm-openvpn3-rust-auth-dialog"

# Render the @LIBEXECDIR@ / @PLUGINDIR@ placeholders.  Use mktemp so a
# pre-planted symlink in /tmp can't redirect the install.
RENDERED=$(mktemp -t nm-openvpn3-rust-service.name.XXXXXX)
trap 'rm -f "$RENDERED"' EXIT
sed -e "s|@LIBEXECDIR@|$LIBEXECDIR|g" \
    -e "s|@PLUGINDIR@|$PLUGINDIR|g" \
    nm-openvpn3-rust-service.name \
    > "$RENDERED"
sudo install -m 0644 "$RENDERED" \
    "$NAMEDIR/nm-openvpn3-rust-service.name"

sudo systemctl reload dbus
echo
echo "Installed.  Verify with:"
echo "  stat $LIBEXECDIR/nm-openvpn3-rust-service"
echo "  cat  $NAMEDIR/nm-openvpn3-rust-service.name"
echo
echo "Create a test connection:"
echo "  nmcli connection add type vpn vpn-type openvpn3.rust con-name ovpn3-rust-test \\"
echo "      vpn.data 'nm-openvpn3-profile=/path/to/profile.ovpn,connection-type=tls'"
echo
echo "Activate + watch the journal:"
echo "  nmcli connection up ovpn3-rust-test"
# Kernel truncates comm to TASK_COMM_LEN=16 (15 chars + NUL), so the
# full binary name "nm-openvpn3-rust-service" shows up as
# "nm-openvpn3-rus" in journald's _COMM field.
echo "  journalctl --since '1 min ago' _COMM=nm-openvpn3-rus"
