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
detect_plugindir() {
    local triplet candidates d
    triplet=$(gcc -dumpmachine 2>/dev/null \
              || dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
              || true)
    candidates=()
    if [ -n "$triplet" ]; then
        candidates+=("/usr/lib/${triplet}/NetworkManager")
    fi
    candidates+=(
        "/usr/lib64/NetworkManager"
        "/usr/lib/NetworkManager"
    )
    for d in "${candidates[@]}"; do
        if [ -d "$d" ]; then
            printf '%s\n' "$d"
            return 0
        fi
    done
    printf '/usr/lib/NetworkManager\n'
}
PLUGINDIR=$(detect_plugindir)
LIBEXECDIR=/usr/libexec
NAMEDIR=/usr/lib/NetworkManager/VPN
echo "Using PLUGINDIR=$PLUGINDIR"

sudo install -m 0755 target/release/nm-openvpn3-service \
    "$LIBEXECDIR/nm-openvpn3-rust-service"
sudo install -m 0755 target/release/nm-openvpn3-auth-dialog \
    "$LIBEXECDIR/nm-openvpn3-rust-auth-dialog"

# Render the @LIBEXECDIR@ / @PLUGINDIR@ placeholders.
sed -e "s|@LIBEXECDIR@|$LIBEXECDIR|g" \
    -e "s|@PLUGINDIR@|$PLUGINDIR|g" \
    nm-openvpn3-rust-service.name \
    > /tmp/nm-openvpn3-rust-service.name
sudo install -m 0644 /tmp/nm-openvpn3-rust-service.name \
    "$NAMEDIR/nm-openvpn3-rust-service.name"
rm /tmp/nm-openvpn3-rust-service.name

sudo systemctl reload dbus
echo
echo "Installed.  Verify with:"
echo "  stat $LIBEXECDIR/nm-openvpn3-rust-service"
echo "  cat  $NAMEDIR/nm-openvpn3-rust-service.name"
echo
echo "Create a test connection:"
echo "  nmcli connection add type vpn vpn-type openvpn3rust con-name ovpn3-rust-test \\"
echo "      vpn.data 'nm-openvpn3-profile=/path/to/profile.ovpn,connection-type=tls'"
echo
echo "Activate + watch the journal:"
echo "  nmcli connection up ovpn3-rust-test"
echo "  journalctl --since '1 min ago' _COMM=nm-openvpn3-rust-service"
