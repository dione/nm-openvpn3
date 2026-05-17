#!/usr/bin/env bash
# Install the Rust port side-by-side with the C plugin for smoke
# testing.  Idempotent — re-run after every rebuild.

set -euo pipefail

cd "$(dirname "$0")"

cargo build --release

PLUGINDIR=/usr/lib/x86_64-linux-gnu/NetworkManager
LIBEXECDIR=/usr/libexec
NAMEDIR=/usr/lib/NetworkManager/VPN

sudo install -m 0755 target/release/nm-openvpn3-service \
    "$LIBEXECDIR/nm-openvpn3-rust-service"

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
echo "  journalctl --since '1 min ago' _COMM=nm-openvpn3-rust"
