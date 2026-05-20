#!/usr/bin/env bash
# Build + install the openvpn3 NM VPN plugin (Rust implementation) for
# smoke testing on a workstation.  Idempotent — re-run after every
# rebuild.  For packaging see data/ (the canonical install paths the
# downstream packager should mirror).

set -euo pipefail

cd "$(dirname "$0")"

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
# NM probes the multiarch + lib64 + lib paths in the same priority order
# as the cdylib plugin dir, so pick the matching VPN subdir to avoid
# installing a .name file NM never reads.
NAMEDIR=$(detect_dir "/VPN")
echo "Using PLUGINDIR=$PLUGINDIR"
echo "Using NAMEDIR=$NAMEDIR"

sudo install -m 0755 target/release/nm-openvpn3-service \
    "$LIBEXECDIR/nm-openvpn3-service"
sudo install -m 0755 target/release/nm-openvpn3-auth-dialog \
    "$LIBEXECDIR/nm-openvpn3-auth-dialog"

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

sudo systemctl reload dbus
echo
echo "Installed.  Verify with:"
echo "  stat $LIBEXECDIR/nm-openvpn3-service"
echo "  cat  $NAMEDIR/nm-openvpn3-service.name"
echo
echo "Create a test connection:"
echo "  nmcli connection add type vpn vpn-type openvpn3 con-name ovpn3-test \\"
echo "      vpn.data 'nm-openvpn3-profile=/path/to/profile.ovpn,connection-type=tls'"
echo
echo "Activate + watch the journal:"
echo "  nmcli connection up ovpn3-test"
# Kernel truncates comm to TASK_COMM_LEN=16 (15 chars + NUL), so
# "nm-openvpn3-service" surfaces as "nm-openvpn3-ser" in journald.
echo "  journalctl --since '1 min ago' _COMM=nm-openvpn3-ser"
