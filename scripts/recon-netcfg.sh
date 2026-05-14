#!/bin/bash
# Recon openvpn3 netcfg device properties for Plan 1b.
#
# Brings up the named NM VPN connection (default: ovpn3-oversee-eu),
# locates the openvpn3 session and its netcfg device, introspects the
# netcfg interface, and dumps sample reads of common property names so
# we know which names actually resolve on this openvpn3-linux version.
#
# Re-runnable.  Does NOT take the VPN down at the end.
#
# Usage:
#   scripts/recon-netcfg.sh [con-name]

set -u
CON_NAME=${1:-ovpn3-oversee-eu}

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: $1 not in PATH" >&2
        exit 2
    }
}
need nmcli
need sudo
need gdbus
need openvpn3

# --- bring VPN up if not already active ----------------------------------
if ! nmcli -t -f NAME connection show --active | grep -qx "$CON_NAME"; then
    echo ">>> bringing up $CON_NAME"
    if ! nmcli connection up "$CON_NAME"; then
        echo "error: failed to activate $CON_NAME" >&2
        exit 3
    fi
else
    echo ">>> $CON_NAME already active"
fi

# --- find session + device paths -----------------------------------------
SESS_PATH=$(sudo openvpn3 sessions-list 2>&1 | awk '/Path:/{print $2; exit}')
if [[ -z "$SESS_PATH" ]]; then
    echo "error: no openvpn3 session found" >&2
    exit 4
fi
echo "SESS_PATH=$SESS_PATH"

DEV_PATH=$(sudo gdbus call --system --dest net.openvpn.v3.sessions \
           --object-path "$SESS_PATH" \
           --method org.freedesktop.DBus.Properties.Get \
           net.openvpn.v3.sessions device_path 2>&1 \
           | grep -oE "/net/openvpn/v3/netcfg/[^'\"]*" | head -1)
if [[ -z "$DEV_PATH" ]]; then
    echo "error: could not resolve session.device_path" >&2
    exit 5
fi
echo "DEV_PATH=$DEV_PATH"
echo

# --- introspect netcfg interface -----------------------------------------
echo "=== introspect net.openvpn.v3.netcfg (interface block only) ==="
sudo gdbus introspect --system --dest net.openvpn.v3.netcfg \
     --object-path "$DEV_PATH" --recurse \
  | sed -n '/interface net.openvpn.v3.netcfg/,/^  };/p'
echo

# --- sample reads of candidate property names ----------------------------
echo "=== Properties.Get sample reads ==="
CANDIDATES=(
    dns_servers
    dns_search
    dns_search_domains
    ipv4_addresses
    ipv4_routes
    routes
    ipv4_gateway
    mtu
    layer
    proxy_settings
)
for P in "${CANDIDATES[@]}"; do
    out=$(sudo gdbus call --system --dest net.openvpn.v3.netcfg \
              --object-path "$DEV_PATH" \
              --method org.freedesktop.DBus.Properties.Get \
              net.openvpn.v3.netcfg "$P" 2>&1)
    if grep -q 'UnknownProperty' <<<"$out"; then
        printf '  %-22s  -> (UnknownProperty)\n' "$P"
    else
        # Print first 200 chars to keep output sane.
        printf '  %-22s  -> %s\n' "$P" "$(printf '%s' "$out" | head -c 200)"
    fi
done
echo

# --- GetAll for completeness (may dump a lot) ----------------------------
echo "=== Properties.GetAll (compact) ==="
sudo gdbus call --system --dest net.openvpn.v3.netcfg \
     --object-path "$DEV_PATH" \
     --method org.freedesktop.DBus.Properties.GetAll \
     net.openvpn.v3.netcfg 2>&1 | head -c 4000
echo
echo
echo ">>> done.  VPN left up.  Tear down with: nmcli connection down $CON_NAME"
