#ifndef __OVPN3_STATUS_H__
#define __OVPN3_STATUS_H__

#include <glib.h>
#include <NetworkManager.h>

typedef enum {
	OVPN3_MAJOR_UNSET      = 0,
	OVPN3_MAJOR_CONFIG     = 1,
	OVPN3_MAJOR_CONNECTION = 2,
	OVPN3_MAJOR_SESSION    = 3,
	OVPN3_MAJOR_PKCS11     = 4,
	OVPN3_MAJOR_PROCESS    = 5,
} Ovpn3StatusMajor;

typedef enum {
	OVPN3_MINOR_CONN_CONNECTING   = 2,
	OVPN3_MINOR_CONN_CONNECTED    = 7,
	OVPN3_MINOR_CONN_DISCONNECTED = 8,
	OVPN3_MINOR_CONN_RECONNECTING = 9,
} Ovpn3MinorConnection;

typedef enum {
	OVPN3_MINOR_SESS_AUTH_FAILED    = 4,
	OVPN3_MINOR_SESS_AUTH_USER_PASS = 5,
} Ovpn3MinorSession;

/* Maps an openvpn3 StatusChange tuple to a NetworkManager VPN service state.
 * Returns -1 if the status is not actionable (e.g. log-only).  On a known
 * status, fills *reason with the appropriate NMVpnConnectionStateReason.
 *
 * NMVpnConnectionStateReason is deprecated upstream in favour of
 * NMActiveConnectionStateReason; the NM VPN-plugin API still accepts the
 * old type though, so the wrapper macros suppress the GLib deprecation
 * warning at the only place we expose the symbol. */
G_GNUC_BEGIN_IGNORE_DEPRECATIONS
int ovpn3_status_to_nm_state (guint32                       code_major,
                              guint32                       code_minor,
                              NMVpnConnectionStateReason   *reason);
G_GNUC_END_IGNORE_DEPRECATIONS

#endif
