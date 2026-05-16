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

/* Maps an openvpn3 StatusChange tuple to a NetworkManager VPN service
 * state.  Returns -1 for log-only / non-actionable statuses, otherwise
 * one of NM_VPN_SERVICE_STATE_*.
 *
 * The original signature also returned an NMVpnConnectionStateReason
 * out-param but the service never read it back (and the type itself is
 * deprecated upstream).  Dropped to keep the API surface honest. */
int ovpn3_status_to_nm_state (guint32 code_major,
                              guint32 code_minor);

#endif
