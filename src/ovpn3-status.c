#include "ovpn3-status.h"

int
ovpn3_status_to_nm_state (guint32                     code_major,
                          guint32                     code_minor,
                          NMVpnConnectionStateReason *reason)
{
	g_return_val_if_fail (reason != NULL, -1);

	if (code_major == OVPN3_MAJOR_CONNECTION) {
		switch (code_minor) {
		case OVPN3_MINOR_CONN_CONNECTING:
			*reason = NM_VPN_CONNECTION_STATE_REASON_NONE;
			return NM_VPN_SERVICE_STATE_STARTING;
		case OVPN3_MINOR_CONN_CONNECTED:
			*reason = NM_VPN_CONNECTION_STATE_REASON_NONE;
			return NM_VPN_SERVICE_STATE_STARTED;
		case OVPN3_MINOR_CONN_DISCONNECTED:
			*reason = NM_VPN_CONNECTION_STATE_REASON_NONE;
			return NM_VPN_SERVICE_STATE_STOPPED;
		case OVPN3_MINOR_CONN_RECONNECTING:
			*reason = NM_VPN_CONNECTION_STATE_REASON_NONE;
			return NM_VPN_SERVICE_STATE_STARTING;
		default:
			return -1;
		}
	}
	if (code_major == OVPN3_MAJOR_SESSION) {
		switch (code_minor) {
		case OVPN3_MINOR_SESS_AUTH_FAILED:
			*reason = NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED;
			return NM_VPN_SERVICE_STATE_STOPPED;
		default:
			return -1;
		}
	}
	return -1;
}
