#include "ovpn3-status.h"

#include <NetworkManager.h>   /* NM_VPN_SERVICE_STATE_* */

int
ovpn3_status_to_nm_state (guint32 code_major,
                          guint32 code_minor)
{
	if (code_major == OVPN3_MAJOR_CONNECTION) {
		switch (code_minor) {
		case OVPN3_MINOR_CONN_CONNECTING:
		case OVPN3_MINOR_CONN_RECONNECTING:
			return NM_VPN_SERVICE_STATE_STARTING;
		case OVPN3_MINOR_CONN_CONNECTED:
			return NM_VPN_SERVICE_STATE_STARTED;
		case OVPN3_MINOR_CONN_DISCONNECTED:
			return NM_VPN_SERVICE_STATE_STOPPED;
		default:
			return -1;
		}
	}
	if (code_major == OVPN3_MAJOR_SESSION) {
		switch (code_minor) {
		case OVPN3_MINOR_SESS_AUTH_FAILED:
			return NM_VPN_SERVICE_STATE_STOPPED;
		default:
			return -1;
		}
	}
	return -1;
}
