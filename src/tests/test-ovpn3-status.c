#include <glib.h>
#include <NetworkManager.h>   /* for NM_VPN_CONNECTION_STATE_* */

#include "ovpn3-status.h"

static void
test_connection_connected_maps_to_nm_activated (void)
{
	NMVpnConnectionStateReason reason = 0;
	int nm_state = ovpn3_status_to_nm_state (OVPN3_MAJOR_CONNECTION,
	                                          OVPN3_MINOR_CONN_CONNECTED,
	                                          &reason);
	g_assert_cmpint (nm_state, ==, NM_VPN_SERVICE_STATE_STARTED);
	g_assert_cmpint (reason, ==, NM_VPN_CONNECTION_STATE_REASON_NONE);
}

static void
test_session_auth_failed_maps_to_login_failed (void)
{
	NMVpnConnectionStateReason reason = 0;
	int nm_state = ovpn3_status_to_nm_state (OVPN3_MAJOR_SESSION,
	                                          OVPN3_MINOR_SESS_AUTH_FAILED,
	                                          &reason);
	g_assert_cmpint (nm_state, ==, NM_VPN_SERVICE_STATE_STOPPED);
	g_assert_cmpint (reason, ==, NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED);
}

static void
test_unknown_status_returns_unknown (void)
{
	NMVpnConnectionStateReason reason = 99;
	int nm_state = ovpn3_status_to_nm_state (0xFF, 0xFF, &reason);
	g_assert_cmpint (nm_state, ==, -1);
	g_assert_cmpint (reason, ==, 99);   /* untouched on unknown */
}

static void
test_connection_connecting_maps_to_starting (void)
{
	NMVpnConnectionStateReason reason = 0;
	int nm_state = ovpn3_status_to_nm_state (OVPN3_MAJOR_CONNECTION,
	                                          OVPN3_MINOR_CONN_CONNECTING,
	                                          &reason);
	g_assert_cmpint (nm_state, ==, NM_VPN_SERVICE_STATE_STARTING);
	g_assert_cmpint (reason, ==, NM_VPN_CONNECTION_STATE_REASON_NONE);
}

static void
test_connection_reconnecting_maps_to_starting (void)
{
	NMVpnConnectionStateReason reason = 0;
	int nm_state = ovpn3_status_to_nm_state (OVPN3_MAJOR_CONNECTION,
	                                          OVPN3_MINOR_CONN_RECONNECTING,
	                                          &reason);
	g_assert_cmpint (nm_state, ==, NM_VPN_SERVICE_STATE_STARTING);
	g_assert_cmpint (reason, ==, NM_VPN_CONNECTION_STATE_REASON_NONE);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_test_add_func ("/ovpn3/status/connected", test_connection_connected_maps_to_nm_activated);
	g_test_add_func ("/ovpn3/status/auth-failed", test_session_auth_failed_maps_to_login_failed);
	g_test_add_func ("/ovpn3/status/unknown", test_unknown_status_returns_unknown);
	g_test_add_func ("/ovpn3/status/connecting", test_connection_connecting_maps_to_starting);
	g_test_add_func ("/ovpn3/status/reconnecting", test_connection_reconnecting_maps_to_starting);
	return g_test_run ();
}
