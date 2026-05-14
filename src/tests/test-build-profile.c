/*
 * network-manager-openvpn - OpenVPN integration with NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>
#include <NetworkManager.h>
#include <string.h>

#include "build-profile.h"

static void
test_minimal_profile (void)
{
	g_autoptr (NMConnection) c = nm_simple_connection_new ();
	NMSettingConnection *s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "ovpn3-test",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
	              NM_SETTING_CONNECTION_UUID, "00000000-0000-0000-0000-000000000000",
	              NULL);
	nm_connection_add_setting (c, (NMSetting *) s_con);

	NMSettingVpn *s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.openvpn3",
	              NULL);
	nm_setting_vpn_add_data_item (s_vpn, "remote", "127.0.0.1:1194");
	nm_setting_vpn_add_data_item (s_vpn, "connection-type", "tls");
	nm_setting_vpn_add_data_item (s_vpn, "ca", "/etc/ssl/certs/ca-certificates.crt");
	nm_setting_vpn_add_data_item (s_vpn, "cert", "/etc/ssl/certs/ca-certificates.crt");
	nm_setting_vpn_add_data_item (s_vpn, "key", "/etc/ssl/certs/ca-certificates.crt");
	nm_connection_add_setting (c, (NMSetting *) s_vpn);

	g_autoptr (GError) e = NULL;
	g_autofree gchar *prof = build_profile_string (c, &e);
	g_assert_no_error (e);
	g_assert_nonnull (prof);
	/* do_export quotes the host token, producing "remote '127.0.0.1' 1194" */
	g_assert_true (strstr (prof, "127.0.0.1") != NULL);
	g_assert_true (strstr (prof, "1194") != NULL);
	g_assert_true (strstr (prof, "client") != NULL);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_test_add_func ("/ovpn3/build-profile/minimal", test_minimal_profile);
	return g_test_run ();
}
