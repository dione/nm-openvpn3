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
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <string.h>

#include "build-profile.h"

/* Create a uniquely-named temp file containing @content and return its
 * absolute path; the caller must g_unlink + g_free it. */
static gchar *
write_temp_file (const char *content, GError **error)
{
	g_autofree gchar *tmpl = g_strdup ("nm-openvpn3-test-XXXXXX");
	g_autofree gchar *path = NULL;
	GError *local = NULL;
	int fd = g_file_open_tmp (tmpl, &path, &local);
	if (fd < 0) {
		g_propagate_error (error, local);
		return NULL;
	}
	if (!g_file_set_contents (path, content, -1, &local)) {
		close (fd);
		g_unlink (path);
		g_propagate_error (error, local);
		return NULL;
	}
	close (fd);
	return g_steal_pointer (&path);
}

static void
test_minimal_profile (void)
{
	g_autoptr (GError) ferr = NULL;
	g_autofree gchar *ca_path   = write_temp_file ("# dummy CA\n",   &ferr);
	g_assert_no_error (ferr);
	g_autofree gchar *cert_path = write_temp_file ("# dummy cert\n", &ferr);
	g_assert_no_error (ferr);
	g_autofree gchar *key_path  = write_temp_file ("# dummy key\n",  &ferr);
	g_assert_no_error (ferr);
	g_assert_nonnull (ca_path);
	g_assert_nonnull (cert_path);
	g_assert_nonnull (key_path);
	/* The three paths must actually differ — otherwise the build_profile
	 * round-trip can't tell apart ca/cert/key. */
	g_assert_cmpstr (ca_path, !=, cert_path);
	g_assert_cmpstr (ca_path, !=, key_path);
	g_assert_cmpstr (cert_path, !=, key_path);

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
	nm_setting_vpn_add_data_item (s_vpn, "ca",   ca_path);
	nm_setting_vpn_add_data_item (s_vpn, "cert", cert_path);
	nm_setting_vpn_add_data_item (s_vpn, "key",  key_path);
	nm_connection_add_setting (c, (NMSetting *) s_vpn);

	g_autoptr (GError) e = NULL;
	g_autofree gchar *prof = build_profile_string (c, &e);
	g_assert_no_error (e);
	g_assert_nonnull (prof);
	/* do_export quotes the host token, producing "remote '127.0.0.1' 1194" */
	g_assert_true (strstr (prof, "127.0.0.1") != NULL);
	g_assert_true (strstr (prof, "1194") != NULL);
	g_assert_true (strstr (prof, "client") != NULL);
	/* The three distinct paths should all appear in the exported profile. */
	g_assert_true (strstr (prof, ca_path)   != NULL);
	g_assert_true (strstr (prof, cert_path) != NULL);
	g_assert_true (strstr (prof, key_path)  != NULL);

	g_unlink (ca_path);
	g_unlink (cert_path);
	g_unlink (key_path);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_test_add_func ("/ovpn3/build-profile/minimal", test_minimal_profile);
	return g_test_run ();
}
