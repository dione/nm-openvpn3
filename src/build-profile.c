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

#include "nm-default.h"

#include "build-profile.h"

#include <fcntl.h>
#include <unistd.h>
#include <glib/gstdio.h>

#include "../properties/import-export.h"

/* NM_OPENVPN3_KEY_PROFILE carries the path to a verbatim .ovpn file.  When
 * present, build_profile_string reads it directly instead of round-tripping
 * the NMConnection through do_export(); this preserves modern openvpn3
 * syntax (tls-crypt-v2, peer-fingerprint, data-ciphers, etc.) that the
 * upstream 1.12.5 token exporter cannot reproduce.  The UI surfaces this
 * key through the "OVPN profile file" entry on the main VPN tab. */

/**
 * build_profile_string:
 * @connection: an NMConnection describing the VPN
 * @error: (out) (nullable): location for a GError
 *
 * Serialises @connection to an .ovpn profile string.  If the connection's
 * vpn.data contains an `nm-openvpn3-profile` key pointing at a readable
 * file, the file's contents are returned verbatim.  Otherwise the function
 * falls back to do_export() (write tempfile + read back).
 *
 * Returns: (transfer full): newly-allocated profile string, or %NULL on error.
 */
gchar *
build_profile_string (NMConnection *connection, GError **error)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	const char *raw_path = NULL;
	g_autofree gchar *tmp_path = NULL;
	int fd;
	gchar *buf = NULL;
	gsize  len = 0;

	if (s_vpn)
		raw_path = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN3_KEY_PROFILE);

	if (raw_path && *raw_path) {
		if (!g_file_get_contents (raw_path, &buf, &len, error))
			return NULL;
		return buf;
	}

	tmp_path = g_strdup ("/tmp/nm-openvpn3-profile-XXXXXX");

	fd = g_mkstemp_full (tmp_path, O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_FAILED,
		                     "could not allocate tempfile for profile export");
		return NULL;
	}
	close (fd);

	if (!do_export (tmp_path, connection, error)) {
		g_unlink (tmp_path);
		return NULL;
	}

	if (!g_file_get_contents (tmp_path, &buf, &len, error)) {
		g_unlink (tmp_path);
		return NULL;
	}

	g_unlink (tmp_path);
	return buf;
}
