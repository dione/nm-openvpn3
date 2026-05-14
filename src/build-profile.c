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

/**
 * build_profile_string:
 * @connection: an NMConnection describing the VPN
 * @error: (out) (nullable): location for a GError
 *
 * Serialises @connection to an .ovpn profile string by delegating to
 * do_export() (which writes a file) and then reading the result back.
 * The temp file is unlinked whether or not the read succeeds.
 *
 * Returns: (transfer full): newly-allocated profile string, or %NULL on error.
 */
gchar *
build_profile_string (NMConnection *connection, GError **error)
{
	g_autofree gchar *tmp_path = g_strdup ("/tmp/nm-openvpn3-profile-XXXXXX");
	int fd;
	gchar *buf = NULL;
	gsize  len = 0;

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
