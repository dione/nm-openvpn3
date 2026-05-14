#include "ovpn3-routes.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

GArray *
ovpn3_parse_proc_routes (const gchar *table_text,
                         const gchar *iface)
{
	g_return_val_if_fail (table_text != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	GArray *out = g_array_new (FALSE, FALSE, sizeof (Ovpn3Route));
	g_auto (GStrv) lines = g_strsplit (table_text, "\n", -1);

	for (gsize i = 1; lines[i] != NULL; i++) {
		const gchar *line = lines[i];
		gchar dev[32] = {0};
		guint32 dest = 0, gw = 0, flags = 0, refcnt = 0, use = 0;
		guint32 metric = 0, mask = 0, mtu = 0, win = 0, irtt = 0;
		int n;
		Ovpn3Route r;

		if (!*line)
			continue;

		n = sscanf (line,
		            "%31s %X %X %X %u %u %u %X %u %u %u",
		            dev, &dest, &gw, &flags, &refcnt, &use,
		            &metric, &mask, &mtu, &win, &irtt);
		if (n < 8)
			continue;

		if (g_strcmp0 (dev, iface) != 0)
			continue;

		/* /proc/net/route prints the kernel's __be32 address values via
		 * %08X.  On a little-endian host the printf renders the byte-
		 * swapped interpretation, so the %X parse returns exactly the
		 * sin_addr.s_addr-style uint32 NM expects — NO htonl needed.
		 * The earlier "byte swap on LE" attempt double-swapped and broke
		 * the on-link skip in nm-openvpn3-service.c. */

		/* popcount(mask) is only a valid CIDR prefix length when the
		 * mask is contiguous (all 1-bits packed at the high-order end).
		 * In the s_addr-style representation we read here, that means
		 * after host-byte-order convert the high bits must be 1s, low
		 * bits 0s.  Convert with ntohl then test the kernel-style
		 * (~m) & ((~m) + 1) == 0 idiom; reject non-contiguous masks
		 * (the kernel does not install them via the FIB but a hand-
		 * crafted /proc/net/route file or future kernel feature could
		 * surface one and we should not silently truncate it). */
		guint32 host_mask = ntohl (mask);
		guint32 not_m = ~host_mask;
		if ((not_m & (not_m + 1)) != 0) {
			g_message ("ovpn3-routes: skipping route with non-contiguous "
			           "mask 0x%08x on %s", mask, dev);
			continue;
		}

		r.dest_be     = dest;
		r.next_hop_be = gw;
		r.prefix      = (guint32) __builtin_popcount (mask);
		r.metric      = metric;
		g_array_append_val (out, r);
	}
	return out;
}

GArray *
ovpn3_read_proc_routes (const gchar *iface, GError **error)
{
	g_autofree gchar *buf = NULL;

	g_return_val_if_fail (iface != NULL, NULL);

	if (!g_file_get_contents ("/proc/net/route", &buf, NULL, error))
		return NULL;
	return ovpn3_parse_proc_routes (buf, iface);
}
