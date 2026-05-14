#ifndef __OVPN3_ROUTES_H__
#define __OVPN3_ROUTES_H__

#include <glib.h>

typedef struct {
	guint32 dest_be;
	guint32 prefix;
	guint32 next_hop_be;
	guint32 metric;
} Ovpn3Route;

/* Parse a /proc/net/route-style table and return entries matching @iface.
 * Returned GArray owns Ovpn3Route elements; free with g_array_free(arr, TRUE). */
GArray *ovpn3_parse_proc_routes (const gchar *table_text,
                                 const gchar *iface);

/* Convenience: read /proc/net/route directly. */
GArray *ovpn3_read_proc_routes (const gchar *iface,
                                GError     **error);

#endif
