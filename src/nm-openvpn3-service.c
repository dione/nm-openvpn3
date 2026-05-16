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
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2010 Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2008 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <errno.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>
#include <glib-unix.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"
#include "build-profile.h"
#include "ovpn3-client.h"
#include "ovpn3-status.h"
#include "ovpn3-routes.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static guint32
mask_for_prefix (guint32 prefix)
{
	if (prefix == 0)
		return 0;
	if (prefix >= 32)
		return 0xFFFFFFFFu;
	return g_htonl (0xFFFFFFFFu << (32 - prefix));
}

#define RUNDIR  LOCALSTATEDIR"/run/NetworkManager"

static struct {
	gboolean debug;
	GPtrArray *tmp_file_paths;
} gl/*obal*/;

#define NM_OPENVPN3_HELPER_PATH LIBEXECDIR"/nm-openvpn3-service-helper"

/*****************************************************************************/

#define NM_TYPE_OPENVPN3_PLUGIN            (nm_openvpn3_plugin_get_type ())
#define NM_OPENVPN3_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENVPN3_PLUGIN, NMOpenvpn3Plugin))
#define NM_OPENVPN3_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENVPN3_PLUGIN, NMOpenvpn3PluginClass))
#define NM_IS_OPENVPN3_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENVPN3_PLUGIN))
#define NM_IS_OPENVPN3_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OPENVPN3_PLUGIN))
#define NM_OPENVPN3_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENVPN3_PLUGIN, NMOpenvpn3PluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMOpenvpn3Plugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMOpenvpn3PluginClass;

GType nm_openvpn3_plugin_get_type (void);

NMOpenvpn3Plugin *nm_openvpn3_plugin_new (const char *bus_name);

/*****************************************************************************/


typedef struct {

	/* ovpn3 session state (Plan 1) */
	Ovpn3Client *ovpn3;
	gchar       *session_path;
	gchar       *config_path;
	guint        status_sub_id;
	guint        attention_sub_id;  /* AttentionRequired signal (Plan 2) */
	guint        poll_timer_id;
	guint        poll_ticks;
	gboolean     ip4_emitted;     /* TRUE after first STARTED transition; gate Ip4Config re-emit
	                                 and switches poll cadence to watchdog mode */
	GMainLoop   *wait_loop;
	int          wait_state;    /* most recent ovpn3_status_to_nm_state result */

	/* Periodic session.statistics fetch (logged to journal at _LOGI). */
	guint        stats_timer_id;
	gint64       stats_last_bytes_in;
	gint64       stats_last_bytes_out;
	gint64       stats_last_monotonic_us;

	/* Plan 2: most recent NMConnection (weak ref to its s_vpn) and the slot
	 * list fetched in response to the last AttentionRequired signal.
	 * real_new_secrets walks the list pushing each slot's value back to
	 * openvpn3 via UserInputProvide. */
	NMConnection *current_connection;
	GSList       *pending_slots;   /* Ovpn3InputSlot* — owned */
} NMOpenvpn3PluginPrivate;

G_DEFINE_TYPE (NMOpenvpn3Plugin, nm_openvpn3_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_OPENVPN3_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENVPN3_PLUGIN, NMOpenvpn3PluginPrivate))

/*****************************************************************************/


/*****************************************************************************/

/* Route every diagnostic through GLib's structured logger.  G_LOG_DOMAIN is
 * compiled-in as "nm-openvpn3" via -DG_LOG_DOMAIN in Makefile.am, so the
 * standard g_debug / g_message / g_warning helpers already tag the output
 * with our domain and reach the journal without any gating bookkeeping.
 *
 * Visibility under the default GLib handler:
 *   _LOGD → G_LOG_LEVEL_DEBUG    — suppressed unless G_MESSAGES_DEBUG matches
 *   _LOGI → G_LOG_LEVEL_MESSAGE  — always printed
 *   _LOGW → G_LOG_LEVEL_WARNING  — always printed (and flagged) */
#define _LOGD(...) g_debug   (__VA_ARGS__)
#define _LOGI(...) g_message (__VA_ARGS__)
#define _LOGW(...) g_warning (__VA_ARGS__)

/*****************************************************************************/

static gboolean
validate_connection_type (const char *ctype)
{
	return NM_IN_STRSET (ctype, NM_OPENVPN3_CONTYPE_TLS,
	                            NM_OPENVPN3_CONTYPE_STATIC_KEY,
	                            NM_OPENVPN3_CONTYPE_PASSWORD,
	                            NM_OPENVPN3_CONTYPE_PASSWORD_TLS);
}

static const char *
check_need_secrets (NMSettingVpn *s_vpn, gboolean *need_secrets)
{
	const char *tmp, *key, *ctype;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	gs_free char *key_free = NULL;

	g_return_val_if_fail (s_vpn != NULL, FALSE);
	g_return_val_if_fail (need_secrets != NULL, FALSE);

	*need_secrets = FALSE;

	ctype = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN3_KEY_CONNECTION_TYPE);
	if (!validate_connection_type (ctype))
		return NULL;

	if (nm_streq (ctype, NM_OPENVPN3_CONTYPE_PASSWORD_TLS)) {
		/* Will require a password and maybe private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN3_KEY_KEY);
		key = nm_utils_str_utf8safe_unescape (key, &key_free);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN3_KEY_CERTPASS))
			*need_secrets = TRUE;

		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN3_KEY_PASSWORD)) {
			*need_secrets = TRUE;
			if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN3_KEY_PASSWORD, &secret_flags, NULL)) {
				if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
					*need_secrets = FALSE;
			}
		}
	} else if (nm_streq (ctype, NM_OPENVPN3_CONTYPE_PASSWORD)) {
		/* Will require a password */
		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN3_KEY_PASSWORD)) {
			*need_secrets = TRUE;
			if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN3_KEY_PASSWORD, &secret_flags, NULL)) {
				if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
					*need_secrets = FALSE;
			}
		}
	} else if (nm_streq (ctype, NM_OPENVPN3_CONTYPE_TLS)) {
		/* May require private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN3_KEY_KEY);
		key = nm_utils_str_utf8safe_unescape (key, &key_free);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN3_KEY_CERTPASS))
			*need_secrets = TRUE;
	} else {
		/* Static key doesn't need passwords */
	}

	/* HTTP Proxy might require a password; assume so if there's an HTTP proxy username */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN3_KEY_HTTP_PROXY_USERNAME);
	if (tmp && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN3_KEY_HTTP_PROXY_PASSWORD))
		*need_secrets = TRUE;

	return ctype;
}

static void
clear_pending_slots (NMOpenvpn3PluginPrivate *priv)
{
	g_slist_free_full (priv->pending_slots,
	                   (GDestroyNotify) ovpn3_input_slot_free);
	priv->pending_slots = NULL;
}

/* Unsubscribe a signal id stored in @sub_id (zeroing it on the way out) iff
 * both the id and the client are still alive. */
static void
clear_signal_sub (Ovpn3Client *client, guint *sub_id)
{
	if (*sub_id && client) {
		ovpn3_session_unsubscribe (client, *sub_id);
		*sub_id = 0;
	}
}

/* Drop every per-session resource: signal subs, poll timer, pending slot
 * queue, cached connection ref, and the two D-Bus paths.  Shared by
 * real_disconnect (after telling openvpn3 to tear down) and dispose. */
static void
cleanup_session_state (NMOpenvpn3PluginPrivate *priv)
{
	clear_signal_sub (priv->ovpn3, &priv->status_sub_id);
	clear_signal_sub (priv->ovpn3, &priv->attention_sub_id);
	nm_clear_g_source (&priv->poll_timer_id);
	nm_clear_g_source (&priv->stats_timer_id);
	priv->ip4_emitted = FALSE;
	clear_pending_slots (priv);
	g_clear_object (&priv->current_connection);
	g_clear_pointer (&priv->session_path, g_free);
	g_clear_pointer (&priv->config_path, g_free);
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **error)
{
	NMOpenvpn3Plugin *self = NM_OPENVPN3_PLUGIN (plugin);
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	GError *local = NULL;

	if (!priv->session_path)
		return TRUE;   /* already disconnected */

	if (!ovpn3_session_disconnect (priv->ovpn3, priv->session_path, &local)) {
		_LOGW ("ovpn3 disconnect: %s", local->message);
		g_clear_error (&local);
	}

	cleanup_session_state (priv);
	return TRUE;
}

#define POLL_INTERVAL_MS 500
#define POLL_MAX_TICKS   120  /* 120 * 500 ms = 60 s */

static gboolean poll_status_cb (gpointer user_data);

/* Walk getifaddrs() looking for the AF_INET entry on @tundev.  On success
 * fills @addr_be / @prefix from the kernel (PtP peer pulled into @peer_be
 * for trace logging) and returns TRUE.  On miss/failure leaves outputs
 * untouched and returns FALSE.  Output BE values are network byte order. */
static gboolean
lookup_tun_ipv4 (const gchar *tundev,
                 guint32     *addr_be,
                 guint32     *peer_be,
                 guint32     *prefix)
{
	struct ifaddrs *ifap = NULL;
	gboolean found = FALSE;

	if (getifaddrs (&ifap) != 0)
		return FALSE;

	for (struct ifaddrs *p = ifap; p; p = p->ifa_next) {
		if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET)
			continue;
		if (g_strcmp0 (p->ifa_name, tundev) != 0)
			continue;
		*addr_be = ((struct sockaddr_in *) p->ifa_addr)->sin_addr.s_addr;
		if (p->ifa_dstaddr && p->ifa_dstaddr->sa_family == AF_INET)
			*peer_be = ((struct sockaddr_in *) p->ifa_dstaddr)->sin_addr.s_addr;
		if (p->ifa_netmask && p->ifa_netmask->sa_family == AF_INET) {
			guint32 mask_be = ((struct sockaddr_in *) p->ifa_netmask)->sin_addr.s_addr;
			*prefix = __builtin_popcount (mask_be);
		}
		found = TRUE;
		break;
	}
	freeifaddrs (ifap);
	return found;
}

/* Query openvpn3 for the remote endpoint host and parse to a BE uint32.
 * 0 on miss / parse failure (NM treats 0 as "no ext-gateway hint"). */
static guint32
lookup_ext_gateway_be (Ovpn3Client *ovpn3, const gchar *session_path)
{
	g_autofree gchar *ext_host = NULL;
	struct in_addr ia;

	if (!ovpn3_session_get_connected_to (ovpn3, session_path,
	                                     NULL, &ext_host, NULL, NULL))
		return 0;
	if (!ext_host || !*ext_host)
		return 0;
	if (!inet_aton (ext_host, &ia))
		return 0;
	g_message ("STARTED branch: ext_host='%s'", ext_host);
	return ia.s_addr;
}

/* Build the SetConfig vardict and hand it to NM.  This MUST happen before
 * SetIp4Config — without HAS_IP4=TRUE here, NM ignores the IP4 config. */
static void
emit_set_config (NMVpnServicePlugin *plugin,
                 const gchar        *tundev,
                 guint32             ext_gw_be,
                 gboolean            have_ip)
{
	GVariantBuilder cfgb;

	g_variant_builder_init (&cfgb, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&cfgb, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_TUNDEV,
	                       g_variant_new_string (tundev));
	if (ext_gw_be != 0)
		g_variant_builder_add (&cfgb, "{sv}",
		                       NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
		                       g_variant_new_uint32 (ext_gw_be));
	g_variant_builder_add (&cfgb, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP4,
	                       g_variant_new_boolean (have_ip));
	g_variant_builder_add (&cfgb, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP6,
	                       g_variant_new_boolean (FALSE));
	g_variant_builder_add (&cfgb, "{sv}",
	                       NM_VPN_PLUGIN_CAN_PERSIST,
	                       g_variant_new_boolean (FALSE));
	nm_vpn_service_plugin_set_config (plugin, g_variant_builder_end (&cfgb));
}

/* Pack the DNS server list into a "au" (network-byte-order uint32 array)
 * and add it under the NM_VPN_PLUGIN_IP4_CONFIG_DNS key on @b. */
static void
add_dns_servers (GVariantBuilder *b, GStrv dns_servers)
{
	GVariantBuilder dnsb;

	if (!dns_servers || !dns_servers[0])
		return;

	g_variant_builder_init (&dnsb, G_VARIANT_TYPE ("au"));
	for (gchar **p = dns_servers; *p; p++) {
		struct in_addr ia;
		if (inet_aton (*p, &ia))
			g_variant_builder_add (&dnsb, "u", ia.s_addr);
		else
			g_message ("DNS skip non-IPv4 entry '%s'", *p);
	}
	g_variant_builder_add (b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_DNS,
	                       g_variant_builder_end (&dnsb));
}

/* Pack DNS search domains into a "as" array on @b. */
static void
add_dns_search (GVariantBuilder *b, GStrv dns_search)
{
	GVariantBuilder dsb;

	if (!dns_search || !dns_search[0])
		return;

	g_variant_builder_init (&dsb, G_VARIANT_TYPE ("as"));
	for (gchar **p = dns_search; *p; p++)
		g_variant_builder_add (&dsb, "s", *p);
	g_variant_builder_add (b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS,
	                       g_variant_builder_end (&dsb));
}

/* Look for a 0.0.0.0/0 route on the tun device.  Absence implies the
 * profile has no redirect-gateway flag → split tunnel intent. */
static gboolean
routes_have_default (GArray *routes)
{
	if (!routes)
		return FALSE;
	for (guint i = 0; i < routes->len; i++) {
		Ovpn3Route r = g_array_index (routes, Ovpn3Route, i);
		if (r.prefix == 0 && r.dest_be == 0)
			return TRUE;
	}
	return FALSE;
}

/* Pack kernel routes into "aau" and add under IP4_CONFIG_ROUTES on @b.
 * Skips the on-link route NM derives from ADDRESS/PREFIX. */
static void
add_routes (GVariantBuilder *b, GArray *routes, guint32 addr_be, guint32 prefix)
{
	GVariantBuilder rb;
	guint emitted = 0;

	if (!routes || routes->len == 0)
		return;

	g_variant_builder_init (&rb, G_VARIANT_TYPE ("aau"));
	for (guint i = 0; i < routes->len; i++) {
		Ovpn3Route r = g_array_index (routes, Ovpn3Route, i);
		const guint32 mask = mask_for_prefix (prefix);

		if (r.prefix == prefix
		    && (r.dest_be & mask) == (addr_be & mask)
		    && r.next_hop_be == 0)
			continue;

		GVariantBuilder one;
		g_variant_builder_init (&one, G_VARIANT_TYPE ("au"));
		g_variant_builder_add (&one, "u", r.dest_be);
		g_variant_builder_add (&one, "u", r.prefix);
		g_variant_builder_add (&one, "u", r.next_hop_be);
		g_variant_builder_add (&one, "u", r.metric);
		g_variant_builder_add_value (&rb, g_variant_builder_end (&one));
		emitted++;
	}
	g_message ("routes emitted to NM: %u (of %u parsed)",
	             emitted, routes->len);
	g_variant_builder_add (b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_ROUTES,
	                       g_variant_builder_end (&rb));
}

/* Periodic openvpn3 session.statistics fetch.  Logged at _LOGI so users
 * can `journalctl -t nm-openvpn3-service | grep stats` to see live tunnel
 * throughput; openvpn3 counters cover the encrypted bytes-on-the-wire
 * which kernel netdev stats do not differentiate from the in-clear payload. */
#define STATS_INTERVAL_S 30

static gchar *
fmt_bytes (gint64 b)
{
	if (b < 1024)
		return g_strdup_printf ("%" G_GINT64_FORMAT " B", b);
	if (b < 1024 * 1024)
		return g_strdup_printf ("%.1f KB", b / 1024.0);
	if (b < 1024LL * 1024 * 1024)
		return g_strdup_printf ("%.1f MB", b / (1024.0 * 1024));
	return g_strdup_printf ("%.2f GB", b / (1024.0 * 1024 * 1024));
}

static gint64
hash_lookup_i64 (GHashTable *h, const char *key)
{
	gint64 *p = g_hash_table_lookup (h, key);
	return p ? *p : 0;
}

static gboolean
stats_timer_cb (gpointer user_data)
{
	NMOpenvpn3Plugin *self = NM_OPENVPN3_PLUGIN (user_data);
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);

	if (!priv->session_path || !priv->ovpn3) {
		priv->stats_timer_id = 0;
		return G_SOURCE_REMOVE;
	}

	g_autoptr (GError) e = NULL;
	g_autoptr (GHashTable) s = ovpn3_session_get_statistics (priv->ovpn3,
	                                                         priv->session_path,
	                                                         &e);
	if (!s) {
		g_message ("stats fetch failed: %s", e ? e->message : "(unknown)");
		return G_SOURCE_CONTINUE;
	}

	gint64 in       = hash_lookup_i64 (s, "BYTES_IN");
	gint64 out      = hash_lookup_i64 (s, "BYTES_OUT");
	gint64 pkt_in   = hash_lookup_i64 (s, "PACKETS_IN");
	gint64 pkt_out  = hash_lookup_i64 (s, "PACKETS_OUT");
	/* TUN_* counters are payload-side: bytes/packets that crossed the
	 * tun device in cleartext.  Subtracting from the encrypted BYTES_*
	 * gives the cryptographic + protocol overhead. */
	gint64 tun_in   = hash_lookup_i64 (s, "TUN_BYTES_IN");
	gint64 tun_out  = hash_lookup_i64 (s, "TUN_BYTES_OUT");

	gint64 now_us  = g_get_monotonic_time ();
	gint64 dt_us   = now_us - priv->stats_last_monotonic_us;
	gint64 d_in    = in  - priv->stats_last_bytes_in;
	gint64 d_out   = out - priv->stats_last_bytes_out;

	g_autofree gchar *fin   = fmt_bytes (in);
	g_autofree gchar *fout  = fmt_bytes (out);
	g_autofree gchar *ftin  = fmt_bytes (tun_in);
	g_autofree gchar *ftout = fmt_bytes (tun_out);

	if (priv->stats_last_monotonic_us > 0 && dt_us > 0) {
		gdouble rate_in  = (d_in  * G_GINT64_CONSTANT (1000000)) / (gdouble) dt_us;
		gdouble rate_out = (d_out * G_GINT64_CONSTANT (1000000)) / (gdouble) dt_us;
		g_autofree gchar *fri = fmt_bytes ((gint64) rate_in);
		g_autofree gchar *fro = fmt_bytes ((gint64) rate_out);
		g_message ("stats: rx=%s tx=%s tun_rx=%s tun_tx=%s pkt_in=%" G_GINT64_FORMAT
		             " pkt_out=%" G_GINT64_FORMAT " rate_rx=%s/s rate_tx=%s/s",
		             fin, fout, ftin, ftout, pkt_in, pkt_out, fri, fro);
	} else {
		g_message ("stats: rx=%s tx=%s tun_rx=%s tun_tx=%s pkt_in=%" G_GINT64_FORMAT
		             " pkt_out=%" G_GINT64_FORMAT,
		             fin, fout, ftin, ftout, pkt_in, pkt_out);
	}

	priv->stats_last_bytes_in     = in;
	priv->stats_last_bytes_out    = out;
	priv->stats_last_monotonic_us = now_us;
	return G_SOURCE_CONTINUE;
}

/* Emit the SetConfig + SetIp4Config bundle that flips NM from "activating"
 * to "activated".  Pre: priv->session_path is live and we have seen a
 * STARTED state from openvpn3.  Idempotent via the priv->ip4_emitted gate. */
static void
emit_started_ip4_config (NMOpenvpn3Plugin *self)
{
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	NMVpnServicePlugin *plugin = (NMVpnServicePlugin *) self;

	if (priv->ip4_emitted || !priv->session_path)
		return;

	g_autoptr (GError) ge = NULL;
	g_autofree gchar *dev = ovpn3_session_get_device_name (
		priv->ovpn3, priv->session_path, &ge);
	const gchar *tundev = (dev && *dev) ? dev : "tun0";
	g_message ("STARTED branch: device_name='%s'", tundev);

	/* Pull the IPv4 address openvpn3 already programmed on the tun
	 * device.  NM requires ADDRESS + PREFIX + INT_GATEWAY to mark
	 * the VPN as activated; emitting TUNDEV alone is not enough. */
	guint32 addr_be = 0, peer_be = 0;
	guint32 prefix = 32;
	gboolean have_ip = lookup_tun_ipv4 (tundev, &addr_be, &peer_be, &prefix);
	g_message ("STARTED branch: have_ip=%d addr=0x%08x peer=0x%08x prefix=%u",
	             have_ip, addr_be, peer_be, prefix);

	/* Read remote VPN endpoint (ext-gateway) so NM keeps a host route
	 * to it OUTSIDE the tunnel. */
	guint32 ext_gw_be = lookup_ext_gateway_be (priv->ovpn3, priv->session_path);
	g_message ("STARTED branch: ext_gw=0x%08x", ext_gw_be);

	/* Pull DNS + search domains from the openvpn3 netcfg device. */
	g_autofree gchar *dev_path = ovpn3_session_get_device_path (
		priv->ovpn3, priv->session_path, NULL);
	g_auto (GStrv) dns_servers = NULL;
	g_auto (GStrv) dns_search  = NULL;
	if (dev_path) {
		dns_servers = ovpn3_netcfg_get_dns_servers (priv->ovpn3, dev_path, NULL);
		dns_search  = ovpn3_netcfg_get_dns_search  (priv->ovpn3, dev_path, NULL);
	}
	g_message ("STARTED branch: dev_path=%s dns_count=%u search_count=%u",
	             dev_path ? dev_path : "(null)",
	             dns_servers ? g_strv_length (dns_servers) : 0,
	             dns_search  ? g_strv_length (dns_search)  : 0);

	emit_set_config (plugin, tundev, ext_gw_be, have_ip);

	GVariantBuilder b;
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV,
	                       g_variant_new_string (tundev));
	g_variant_builder_add (&b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
	                       g_variant_new_uint32 (addr_be));
	g_variant_builder_add (&b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
	                       g_variant_new_uint32 (prefix));
	/* openvpn3's tun device shows the broadcast address as PtP peer
	 * (e.g. .255 of a /20).  Pass 0 to let NM skip installing a
	 * gateway route — kernel already has the on-link route from
	 * openvpn3's netcfg setup. */
	g_variant_builder_add (&b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY,
	                       g_variant_new_uint32 (0));
	/* openvpn3 already installed routes via netcfg; tell NM not to
	 * recompute them. */
	g_variant_builder_add (&b, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES,
	                       g_variant_new_boolean (TRUE));

	add_dns_servers (&b, dns_servers);
	add_dns_search  (&b, dns_search);

	/* Pull installed routes from kernel for our tun device. */
	g_autoptr (GError) re = NULL;
	g_autoptr (GArray) routes = ovpn3_read_proc_routes (tundev, &re);
	g_message ("STARTED branch: route_count=%u%s%s",
	             routes ? routes->len : 0,
	             re ? " err=" : "",
	             re ? re->message : "");

	/* Detect openvpn3's split-tunnel intent: if it did NOT install a
	 * 0.0.0.0/0 route on the tun device, the profile has no
	 * redirect-gateway flag and the user wants split tunnel.  Tell NM
	 * to NOT promote the VPN to system default route — without this NM
	 * unconditionally installs 'default dev tunX' on top of openvpn3's
	 * per-subnet routes. */
	if (!routes_have_default (routes)) {
		g_variant_builder_add (&b, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT,
		                       g_variant_new_boolean (TRUE));
		g_message ("split-tunnel: emit never-default=TRUE (no 0.0.0.0/0 on tun)");
	}

	add_routes (&b, routes, addr_be, prefix);

	nm_vpn_service_plugin_set_ip4_config (plugin, g_variant_builder_end (&b));

	/* Drop the fast-poll cadence, re-arm a 5 s watchdog that checks the
	 * session is still alive.  When openvpn3 disconnects (either via
	 * 'session-manage --disconnect' from outside NM, or because of network
	 * loss), the status read fails and we propagate failure to NM. */
	priv->ip4_emitted = TRUE;
	priv->poll_ticks  = 0;
	nm_clear_g_source (&priv->poll_timer_id);
	priv->poll_timer_id = g_timeout_add_seconds (5, poll_status_cb, self);

	/* Arm periodic stats logger.  Reset rate-delta state so the first
	 * tick prints an absolute reading without a bogus rate value. */
	nm_clear_g_source (&priv->stats_timer_id);
	priv->stats_last_bytes_in     = 0;
	priv->stats_last_bytes_out    = 0;
	priv->stats_last_monotonic_us = 0;
	priv->stats_timer_id = g_timeout_add_seconds (STATS_INTERVAL_S,
	                                              stats_timer_cb, self);
}

/* Map an openvpn3 input slot name (e.g. "password", "static_challenge") to
 * the NM vpn-secrets key NM uses when popping the inline auth prompt.  The
 * mapping is heuristic because openvpn3 has more slot kinds than NM's
 * upstream key set; unknown names fall back to PASSWORD so the user still
 * gets a generic prompt. */
static const char *
slot_name_to_vpn_key (const Ovpn3InputSlot *slot)
{
	if (!slot || !slot->name)
		return NM_OPENVPN3_KEY_PASSWORD;
	if (g_strcmp0 (slot->name, "username") == 0)
		return NM_OPENVPN3_KEY_USERNAME;
	if (g_strcmp0 (slot->name, "password") == 0)
		return NM_OPENVPN3_KEY_PASSWORD;
	if (strstr (slot->name, "challenge") || strstr (slot->name, "response"))
		return NM_OPENVPN3_KEY_CHALLENGE_RESPONSE;
	if (strstr (slot->name, "private_key") || strstr (slot->name, "key_pass"))
		return NM_OPENVPN3_KEY_CERTPASS;
	if (strstr (slot->name, "http_proxy_user"))
		return NM_OPENVPN3_KEY_HTTP_PROXY_USERNAME;
	if (strstr (slot->name, "http_proxy_pass"))
		return NM_OPENVPN3_KEY_HTTP_PROXY_PASSWORD;
	return NM_OPENVPN3_KEY_PASSWORD;
}

/* Read the value backing @vkey: NM_OPENVPN3_KEY_USERNAME lives in vpn.data,
 * every other secrets-style key lives in vpn.secrets.  Returns NULL when the
 * key is unset or @s_vpn is NULL. */
static const char *
slot_value_from_s_vpn (NMSettingVpn *s_vpn, const char *vkey)
{
	if (!s_vpn)
		return NULL;
	if (nm_streq0 (vkey, NM_OPENVPN3_KEY_USERNAME))
		return nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN3_KEY_USERNAME);
	return nm_setting_vpn_get_secret (s_vpn, vkey);
}

/* Pre-provide slots that have an obvious value already stored in the
 * connection (username from vpn.data, persistent password from
 * vpn.secrets) — saves a round-trip through NM's secret dialog when the
 * user already saved their credentials.  Returns the subset of slots that
 * still need NM to prompt the user. */
static GSList *
auto_provide_known_slots (NMOpenvpn3Plugin *self, GSList *slots)
{
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn = priv->current_connection
		? nm_connection_get_setting_vpn (priv->current_connection) : NULL;
	GSList *still_needed = NULL;

	for (GSList *l = slots; l; l = l->next) {
		Ovpn3InputSlot *slot = l->data;
		const char *vkey = slot_name_to_vpn_key (slot);
		const char *value = slot_value_from_s_vpn (s_vpn, vkey);

		if (!value || !*value) {
			still_needed = g_slist_prepend (still_needed, slot);
			continue;
		}

		g_autoptr (GError) pe = NULL;
		if (ovpn3_session_provide_input (priv->ovpn3, priv->session_path,
		                                 slot->type, slot->group, slot->id,
		                                 value, &pe)) {
			g_message ("auto-ProvideInput(%s) ok", slot->name);
			ovpn3_input_slot_free (slot);
		} else {
			_LOGW ("auto-ProvideInput(%s) failed: %s",
			       slot->name, pe ? pe->message : "(unknown)");
			still_needed = g_slist_prepend (still_needed, slot);
		}
	}
	g_slist_free (slots);
	return g_slist_reverse (still_needed);
}

static void
attention_required_cb (guint32      type,
                       guint32      group,
                       const gchar *msg,
                       gpointer     user_data)
{
	NMOpenvpn3Plugin *self = NM_OPENVPN3_PLUGIN (user_data);
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	NMVpnServicePlugin *plugin = (NMVpnServicePlugin *) self;

	g_message ("AttentionRequired: type=%u group=%u msg='%s'",
	             type, group, msg ?: "");

	if (!priv->session_path) {
		g_message ("AttentionRequired: no session_path, ignoring");
		return;
	}

	/* Fetch every pending slot (across all type/group pairs, not just
	 * the one named in this signal — openvpn3 may have queued multiples). */
	g_autoptr (GError) fe = NULL;
	GSList *slots = ovpn3_session_fetch_input_slots (priv->ovpn3,
	                                                 priv->session_path,
	                                                 &fe);
	if (fe) {
		_LOGW ("FetchInputSlots failed: %s", fe->message);
		return;
	}
	if (!slots) {
		g_message ("AttentionRequired: queue empty, nothing to ask for");
		return;
	}

	/* Auto-provide whatever the connection already has stored. */
	slots = auto_provide_known_slots (self, slots);
	if (!slots) {
		g_message ("AttentionRequired: all slots auto-provided");
		return;
	}

	/* Stash the remainder so real_new_secrets can fulfil them. */
	clear_pending_slots (priv);
	priv->pending_slots = slots;

	/* Build a hint array for NM.  NM_VPN_PLUGIN_SECRET_HINT_X_VPN_MESSAGE
	 * (string "x-vpn-message:<text>") lets us pass a human description,
	 * the remaining entries are vpn-secrets keys NM should prompt for. */
	GPtrArray *hints = g_ptr_array_new_with_free_func (g_free);
	if (msg && *msg)
		g_ptr_array_add (hints, g_strdup_printf ("x-vpn-message:%s", msg));
	for (GSList *l = priv->pending_slots; l; l = l->next) {
		Ovpn3InputSlot *slot = l->data;
		g_ptr_array_add (hints, g_strdup (slot_name_to_vpn_key (slot)));
	}
	g_ptr_array_add (hints, NULL);

	const char *prompt = (msg && *msg) ? msg
	                                   : _("OpenVPN 3 needs authentication");
	nm_vpn_service_plugin_secrets_required (plugin,
	                                        prompt,
	                                        (const char **) hints->pdata);
	g_ptr_array_free (hints, TRUE);
}

/* Dispatch a (maj, min, msg) status triple to the right post-state action.
 * Invoked from BOTH the StatusChange D-Bus signal callback (fires within
 * milliseconds of the openvpn3 backend updating its state) and the polling
 * timer (slower but resilient if the signal subscription drops).  Idempotent
 * on the STARTED branch via priv->ip4_emitted; STOPPED triggers failure once. */
static void
status_handle_state (NMOpenvpn3Plugin *self,
                     guint32 maj,
                     guint32 min,
                     const gchar *msg)
{
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	NMVpnServicePlugin *plugin = (NMVpnServicePlugin *) self;

	int state = ovpn3_status_to_nm_state (maj, min);

	g_message ("status: maj=%u min=%u msg=%s -> nm_state=%d",
	             maj, min, msg ?: "", state);

	if (state == NM_VPN_SERVICE_STATE_STARTED) {
		emit_started_ip4_config (self);
		return;
	}

	if (state == NM_VPN_SERVICE_STATE_STOPPED) {
		nm_vpn_service_plugin_failure (plugin,
		                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		nm_clear_g_source (&priv->poll_timer_id);
	}
}

static void
status_change_signal_cb (guint32 maj, guint32 min, const gchar *msg, gpointer user_data)
{
	status_handle_state (NM_OPENVPN3_PLUGIN (user_data), maj, min, msg);
}

/* Tell NM the connect attempt failed, clear the poll timer id (the source
 * itself is dropped via G_SOURCE_REMOVE by the caller) and return
 * G_SOURCE_REMOVE so the calling timer callback can return it directly. */
static gboolean
poll_fail (NMOpenvpn3Plugin *self)
{
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	NMVpnServicePlugin *plugin = (NMVpnServicePlugin *) self;

	nm_vpn_service_plugin_failure (plugin,
	                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	priv->poll_timer_id = 0;
	return G_SOURCE_REMOVE;
}

static gboolean
poll_status_cb (gpointer user_data)
{
	NMOpenvpn3Plugin *self = NM_OPENVPN3_PLUGIN (user_data);
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);

	priv->poll_ticks++;

	if (!priv->session_path) {
		priv->poll_timer_id = 0;
		return G_SOURCE_REMOVE;
	}

	guint32 maj = 0, min = 0;
	g_autofree gchar *msg = NULL;
	g_autoptr (GError) e = NULL;
	if (!ovpn3_session_get_status (priv->ovpn3, priv->session_path,
	                               &maj, &min, &msg, &e)) {
		_LOGW ("status poll failed: %s", e ? e->message : "unknown");
		if (priv->ip4_emitted) {
			/* Session vanished externally (e.g. user ran `openvpn3
			 * session-manage --disconnect` behind NM's back).  Tell
			 * NM the tunnel is gone so it tears the connection down
			 * instead of showing ACTIVATED with a dead tun. */
			g_message ("session disappeared post-connect; failing to NM");
			return poll_fail (self);
		}
		if (priv->poll_ticks >= POLL_MAX_TICKS)
			return poll_fail (self);
		return G_SOURCE_CONTINUE;
	}

	status_handle_state (self, maj, min, msg);

	/* After STARTED the helper re-arms a 5 s watchdog and replaces
	 * poll_timer_id; this firing must drop out. */
	if (priv->ip4_emitted)
		return G_SOURCE_REMOVE;

	if (priv->poll_ticks >= POLL_MAX_TICKS) {
		_LOGW ("status poll timed out after %u ticks (last status %u/%u)",
		       priv->poll_ticks, maj, min);
		return poll_fail (self);
	}

	return G_SOURCE_CONTINUE;
}

/* Push UI-toggled SetOverride flags to the freshly imported config.
 * Each table entry maps a vpn.data key to an openvpn3 override name;
 * the override is sent only when the vpn.data key is present and
 * equals "yes" (matches the rest of the plugin's boolean convention).
 * Best-effort: per-override failures are logged, not propagated. */
static void
apply_config_overrides (Ovpn3Client *ovpn3,
                        const gchar *config_path,
                        NMConnection *connection)
{
	static const struct {
		const char *vpn_key;
		const char *ovpn3_name;
	} override_map[] = {
		{ NM_OPENVPN3_KEY_OVERRIDE_ROUTE_NOPULL,          "route-nopull" },
		{ NM_OPENVPN3_KEY_OVERRIDE_FORCE_DEFAULT_GATEWAY, "force-default-gateway" },
		{ NM_OPENVPN3_KEY_OVERRIDE_BLOCK_IPV6,            "block-ipv6" },
		{ NM_OPENVPN3_KEY_OVERRIDE_DNS_SETUP_DISABLED,    "dns-setup-disabled" },
		{ NM_OPENVPN3_KEY_OVERRIDE_DCO,                   "dco" },
	};
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);

	if (!s_vpn)
		return;

	for (gsize i = 0; i < G_N_ELEMENTS (override_map); i++) {
		const char *val = nm_setting_vpn_get_data_item (s_vpn,
		                                                override_map[i].vpn_key);
		if (!nm_streq0 (val, "yes"))
			continue;

		g_autoptr (GError) ov_err = NULL;
		if (!ovpn3_config_set_override_bool (ovpn3, config_path,
		                                     override_map[i].ovpn3_name,
		                                     TRUE, &ov_err)) {
			_LOGW ("SetOverride(%s) failed: %s",
			       override_map[i].ovpn3_name,
			       ov_err ? ov_err->message : "(unknown)");
		} else {
			g_message ("SetOverride(%s)=TRUE", override_map[i].ovpn3_name);
		}
	}

	/* String override: log-level.  openvpn3 stores log-level as a string
	 * variant in the configuration manager's `overrides` property (matches
	 * `openvpn3 config-manage --log-level N`), so the wire type is "s"
	 * even though the value is numeric.  Range is 1..6 per openvpn3 CLI;
	 * empty / "default" means leave the backend on its built-in default
	 * (currently 3 INFO).  Validate before dispatching to avoid stuffing
	 * arbitrary strings through. */
	{
		const char *log_str = nm_setting_vpn_get_data_item (
			s_vpn, NM_OPENVPN3_KEY_OVERRIDE_LOG_LEVEL);
		/* Treat "0" as unset — v0.5.14 briefly exposed it as a UI option
		 * before the openvpn3 CLI documentation made clear the valid
		 * range is 1..6.  Skipping it silently keeps old connections
		 * usable until the user re-saves through the editor. */
		if (log_str && *log_str && g_strcmp0 (log_str, "0") != 0) {
			gint64 v = _nm_utils_ascii_str_to_int64 (log_str, 10, 1, 6, -1);
			if (v >= 1) {
				g_autoptr (GError) ov_err = NULL;
				if (!ovpn3_config_set_override_string (ovpn3, config_path,
				                                       "log-level",
				                                       log_str, &ov_err)) {
					_LOGW ("SetOverride(log-level=%s) failed: %s",
					       log_str,
					       ov_err ? ov_err->message : "(unknown)");
				} else {
					_LOGI ("SetOverride(log-level=%s) ok", log_str);
				}
			} else {
				_LOGW ("invalid log-level override '%s' (must be 1..6)",
				       log_str);
			}
		}
	}
}

/* Scan /run/user for the lowest non-zero uid (systemd marks active user
 * sessions with these directories), and grant it sessions-list access.
 * Called when the NM connection has no explicit user:NAME permission —
 * service runs as root, so XDG_RUNTIME_DIR points at /run/user/0 and
 * doesn't help us guess who triggered the NM activation. */
static void
grant_access_run_user_fallback (Ovpn3Client *ovpn3, const gchar *session_path)
{
	GDir *d = g_dir_open ("/run/user", 0, NULL);
	const gchar *name;
	guint32 best_uid = 0;

	if (!d)
		return;

	while ((name = g_dir_read_name (d)) != NULL) {
		gchar *endptr = NULL;
		guint64 v = g_ascii_strtoull (name, &endptr, 10);
		if (!endptr || *endptr != '\0' || v == 0 || v > G_MAXUINT32)
			continue;
		if (best_uid == 0 || v < best_uid)
			best_uid = (guint32) v;
	}
	g_dir_close (d);

	if (best_uid == 0) {
		g_message ("AccessGrant fallback: no non-root uid in /run/user");
		return;
	}

	g_autoptr (GError) ag_err = NULL;
	if (!ovpn3_session_access_grant (ovpn3, session_path, best_uid, &ag_err)) {
		g_message ("AccessGrant fallback uid=%u failed: %s",
		             best_uid, ag_err ? ag_err->message : "(unknown)");
	} else {
		g_message ("AccessGrant fallback uid=%u (/run/user scan) ok", best_uid);
	}
}

/* Our service runs as root; without explicit ACL entries, every other
 * UID (incl. the user who triggered the NM activation) gets a blank
 * `openvpn3 sessions-list` view.  public_access=TRUE authorises the
 * management methods (Connect/Disconnect/Pause/…); AccessGrant adds
 * a UID to the per-property ACL so `sessions-list` can read status,
 * device, owner, etc.  Best-effort on both calls — a failure here is
 * a usability regression, not a connectivity blocker. */
static void
grant_access_for_connection (Ovpn3Client *ovpn3,
                             const gchar *session_path,
                             NMConnection *connection)
{
	g_autoptr (GError) pa_err = NULL;
	if (!ovpn3_session_set_public_access (ovpn3, session_path, TRUE, &pa_err)) {
		g_message ("set public_access=TRUE failed: %s",
		             pa_err ? pa_err->message : "(unknown)");
	}

	NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
	guint n_perms = s_con ? nm_setting_connection_get_num_permissions (s_con) : 0;
	gboolean granted_any = FALSE;

	for (guint i = 0; i < n_perms; i++) {
		const char *ptype = NULL;
		const char *pitem = NULL;
		if (!nm_setting_connection_get_permission (s_con, i, &ptype, &pitem, NULL))
			continue;
		if (g_strcmp0 (ptype, "user") != 0 || !pitem)
			continue;

		struct passwd *pw = getpwnam (pitem);
		if (!pw) {
			g_message ("AccessGrant: getpwnam(%s) failed", pitem);
			continue;
		}

		g_autoptr (GError) ag_err = NULL;
		if (!ovpn3_session_access_grant (ovpn3, session_path,
		                                 (guint32) pw->pw_uid, &ag_err)) {
			g_message ("AccessGrant uid=%u (%s) failed: %s",
			             (guint) pw->pw_uid, pitem,
			             ag_err ? ag_err->message : "(unknown)");
		} else {
			granted_any = TRUE;
			g_message ("AccessGrant uid=%u (%s) ok",
			             (guint) pw->pw_uid, pitem);
		}
	}

	if (!granted_any)
		grant_access_run_user_fallback (ovpn3, session_path);
}

static gboolean
real_connect (NMVpnServicePlugin *plugin,
              NMConnection       *connection,
              GError            **error)
{
	NMOpenvpn3Plugin *self = NM_OPENVPN3_PLUGIN (plugin);
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	g_autofree gchar *profile = NULL;
	const gchar *id;

	/* Keep a reference to the connection so the AttentionRequired callback
	 * can auto-provide username / saved secrets. */
	g_clear_object (&priv->current_connection);
	priv->current_connection = g_object_ref (connection);

	if (!priv->ovpn3) {
		priv->ovpn3 = ovpn3_client_new (error);
		if (!priv->ovpn3)
			return FALSE;
	}

	profile = build_profile_string (connection, error);
	if (!profile)
		return FALSE;

	id = nm_connection_get_id (connection) ?: "nm-openvpn3";
	priv->config_path = ovpn3_import_config (priv->ovpn3, id, profile, TRUE, error);
	if (!priv->config_path)
		return FALSE;

	apply_config_overrides (priv->ovpn3, priv->config_path, connection);

	priv->session_path = ovpn3_new_tunnel (priv->ovpn3, priv->config_path, error);
	if (!priv->session_path)
		return FALSE;

	if (!ovpn3_session_wait_ready (priv->ovpn3, priv->session_path, 5000, error))
		return FALSE;

	/* Subscribe to the session's StatusChange signal so we react to state
	 * transitions (in particular CONNECTED → STARTED) within milliseconds
	 * instead of having to wait up to one poll interval.  The polling timer
	 * armed below stays as a fallback for the case where the signal
	 * subscription drops or never delivers. */
	{
		g_autoptr (GError) sub_err = NULL;
		priv->status_sub_id = ovpn3_session_subscribe_status (
			priv->ovpn3, priv->session_path,
			status_change_signal_cb, self, &sub_err);
		if (!priv->status_sub_id) {
			g_message ("StatusChange subscribe failed: %s",
			             sub_err ? sub_err->message : "(unknown)");
		} else {
			g_message ("StatusChange subscribed sub_id=%u", priv->status_sub_id);
		}
	}

	/* Subscribe to AttentionRequired so password / 2FA prompts trigger an
	 * NM inline auth dialog via real_new_secrets.  Best-effort: a failure
	 * here only breaks interactive auth, the rest of the flow continues. */
	{
		g_autoptr (GError) sub_err = NULL;
		priv->attention_sub_id = ovpn3_session_subscribe_attention (
			priv->ovpn3, priv->session_path,
			attention_required_cb, self, &sub_err);
		if (!priv->attention_sub_id) {
			g_message ("AttentionRequired subscribe failed: %s",
			             sub_err ? sub_err->message : "(unknown)");
		} else {
			g_message ("AttentionRequired subscribed sub_id=%u",
			             priv->attention_sub_id);
		}
	}

	grant_access_for_connection (priv->ovpn3, priv->session_path, connection);

	if (!ovpn3_session_connect (priv->ovpn3, priv->session_path, error))
		return FALSE;

	priv->poll_ticks = 0;
	priv->poll_timer_id = g_timeout_add (POLL_INTERVAL_MS, poll_status_cb, self);
	priv->wait_state = -1;
	return TRUE;
}

static gboolean
real_connect_interactive (NMVpnServicePlugin *plugin,
                          NMConnection       *connection,
                          GVariant           *details,
                          GError            **error)
{
	(void) details;
	return real_connect (plugin, connection, error);
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	const char *connection_type;
	gboolean need_secrets = FALSE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	/* nm_connection_dump prints to stdout regardless of any log filter,
	 * so gate it on the --debug flag specifically (independent of
	 * G_MESSAGES_DEBUG).  Otherwise every connect would dump the whole
	 * connection (and its secrets) to the journal. */
	if (gl.debug) {
		_LOGD ("connection -------------------------------------");
		nm_connection_dump (connection);
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	connection_type = check_need_secrets (s_vpn, &need_secrets);
	if (!connection_type) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Invalid connection type."));
		return FALSE;
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

	return need_secrets;
}

static gboolean
real_new_secrets (NMVpnServicePlugin *base_plugin,
                  NMConnection *connection,
                  GError **error)
{
	NMOpenvpn3Plugin *self = NM_OPENVPN3_PLUGIN (base_plugin);
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);

	if (!s_vpn) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	if (!priv->pending_slots) {
		/* Nothing was queued by AttentionRequired — NM may have called
		 * us speculatively after a connect retry.  Nothing to do. */
		g_message ("new_secrets: no pending slots, nop");
		return TRUE;
	}

	/* Refresh our connection ref so future AttentionRequired bursts pick
	 * up any newly-persisted credentials. */
	g_clear_object (&priv->current_connection);
	priv->current_connection = g_object_ref (connection);

	guint sent = 0, missing = 0;
	for (GSList *l = priv->pending_slots; l; l = l->next) {
		Ovpn3InputSlot *slot = l->data;
		const char *vkey = slot_name_to_vpn_key (slot);
		const char *value = slot_value_from_s_vpn (s_vpn, vkey);

		if (!value || !*value) {
			g_message ("new_secrets: slot '%s' has no value in vpn.secrets[%s]",
			             slot->name, vkey);
			missing++;
			continue;
		}

		g_autoptr (GError) pe = NULL;
		if (ovpn3_session_provide_input (priv->ovpn3, priv->session_path,
		                                 slot->type, slot->group, slot->id,
		                                 value, &pe)) {
			g_message ("ProvideInput(%s) ok", slot->name);
			sent++;
		} else {
			_LOGW ("ProvideInput(%s) failed: %s",
			       slot->name, pe ? pe->message : "(unknown)");
			missing++;
		}
	}

	clear_pending_slots (priv);

	if (missing > 0) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("Could not provide %u authentication slot(s)."),
		             missing);
		return FALSE;
	}

	g_message ("new_secrets: provided %u slots", sent);
	return TRUE;
}

static void
nm_openvpn3_plugin_init (NMOpenvpn3Plugin *plugin)
{
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (plugin);

	priv->ovpn3         = NULL;
	priv->session_path  = NULL;
	priv->config_path   = NULL;
	priv->status_sub_id = 0;
	priv->wait_loop     = NULL;
	priv->wait_state    = -1;
}

static void
dispose (GObject *object)
{
	NMOpenvpn3PluginPrivate *priv = NM_OPENVPN3_PLUGIN_GET_PRIVATE (object);

	/* Clean up ovpn3 session state */
	clear_signal_sub (priv->ovpn3, &priv->status_sub_id);
	clear_signal_sub (priv->ovpn3, &priv->attention_sub_id);
	nm_clear_g_source (&priv->stats_timer_id);
	clear_pending_slots (priv);
	g_clear_object (&priv->current_connection);
	g_clear_pointer (&priv->session_path, g_free);
	g_clear_pointer (&priv->config_path, g_free);
	if (priv->ovpn3) {
		ovpn3_client_free (priv->ovpn3);
		priv->ovpn3 = NULL;
	}
	if (priv->wait_loop) {
		if (g_main_loop_is_running (priv->wait_loop))
			g_main_loop_quit (priv->wait_loop);
		g_clear_pointer (&priv->wait_loop, g_main_loop_unref);
	}

	G_OBJECT_CLASS (nm_openvpn3_plugin_parent_class)->dispose (object);
}

static void
nm_openvpn3_plugin_class_init (NMOpenvpn3PluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMOpenvpn3PluginPrivate));

	object_class->dispose = dispose;

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->connect_interactive = real_connect_interactive;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
	parent_class->new_secrets  = real_new_secrets;
}

static void
plugin_state_changed (NMOpenvpn3Plugin *plugin,
                      NMVpnServiceState state,
                      gpointer user_data)
{
	(void) plugin;
	(void) state;
	(void) user_data;
}

NMOpenvpn3Plugin *
nm_openvpn3_plugin_new (const char *bus_name)
{
	NMOpenvpn3Plugin *plugin;
	GError *error = NULL;

	plugin =  (NMOpenvpn3Plugin *) g_initable_new (NM_TYPE_OPENVPN3_PLUGIN, NULL, &error,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                                              NULL);

	if (plugin) {
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (plugin_state_changed), NULL);
	} else {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

	return plugin;
}

static gboolean
signal_handler (gpointer user_data)
{
	g_main_loop_quit (user_data);
	return G_SOURCE_CONTINUE;
}

static void
quit_mainloop (NMVpnServicePlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	gs_unref_object NMOpenvpn3Plugin *plugin = NULL;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	gchar *bus_name = NM_DBUS_SERVICE_OPENVPN3;
	GError *error = NULL;
	GMainLoop *loop;
	guint source_id_sigterm;
	guint source_id_sigint;
	gulong handler_id_plugin = 0;
	guint i;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don’t quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (getenv ("OPENVPN_DEBUG"))
		gl.debug = TRUE;

	gl.tmp_file_paths = g_ptr_array_new_with_free_func(g_free);

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_OPENVPN3_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              _("nm-openvpn3-service provides integrated "
	                                "OpenVPN capability to NetworkManager."));

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing the command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_clear_error (&error);
		return EXIT_FAILURE;
	}
	g_option_context_free (opt_ctx);

	/* --debug raises everything we emit through the GLib logger to DEBUG
	 * level by routing the "all" tag into G_MESSAGES_DEBUG, which the
	 * default handler then echoes for our domain. */
	if (gl.debug && !g_getenv ("G_MESSAGES_DEBUG"))
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);

	_LOGI ("nm-openvpn3-service (version " DIST_VERSION ") starting...");

	if (   !g_file_test ("/sys/class/misc/tun", G_FILE_TEST_EXISTS)
	    && (system ("/sbin/modprobe tun") == -1))
		return EXIT_FAILURE;

	plugin = nm_openvpn3_plugin_new (bus_name);
	if (!plugin)
		return EXIT_FAILURE;

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		handler_id_plugin = g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	signal (SIGPIPE, SIG_IGN);
	source_id_sigterm = g_unix_signal_add (SIGTERM, signal_handler, loop);
	source_id_sigint = g_unix_signal_add (SIGINT, signal_handler, loop);

	g_main_loop_run (loop);

	nm_clear_g_source (&source_id_sigterm);
	nm_clear_g_source (&source_id_sigint);
	nm_clear_g_signal_handler (plugin, &handler_id_plugin);

	g_clear_object (&plugin);

	for (i = 0; i < gl.tmp_file_paths->len; i++) {
		unlink ((const char *) gl.tmp_file_paths->pdata[i]);
	}
	g_ptr_array_unref (gl.tmp_file_paths);

	g_main_loop_unref (loop);
	return EXIT_SUCCESS;
}
