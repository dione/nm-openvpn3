#include "ovpn3-client.h"

#include <stdarg.h>
#include <string.h>

/* Forward openvpn3-client diagnostics through GLib's logging into the same
 * journal stream that NetworkManager uses for our service.  MESSAGE level
 * is always shown by GLib's default handler (INFO/DEBUG are suppressed
 * unless G_MESSAGES_DEBUG is set), and NM captures our stderr into
 * journald under the nm-openvpn3-service syslog ident. */
void
ovpn3_trace (const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	g_logv ("nm-openvpn3", G_LOG_LEVEL_MESSAGE, fmt, ap);
	va_end (ap);
}

struct _Ovpn3Client {
	GDBusConnection *bus;
	GDBusProxy      *config_proxy;
	GDBusProxy      *sessions_proxy;
};

Ovpn3Client *
ovpn3_client_new (GError **error)
{
	g_autoptr (GDBusConnection) bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, error);
	if (!bus)
		return NULL;

	g_autoptr (GDBusProxy) cfg = g_dbus_proxy_new_sync (
		bus, G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		NULL, OVPN3_BUS_CONFIG, OVPN3_PATH_CONFIG,
		OVPN3_IFACE_CONFIG, NULL, error);
	if (!cfg)
		return NULL;

	g_autoptr (GDBusProxy) ses = g_dbus_proxy_new_sync (
		bus, G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		NULL, OVPN3_BUS_SESSIONS, OVPN3_PATH_SESSIONS,
		OVPN3_IFACE_SESSIONS, NULL, error);
	if (!ses)
		return NULL;

	Ovpn3Client *self = g_new0 (Ovpn3Client, 1);
	self->bus            = g_steal_pointer (&bus);
	self->config_proxy   = g_steal_pointer (&cfg);
	self->sessions_proxy = g_steal_pointer (&ses);
	return self;
}

void
ovpn3_client_free (Ovpn3Client *self)
{
	if (!self)
		return;
	g_clear_object (&self->sessions_proxy);
	g_clear_object (&self->config_proxy);
	g_clear_object (&self->bus);
	g_free (self);
}

/* Wrap a GDBusProxy.<method> call with retry on transient bus errors.
 * openvpn3's configuration / sessions managers are D-Bus auto-activated
 * services; the first call after a `systemctl reload dbus` or after the
 * daemons exited idle can race the bus daemon's activation step and
 * surface as ServiceUnknown / NoReply / Timeout.  Retry up to @attempts
 * with a small backoff and propagate the LAST error if all attempts
 * fail.  Returns the floating GVariant result on success (or NULL). */
static GVariant *
dbus_call_with_retry (GDBusProxy  *proxy,
                      const gchar *method,
                      GVariant    *params,
                      guint        attempts,
                      guint        backoff_ms,
                      GError     **error)
{
	g_return_val_if_fail (proxy != NULL, NULL);
	g_return_val_if_fail (method != NULL, NULL);

	/* Take ownership of the (typically floating) caller-supplied params so
	 * we can re-pass them to each retry attempt.  g_dbus_proxy_call_sync
	 * consumes one floating-or-full ref per call, so we hand it an extra
	 * ref each attempt and unref our own at the end. */
	g_variant_ref_sink (params);

	GError *local = NULL;
	for (guint i = 0; i < attempts; i++) {
		g_clear_error (&local);
		GVariant *r = g_dbus_proxy_call_sync (proxy, method,
		                                       g_variant_ref (params),
		                                       G_DBUS_CALL_FLAGS_NONE,
		                                       -1, NULL, &local);
		if (r) {
			g_variant_unref (params);
			return r;
		}
		if (!g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN) &&
		    !g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY) &&
		    !g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_TIMEOUT) &&
		    !g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_CHILD_EXITED) &&
		    !g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_DISCONNECTED)) {
			break;   /* non-transient; surface immediately */
		}
		if (i + 1 < attempts) {
			ovpn3_trace ("dbus_call_with_retry: %s attempt %u failed (%s); retrying in %u ms",
			             method, i + 1, local->message, backoff_ms);
			g_usleep (backoff_ms * 1000);
		}
	}
	g_variant_unref (params);
	if (local)
		g_propagate_error (error, local);
	return NULL;
}

gchar *
ovpn3_import_config (Ovpn3Client *self,
                     const gchar *name,
                     const gchar *ovpn_profile,
                     gboolean     single_use,
                     GError     **error)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (ovpn_profile != NULL, NULL);

	GVariant *params = g_variant_new ("(ssbb)", name, ovpn_profile, single_use, FALSE);
	g_autoptr (GVariant) result = dbus_call_with_retry (self->config_proxy,
	                                                    "Import", params,
	                                                    3, 200, error);
	if (!result)
		return NULL;

	const gchar *path = NULL;
	g_variant_get (result, "(&o)", &path);
	return g_strdup (path);
}

gchar *
ovpn3_new_tunnel (Ovpn3Client *self,
                  const gchar *config_path,
                  GError     **error)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (config_path != NULL, NULL);

	GVariant *params = g_variant_new ("(o)", config_path);
	g_autoptr (GVariant) result = dbus_call_with_retry (self->sessions_proxy,
	                                                    "NewTunnel", params,
	                                                    3, 200, error);
	if (!result)
		return NULL;

	const gchar *path = NULL;
	g_variant_get (result, "(&o)", &path);
	return g_strdup (path);
}

static GDBusProxy *
session_proxy (Ovpn3Client *self, const gchar *session_path, GError **error)
{
	return g_dbus_proxy_new_sync (
		self->bus,
		G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		NULL, OVPN3_BUS_SESSIONS, session_path,
		OVPN3_IFACE_SESSIONS, NULL, error);
}

gboolean
ovpn3_session_wait_ready (Ovpn3Client *self,
                          const gchar *session_path,
                          guint        timeout_ms,
                          GError     **error)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (session_path != NULL, FALSE);

	const guint sleep_ms = 100;
	guint waited = 0;
	gchar *last_msg = NULL;
	while (waited <= timeout_ms) {
		GError *local = NULL;
		GDBusProxy *p = session_proxy (self, session_path, &local);
		if (p) {
			GVariant *r = g_dbus_proxy_call_sync (
				p, "Ready", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &local);
			if (r) {
				g_variant_unref (r);
				g_object_unref (p);
				g_free (last_msg);
				return TRUE;
			}
			g_object_unref (p);
		}
		/* Capture the most recent error message before retrying. */
		if (local) {
			g_free (last_msg);
			last_msg = g_strdup (local->message);
			/* If Ready raises a non-transient error (object actually does
			 * not exist any more, access denied, etc.), give up early. */
			if (g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED) ||
			    g_error_matches (local, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY)) {
				g_propagate_error (error, local);
				g_free (last_msg);
				return FALSE;
			}
			g_error_free (local);
		}
		g_usleep (sleep_ms * 1000);
		waited += sleep_ms;
	}
	g_set_error (error,
	             G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
	             "openvpn3 session.Ready timed out after %u ms; last error: %s",
	             timeout_ms,
	             last_msg ? last_msg : "(none)");
	g_free (last_msg);
	return FALSE;
}

gboolean
ovpn3_session_connect (Ovpn3Client *self,
                       const gchar *session_path,
                       GError     **error)
{
	g_autoptr (GDBusProxy) p = session_proxy (self, session_path, error);
	if (!p) return FALSE;
	g_autoptr (GVariant) r = g_dbus_proxy_call_sync (
		p, "Connect", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	return r != NULL;
}

gboolean
ovpn3_session_disconnect (Ovpn3Client *self,
                          const gchar *session_path,
                          GError     **error)
{
	g_autoptr (GDBusProxy) p = session_proxy (self, session_path, error);
	if (!p) return FALSE;
	g_autoptr (GVariant) r = g_dbus_proxy_call_sync (
		p, "Disconnect", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	return r != NULL;
}

typedef struct {
	Ovpn3StatusChangeCb cb;
	gpointer            user_data;
} StatusSubData;

static void
status_signal_cb (GDBusConnection *conn,
                  const gchar     *sender,
                  const gchar     *path,
                  const gchar     *iface,
                  const gchar     *signal_name,
                  GVariant        *parameters,
                  gpointer         user_data)
{
	StatusSubData *d = user_data;
	guint32 maj = 0, min = 0;
	const gchar *msg = NULL;

	(void) sender;
	(void) path;
	(void) iface;
	if (g_strcmp0 (signal_name, "StatusChange") != 0)
		return;
	g_variant_get (parameters, "(uu&s)", &maj, &min, &msg);
	d->cb (maj, min, msg, d->user_data);
}

guint
ovpn3_session_subscribe_status (Ovpn3Client         *self,
                                const gchar         *session_path,
                                Ovpn3StatusChangeCb  cb,
                                gpointer             user_data,
                                GError             **error)
{
	(void) error;
	StatusSubData *d = g_new0 (StatusSubData, 1);
	d->cb        = cb;
	d->user_data = user_data;

	/* Filter to net.openvpn.v3.sessions StatusChange on this session's
	 * object path.  sender stays NULL because openvpn3 emits signals from
	 * the backend client's unique bus name, not the well-known service
	 * name; path + interface + member are enough to scope the match.
	 *
	 * NOTE: Plan 1c switched the service to polling session.status because
	 * openvpn3 unicasts StatusChange to long-running subscribers and our
	 * auto-spawned service never receives them.  This entry point is kept
	 * for future use (e.g. Plan 2 AttentionRequired). */
	return g_dbus_connection_signal_subscribe (
		self->bus,
		NULL,
		OVPN3_IFACE_SESSIONS,
		"StatusChange",
		session_path,
		NULL,
		G_DBUS_SIGNAL_FLAGS_NONE,
		status_signal_cb, d, g_free);
}

void
ovpn3_session_unsubscribe (Ovpn3Client *self, guint subscription_id)
{
	g_dbus_connection_signal_unsubscribe (self->bus, subscription_id);
}

gchar *
ovpn3_session_get_device_name (Ovpn3Client *self,
                               const gchar *session_path,
                               GError     **error)
{
	g_autoptr (GVariant) v = g_dbus_connection_call_sync (
		self->bus, OVPN3_BUS_SESSIONS, session_path,
		"org.freedesktop.DBus.Properties", "Get",
		g_variant_new ("(ss)", OVPN3_IFACE_SESSIONS, "device_name"),
		G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	if (!v) return NULL;
	g_autoptr (GVariant) inner = NULL;
	g_variant_get (v, "(v)", &inner);
	const gchar *s = NULL;
	g_variant_get (inner, "&s", &s);
	return g_strdup (s);
}

gchar *
ovpn3_session_get_device_path (Ovpn3Client *self,
                               const gchar *session_path,
                               GError     **error)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (session_path != NULL, NULL);

	g_autoptr (GVariant) v = g_dbus_connection_call_sync (
		self->bus, OVPN3_BUS_SESSIONS, session_path,
		"org.freedesktop.DBus.Properties", "Get",
		g_variant_new ("(ss)", OVPN3_IFACE_SESSIONS, "device_path"),
		G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	if (!v)
		return NULL;
	g_autoptr (GVariant) inner = NULL;
	g_variant_get (v, "(v)", &inner);
	const gchar *s = NULL;
	g_variant_get (inner, "&o", &s);
	return g_strdup (s);
}

#define OVPN3_BUS_NETCFG   "net.openvpn.v3.netcfg"
#define OVPN3_IFACE_NETCFG "net.openvpn.v3.netcfg"

static gchar **
netcfg_read_as_property (Ovpn3Client *self,
                         const gchar *device_path,
                         const gchar *prop_name,
                         GError     **error)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (device_path != NULL, NULL);
	g_return_val_if_fail (prop_name != NULL, NULL);

	g_autoptr (GVariant) v = g_dbus_connection_call_sync (
		self->bus, OVPN3_BUS_NETCFG, device_path,
		"org.freedesktop.DBus.Properties", "Get",
		g_variant_new ("(ss)", OVPN3_IFACE_NETCFG, prop_name),
		G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	if (!v)
		return NULL;
	g_autoptr (GVariant) inner = NULL;
	g_variant_get (v, "(v)", &inner);
	GVariantIter it;
	g_variant_iter_init (&it, inner);
	const gchar *unowned = NULL;
	GPtrArray *arr = g_ptr_array_new ();
	while (g_variant_iter_next (&it, "&s", &unowned))
		g_ptr_array_add (arr, g_strdup (unowned));
	g_ptr_array_add (arr, NULL);
	return (gchar **) g_ptr_array_free (arr, FALSE);
}

gchar **
ovpn3_netcfg_get_dns_servers (Ovpn3Client *self,
                              const gchar *device_path,
                              GError     **error)
{
	return netcfg_read_as_property (self, device_path, "dns_name_servers", error);
}

gchar **
ovpn3_netcfg_get_dns_search (Ovpn3Client *self,
                             const gchar *device_path,
                             GError     **error)
{
	return netcfg_read_as_property (self, device_path, "dns_search_domains", error);
}

gboolean
ovpn3_session_get_connected_to (Ovpn3Client *self,
                                const gchar *session_path,
                                gchar      **out_proto,
                                gchar      **out_host,
                                guint32     *out_port,
                                GError     **error)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (session_path != NULL, FALSE);

	g_autoptr (GVariant) v = g_dbus_connection_call_sync (
		self->bus, OVPN3_BUS_SESSIONS, session_path,
		"org.freedesktop.DBus.Properties", "Get",
		g_variant_new ("(ss)", OVPN3_IFACE_SESSIONS, "connected_to"),
		G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	if (!v)
		return FALSE;
	g_autoptr (GVariant) inner = NULL;
	g_variant_get (v, "(v)", &inner);
	const gchar *proto = NULL, *host = NULL;
	guint32 port = 0;
	g_variant_get (inner, "(&s&su)", &proto, &host, &port);
	if (out_proto) *out_proto = g_strdup (proto);
	if (out_host) *out_host = g_strdup (host);
	if (out_port) *out_port = port;
	return TRUE;
}

gboolean
ovpn3_session_get_status (Ovpn3Client *self,
                          const gchar *session_path,
                          guint32     *out_major,
                          guint32     *out_minor,
                          gchar      **out_message,
                          GError     **error)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (session_path != NULL, FALSE);

	g_autoptr (GVariant) v = g_dbus_connection_call_sync (
		self->bus, OVPN3_BUS_SESSIONS, session_path,
		"org.freedesktop.DBus.Properties", "Get",
		g_variant_new ("(ss)", OVPN3_IFACE_SESSIONS, "status"),
		G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);
	if (!v)
		return FALSE;
	g_autoptr (GVariant) inner = NULL;
	g_variant_get (v, "(v)", &inner);
	guint32 maj = 0, min = 0;
	const gchar *msg = NULL;
	g_variant_get (inner, "(uu&s)", &maj, &min, &msg);
	if (out_major) *out_major = maj;
	if (out_minor) *out_minor = min;
	if (out_message) *out_message = g_strdup (msg);
	return TRUE;
}
