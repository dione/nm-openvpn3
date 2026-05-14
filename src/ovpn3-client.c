#include "ovpn3-client.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void
ovpn3_trace (const char *fmt, ...)
{
	static FILE *f = NULL;
	if (!f) {
		f = fopen ("/tmp/nm-openvpn3-trace.log", "a");
		if (!f) return;
	}
	struct timespec ts;
	clock_gettime (CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r (&ts.tv_sec, &tm);
	char tbuf[32];
	strftime (tbuf, sizeof (tbuf), "%H:%M:%S", &tm);
	fprintf (f, "%s.%03ld [%d] ", tbuf, ts.tv_nsec / 1000000, (int) getpid ());
	va_list ap;
	va_start (ap, fmt);
	vfprintf (f, fmt, ap);
	va_end (ap);
	fputc ('\n', f);
	fflush (f);
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

	ovpn3_trace ("client_new: ovpn3 client bus unique name = %s",
	             g_dbus_connection_get_unique_name (self->bus));
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

	g_autoptr (GVariant) result = g_dbus_proxy_call_sync (
		self->config_proxy,
		"Import",
		g_variant_new ("(ssbb)", name, ovpn_profile, single_use, FALSE),
		G_DBUS_CALL_FLAGS_NONE,
		-1, NULL, error);
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

	g_autoptr (GVariant) result = g_dbus_proxy_call_sync (
		self->sessions_proxy,
		"NewTunnel",
		g_variant_new ("(o)", config_path),
		G_DBUS_CALL_FLAGS_NONE,
		-1, NULL, error);
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

	/* Skip noise — only log openvpn-related signals. */
	const gboolean is_openvpn =
		(iface && strstr (iface, "openvpn") != NULL) ||
		(path  && strstr (path,  "openvpn") != NULL);
	if (!is_openvpn)
		return;

	ovpn3_trace ("signal arrived: sender=%s path=%s iface=%s signal=%s sig=%s",
	             sender, path, iface, signal_name,
	             g_variant_get_type_string (parameters));
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

	/* Subscribe broad — every signal on ANY interface, any path, any sender.
	 * We don't yet know where openvpn3 actually emits status updates;
	 * trace logs will show that. */
	guint sub = g_dbus_connection_signal_subscribe (
		self->bus,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		G_DBUS_SIGNAL_FLAGS_NONE,
		status_signal_cb, d, g_free);
	ovpn3_trace ("subscribed broad sub_id=%u session_path=%s",
	             sub, session_path);
	return sub;
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
