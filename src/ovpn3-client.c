#include "ovpn3-client.h"

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
