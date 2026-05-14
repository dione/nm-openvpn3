#ifndef __OVPN3_CLIENT_H__
#define __OVPN3_CLIENT_H__

#include <gio/gio.h>

#define OVPN3_BUS_CONFIG   "net.openvpn.v3.configuration"
#define OVPN3_BUS_SESSIONS "net.openvpn.v3.sessions"
#define OVPN3_PATH_CONFIG   "/net/openvpn/v3/configuration"
#define OVPN3_PATH_SESSIONS "/net/openvpn/v3/sessions"
#define OVPN3_IFACE_CONFIG   "net.openvpn.v3.configuration"
#define OVPN3_IFACE_SESSIONS "net.openvpn.v3.sessions"

typedef struct _Ovpn3Client Ovpn3Client;

/* Synchronously connect to the system bus and cache configuration/session manager
 * proxies. */
Ovpn3Client *ovpn3_client_new (GError **error);
void         ovpn3_client_free (Ovpn3Client *self);

/* Import @ovpn_profile (the textual content of an .ovpn file) under @name.
 * @single_use means the configuration is auto-deleted after the session ends.
 * Returns a heap-allocated D-Bus object path; caller frees with g_free. */
gchar *ovpn3_import_config (Ovpn3Client *self,
                            const gchar *name,
                            const gchar *ovpn_profile,
                            gboolean     single_use,
                            GError     **error);

/* Allocate a new tunnel for the given @config_path.  Returns the session's
 * D-Bus object path; caller frees with g_free. */
gchar *ovpn3_new_tunnel (Ovpn3Client *self,
                         const gchar *config_path,
                         GError     **error);

#endif
