#ifndef __OVPN3_CLIENT_H__
#define __OVPN3_CLIENT_H__

#include <gio/gio.h>

/* Direct-to-file trace logger writing /tmp/nm-openvpn3-trace.log.
 * Public so the service body can sprinkle trace points too. */
void ovpn3_trace (const char *fmt, ...) G_GNUC_PRINTF (1, 2);

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

typedef void (*Ovpn3StatusChangeCb) (guint32      code_major,
                                     guint32      code_minor,
                                     const gchar *message,
                                     gpointer     user_data);

/* Poll session.Ready until the backend is registered or @timeout_ms elapses.
 * NewTunnel returns a session path before the backend client is fully
 * registered on the bus; calling Connect immediately races against that
 * registration and yields UnknownMethod. */
gboolean ovpn3_session_wait_ready (Ovpn3Client *self,
                                   const gchar *session_path,
                                   guint        timeout_ms,
                                   GError     **error);

/* Synchronously call session.Connect on @session_path. */
gboolean ovpn3_session_connect (Ovpn3Client *self,
                                const gchar *session_path,
                                GError     **error);

/* Synchronously call session.Disconnect. */
gboolean ovpn3_session_disconnect (Ovpn3Client *self,
                                   const gchar *session_path,
                                   GError     **error);

/* Subscribe to the StatusChange signal on @session_path.  Returns a subscription
 * id; pass to ovpn3_session_unsubscribe.  @cb runs on the same main context
 * that was current when this function was called. */
guint ovpn3_session_subscribe_status (Ovpn3Client         *self,
                                      const gchar         *session_path,
                                      Ovpn3StatusChangeCb  cb,
                                      gpointer             user_data,
                                      GError             **error);

void ovpn3_session_unsubscribe (Ovpn3Client *self,
                                guint        subscription_id);

/* Read the device_name property of @session_path (e.g. "tun0"). */
gchar *ovpn3_session_get_device_name (Ovpn3Client *self,
                                      const gchar *session_path,
                                      GError     **error);

/* Read the status property of @session_path.  The property is a (uus)
 * tuple of (major, minor, message).  Both out-params may be NULL.
 * Returns FALSE on error. */
gboolean ovpn3_session_get_status (Ovpn3Client *self,
                                   const gchar *session_path,
                                   guint32     *out_major,
                                   guint32     *out_minor,
                                   gchar      **out_message,
                                   GError     **error);

#endif
