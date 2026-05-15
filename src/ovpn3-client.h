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

/* User-input slot fetched from the session's UserInputQueue.  openvpn3
 * identifies prompts by (type, group, id) tuples; @name and @description
 * are display strings; @hidden_input=TRUE means the value should be masked
 * (passwords).  Caller frees with ovpn3_input_slot_free(). */
typedef struct {
	guint32   type;
	guint32   group;
	guint32   id;
	gchar    *name;
	gchar    *description;
	gboolean  hidden_input;
} Ovpn3InputSlot;

void ovpn3_input_slot_free (Ovpn3InputSlot *slot);

typedef void (*Ovpn3AttentionRequiredCb) (guint32      type,
                                          guint32      group,
                                          const gchar *message,
                                          gpointer     user_data);

/* Subscribe to AttentionRequired signal on @session_path.  Returns
 * subscription id (pass to ovpn3_session_unsubscribe). */
guint ovpn3_session_subscribe_attention (Ovpn3Client              *self,
                                         const gchar              *session_path,
                                         Ovpn3AttentionRequiredCb  cb,
                                         gpointer                  user_data,
                                         GError                  **error);

/* Enumerate all pending input slots on @session_path.  Walks
 * UserInputQueueGetTypeGroup → UserInputQueueCheck → UserInputQueueFetch.
 * Returns a GSList of Ovpn3InputSlot* (free with
 * g_slist_free_full(slist, (GDestroyNotify) ovpn3_input_slot_free)) or
 * NULL if the queue is empty (which is a valid state, not an error). */
GSList *ovpn3_session_fetch_input_slots (Ovpn3Client *self,
                                         const gchar *session_path,
                                         GError     **error);

/* Push a value into a specific (type, group, id) slot via UserInputProvide. */
gboolean ovpn3_session_provide_input (Ovpn3Client *self,
                                      const gchar *session_path,
                                      guint32      type,
                                      guint32      group,
                                      guint32      id,
                                      const gchar *value,
                                      GError     **error);

/* Set a boolean override on @config_path via
 * net.openvpn.v3.configuration.SetOverride(s name, v value).  Used to push
 * UI-driven flags (route-nopull, force-default-gateway, block-ipv6,
 * dns-setup-disabled, dco, …) into the imported configuration before the
 * tunnel is started.  Returns FALSE and propagates @error on failure. */
gboolean ovpn3_config_set_override_bool (Ovpn3Client *self,
                                         const gchar *config_path,
                                         const gchar *name,
                                         gboolean     value,
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

/* Read the connected_to property — a (ssu) tuple of (protocol, host, port).
 * Out params may be NULL. */
gboolean ovpn3_session_get_connected_to (Ovpn3Client *self,
                                         const gchar *session_path,
                                         gchar      **out_proto,
                                         gchar      **out_host,
                                         guint32     *out_port,
                                         GError     **error);

/* Read the device_path property of @session_path (e.g.
 * "/net/openvpn/v3/netcfg/<pid>_<hex>"). */
gchar *ovpn3_session_get_device_path (Ovpn3Client *self,
                                      const gchar *session_path,
                                      GError     **error);

/* Read the dns_name_servers property of an openvpn3 netcfg device.
 * Returns a heap-allocated, NULL-terminated array of strings; caller
 * frees with g_strfreev.  Empty array (just a sentinel NULL) is valid. */
gchar **ovpn3_netcfg_get_dns_servers (Ovpn3Client *self,
                                      const gchar *device_path,
                                      GError     **error);

/* Read the dns_search_domains property.  Same ownership contract. */
gchar **ovpn3_netcfg_get_dns_search (Ovpn3Client *self,
                                     const gchar *device_path,
                                     GError     **error);

/* Set the session's public_access boolean property.  When TRUE, any UID
 * on the system bus can list and manage the session via the openvpn3
 * CLI — required so the user that triggered the NM connection (typically
 * uid 1000) sees the session created by our root-running service. */
gboolean ovpn3_session_set_public_access (Ovpn3Client *self,
                                          const gchar *session_path,
                                          gboolean     value,
                                          GError     **error);

/* Add @uid to the session's ACL via session.AccessGrant(u uid).  Required
 * for that uid to read per-property values like 'status' and 'device_name'
 * — public_access alone only authorises management methods. */
gboolean ovpn3_session_access_grant (Ovpn3Client *self,
                                     const gchar *session_path,
                                     guint32      uid,
                                     GError     **error);

#endif
