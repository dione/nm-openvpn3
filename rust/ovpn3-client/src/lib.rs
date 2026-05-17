//! Async Rust client for the openvpn3-linux D-Bus stack.
//!
//! Mirrors the C `ovpn3-client.{h,c}` API used by the legacy
//! `nm-openvpn3-service` daemon, but built on `zbus` instead of GDBus.
//! Method signatures match the documented openvpn3-linux interface and
//! were cross-checked against `gdbus introspect` output on a live
//! configuration / session object.

use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{proxy, Connection};

pub mod retry;

pub use proxies::{ConfigurationManagerProxy, ConfigurationProxy, NetCfgDeviceProxy, SessionProxy, SessionsManagerProxy};

pub const BUS_CONFIG: &str = "net.openvpn.v3.configuration";
pub const BUS_SESSIONS: &str = "net.openvpn.v3.sessions";
pub const BUS_NETCFG: &str = "net.openvpn.v3.netcfg";

pub const PATH_CONFIG: &str = "/net/openvpn/v3/configuration";
pub const PATH_SESSIONS: &str = "/net/openvpn/v3/sessions";

/// Cached system-bus connection + manager proxies.
///
/// Constructed once per service activation; individual sessions / configs
/// reuse the same `Connection` via per-object proxies.
#[derive(Clone)]
pub struct Client {
    connection: Connection,
}

impl Client {
    /// Open the system bus and stash a connection handle.
    pub async fn new() -> zbus::Result<Self> {
        let connection = Connection::system().await?;
        Ok(Self { connection })
    }

    /// Borrow the underlying connection (the per-object proxies need it).
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// `net.openvpn.v3.configuration.Import` with retry on transient
    /// auto-activation errors.  Returns the new configuration's object
    /// path.
    pub async fn import_config(
        &self,
        name: &str,
        ovpn_profile: &str,
        single_use: bool,
    ) -> anyhow::Result<OwnedObjectPath> {
        let proxy = ConfigurationManagerProxy::new(&self.connection).await?;
        retry::with_transient_retry(3, Duration::from_millis(200), || async {
            proxy.import(name, ovpn_profile, single_use, false).await
        })
        .await
    }

    /// `net.openvpn.v3.sessions.NewTunnel(config_path)`.
    pub async fn new_tunnel(
        &self,
        config_path: &OwnedObjectPath,
    ) -> anyhow::Result<OwnedObjectPath> {
        let proxy = SessionsManagerProxy::new(&self.connection).await?;
        let path_ref: &zbus::zvariant::ObjectPath<'_> = config_path;
        retry::with_transient_retry(3, Duration::from_millis(200), || async {
            proxy.new_tunnel(path_ref).await
        })
        .await
    }

    /// `net.openvpn.v3.configuration.SetOverride(name, value)` with a bool value.
    pub async fn config_set_override_bool(
        &self,
        config_path: &OwnedObjectPath,
        name: &str,
        value: bool,
    ) -> zbus::Result<()> {
        let proxy = ConfigurationProxy::builder(&self.connection)
            .path(config_path.as_ref())?
            .build()
            .await?;
        proxy.set_override(name, &Value::Bool(value)).await
    }

    /// `net.openvpn.v3.configuration.SetOverride(name, value)` with a string value.
    /// openvpn3 stores the `log-level` override as a string ("1".."6"), so
    /// the integer-shaped wrapper would be rejected — use this for the
    /// numeric-but-stringly-typed overrides.
    pub async fn config_set_override_string(
        &self,
        config_path: &OwnedObjectPath,
        name: &str,
        value: &str,
    ) -> zbus::Result<()> {
        let proxy = ConfigurationProxy::builder(&self.connection)
            .path(config_path.as_ref())?
            .build()
            .await?;
        let v: zbus::zvariant::Value = value.into();
        proxy.set_override(name, &v).await
    }

    /// Poll the session's `Ready` method until the backend client has
    /// finished registering on the bus.  GetStatus would also work
    /// once the session is alive, but it is per-property ACL-gated;
    /// `Ready` is not, so it is the right probe to use before
    /// AccessGrant has been issued.
    pub async fn session_wait_ready(
        &self,
        session_path: &OwnedObjectPath,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let proxy = SessionProxy::builder(&self.connection)
            .path(session_path.as_ref())?
            .build()
            .await?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match proxy.ready().await {
                Ok(()) => return Ok(()),
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => return Err(anyhow::Error::from(e)),
            }
        }
    }

    /// `session.Connect()` — start the backend handshake.
    pub async fn session_connect(&self, session_path: &OwnedObjectPath) -> zbus::Result<()> {
        let proxy = SessionProxy::builder(&self.connection)
            .path(session_path.as_ref())?
            .build()
            .await?;
        proxy.connect().await
    }

    /// `session.Disconnect()`.
    pub async fn session_disconnect(&self, session_path: &OwnedObjectPath) -> zbus::Result<()> {
        let proxy = SessionProxy::builder(&self.connection)
            .path(session_path.as_ref())?
            .build()
            .await?;
        proxy.disconnect().await
    }

    /// Read `session.statistics` (the `a{sx}` dictionary).
    pub async fn session_get_statistics(
        &self,
        session_path: &OwnedObjectPath,
    ) -> zbus::Result<HashMap<String, i64>> {
        let proxy = SessionProxy::builder(&self.connection)
            .path(session_path.as_ref())?
            .build()
            .await?;
        let raw = proxy.statistics().await?;
        Ok(raw.into_iter().collect())
    }

    /// Read the netcfg device's DNS server list (each element is a
    /// dotted-quad / IPv6 string).
    pub async fn netcfg_get_dns_servers(
        &self,
        device_path: &OwnedObjectPath,
    ) -> zbus::Result<Vec<String>> {
        let proxy = NetCfgDeviceProxy::builder(&self.connection)
            .path(device_path.as_ref())?
            .build()
            .await?;
        proxy.dns_name_servers().await
    }

    pub async fn netcfg_get_dns_search(
        &self,
        device_path: &OwnedObjectPath,
    ) -> zbus::Result<Vec<String>> {
        let proxy = NetCfgDeviceProxy::builder(&self.connection)
            .path(device_path.as_ref())?
            .build()
            .await?;
        proxy.dns_search_domains().await
    }

    /// Build a Session proxy for an existing session path.  Callers use
    /// this to subscribe to StatusChange / AttentionRequired streams
    /// without going through one of the wrapped helpers.
    pub async fn session_proxy(
        &self,
        session_path: &OwnedObjectPath,
    ) -> zbus::Result<SessionProxy<'static>> {
        SessionProxy::builder(&self.connection)
            .path(session_path.clone())?
            .build()
            .await
    }

    /// Read the per-session remote host.  openvpn3-linux v27 exposes
    /// the live remote endpoint via the `last_connection` property
    /// (`a{sv}` with `host`, `port`, `protocol`, `ip` keys).  Older
    /// builds shipped `connected_to` as a plain string of the form
    /// `user@host:port`; we accept either.
    pub async fn session_get_connected_to(
        &self,
        session_path: &OwnedObjectPath,
    ) -> zbus::Result<Option<(String, String, u32)>> {
        use zbus::zvariant::OwnedValue;
        let conn = &self.connection;

        let try_prop = |name: &'static str| {
            let conn = conn.clone();
            let path = session_path.clone();
            async move {
                conn.call_method(
                    Some(BUS_SESSIONS),
                    path.as_ref(),
                    Some("org.freedesktop.DBus.Properties"),
                    "Get",
                    &("net.openvpn.v3.sessions", name),
                )
                .await
            }
        };

        // Preferred: `last_connection` dict (v27+).
        if let Ok(reply) = try_prop("last_connection").await {
            let body = reply.body();
            if let Ok(value) = body.deserialize::<OwnedValue>() {
                if let Ok(map) = <HashMap<String, OwnedValue>>::try_from(value) {
                    let host = map
                        .get("ip")
                        .or_else(|| map.get("host"))
                        .and_then(|v| <String>::try_from(v.try_clone().ok()?).ok())
                        .unwrap_or_default();
                    let port = map
                        .get("port")
                        .and_then(|v| <u32>::try_from(v.try_clone().ok()?).ok())
                        .unwrap_or(0);
                    let proto = map
                        .get("protocol")
                        .and_then(|v| <String>::try_from(v.try_clone().ok()?).ok())
                        .unwrap_or_default();
                    if !host.is_empty() {
                        return Ok(Some((proto, host, port)));
                    }
                }
            }
        }

        // Legacy: `connected_to` — usually `(ssu)` or a single string.
        if let Ok(reply) = try_prop("connected_to").await {
            let body = reply.body();
            if let Ok(value) = body.deserialize::<OwnedValue>() {
                if let Ok((p, h, port)) = <(String, String, u32)>::try_from(value.try_clone()?) {
                    return Ok(Some((p, h, port)));
                }
                if let Ok(s) = <String>::try_from(value) {
                    // "user@host:port" or "host:port" or bare host.
                    let rest = s.rsplit_once('@').map(|(_, r)| r).unwrap_or(&s);
                    if let Some((host, port)) = rest.rsplit_once(':') {
                        let port = port.parse::<u32>().unwrap_or(0);
                        return Ok(Some((String::new(), host.to_string(), port)));
                    }
                    return Ok(Some((String::new(), rest.to_string(), 0)));
                }
            }
        }
        Ok(None)
    }

    /// Read the per-session device_name property.
    pub async fn session_get_device_name(
        &self,
        session_path: &OwnedObjectPath,
    ) -> zbus::Result<String> {
        let proxy = self.session_proxy(session_path).await?;
        proxy.device_name().await
    }

    /// Read the per-session device_path property.
    pub async fn session_get_device_path(
        &self,
        session_path: &OwnedObjectPath,
    ) -> zbus::Result<OwnedObjectPath> {
        let proxy = self.session_proxy(session_path).await?;
        proxy.device_path().await
    }

    /// `session.set_public_access(b)` toggles whether non-owner UIDs
    /// can manage the session via the `openvpn3 sessions-list` CLI.
    pub async fn session_set_public_access(
        &self,
        session_path: &OwnedObjectPath,
        value: bool,
    ) -> zbus::Result<()> {
        let proxy = self.session_proxy(session_path).await?;
        proxy.set_public_access(value).await
    }

    /// Grant a specific UID per-property read access via AccessGrant.
    pub async fn session_access_grant(
        &self,
        session_path: &OwnedObjectPath,
        uid: u32,
    ) -> zbus::Result<()> {
        let proxy = self.session_proxy(session_path).await?;
        proxy.access_grant(uid).await
    }

    /// Drain the session's UserInputQueue and return every pending
    /// slot.  Mirrors the C `ovpn3_session_fetch_input_slots()` —
    /// walks the (type, group) pairs, then `Check`s each pair for
    /// queued slot indices, then `Fetch`es each to get the descriptor.
    pub async fn session_fetch_input_slots(
        &self,
        session_path: &OwnedObjectPath,
    ) -> anyhow::Result<Vec<InputSlot>> {
        let proxy = self.session_proxy(session_path).await?;
        let mut out = Vec::new();
        let pairs = match proxy.user_input_queue_get_type_group().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("UserInputQueueGetTypeGroup failed: {e}");
                return Ok(out);
            }
        };
        for (t, g) in pairs {
            let ids = match proxy.user_input_queue_check(t, g).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("UserInputQueueCheck({t},{g}) failed: {e}");
                    continue;
                }
            };
            for id in ids {
                match proxy.user_input_queue_fetch(t, g, id).await {
                    Ok((_t, _g, _id, name, descr, mask_input)) => out.push(InputSlot {
                        type_: t,
                        group: g,
                        id,
                        name,
                        description: descr,
                        mask_input,
                    }),
                    Err(e) => tracing::debug!(
                        "UserInputQueueFetch({t},{g},{id}) failed: {e}"
                    ),
                }
            }
        }
        Ok(out)
    }

    /// Send a queued user-input value back to the backend.
    pub async fn session_provide_input(
        &self,
        session_path: &OwnedObjectPath,
        slot: &InputSlot,
        value: &str,
    ) -> zbus::Result<()> {
        let proxy = self.session_proxy(session_path).await?;
        proxy
            .user_input_provide(slot.type_, slot.group, slot.id, value)
            .await
    }
}

/// One queued credential request from openvpn3's UserInputQueue.
/// `type_` + `group` + `id` are the coordinates ProvideInput needs.
#[derive(Debug, Clone)]
pub struct InputSlot {
    pub type_: u32,
    pub group: u32,
    pub id: u32,
    /// Slot identifier as openvpn3 names it ("username", "password",
    /// "static_challenge", ...). Used by the NM-side slot→vpn-secrets
    /// mapping.
    pub name: String,
    pub description: String,
    /// True for password-style slots (NM should not echo the value).
    #[allow(dead_code)]
    pub mask_input: bool,
}

mod proxies {
    use super::*;

    #[proxy(
        interface = "net.openvpn.v3.configuration",
        default_service = "net.openvpn.v3.configuration",
        default_path = "/net/openvpn/v3/configuration"
    )]
    pub trait ConfigurationManager {
        /// `Import(name, config_str, single_use, persistent) -> config_path`.
        fn import(
            &self,
            name: &str,
            config_str: &str,
            single_use: bool,
            persistent: bool,
        ) -> zbus::Result<OwnedObjectPath>;
    }

    /// Per-configuration object (path is dynamic).
    #[proxy(
        interface = "net.openvpn.v3.configuration",
        default_service = "net.openvpn.v3.configuration",
        assume_defaults = false
    )]
    pub trait Configuration {
        fn set_override(&self, name: &str, value: &Value<'_>) -> zbus::Result<()>;
        fn unset_override(&self, name: &str) -> zbus::Result<()>;

        #[zbus(property, name = "overrides")]
        fn overrides(&self) -> zbus::Result<HashMap<String, OwnedValue>>;
    }

    #[proxy(
        interface = "net.openvpn.v3.sessions",
        default_service = "net.openvpn.v3.sessions",
        default_path = "/net/openvpn/v3/sessions"
    )]
    pub trait SessionsManager {
        fn new_tunnel(&self, config_path: &zbus::zvariant::ObjectPath<'_>)
            -> zbus::Result<OwnedObjectPath>;

        #[zbus(name = "FetchAvailableSessions")]
        fn fetch_available_sessions(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    }

    /// Per-session object.
    #[proxy(
        interface = "net.openvpn.v3.sessions",
        default_service = "net.openvpn.v3.sessions",
        assume_defaults = false
    )]
    pub trait Session {
        fn connect(&self) -> zbus::Result<()>;
        fn disconnect(&self) -> zbus::Result<()>;
        fn ready(&self) -> zbus::Result<()>;
        fn access_grant(&self, uid: u32) -> zbus::Result<()>;

        /// `status` is a read-only property (the `GetStatus` method
        /// exists too but is not in the upstream D-Bus policy
        /// allow-list — Properties.Get is, so the property read is the
        /// only safe probe from a non-_openvpn process).  Returns a
        /// `(major, minor, message)` tuple.  Lower-case `status` —
        /// zbus would otherwise PascalCase it to `Status`.
        // openvpn3-linux does NOT emit PropertiesChanged for `status`
        // (only its unicast `StatusChange` signal carries the data), so
        // zbus' default property cache would freeze on the first poll.
        // `emits_changed_signal = "false"` forces a fresh Properties.Get
        // on every call.
        #[zbus(property(emits_changed_signal = "false"), name = "status")]
        fn status(&self) -> zbus::Result<(u32, u32, String)>;

        // UserInputQueue (Plan 2 path)
        #[zbus(name = "UserInputQueueGetTypeGroup")]
        fn user_input_queue_get_type_group(&self) -> zbus::Result<Vec<(u32, u32)>>;
        #[zbus(name = "UserInputQueueCheck")]
        fn user_input_queue_check(&self, t: u32, g: u32) -> zbus::Result<Vec<u32>>;
        #[zbus(name = "UserInputQueueFetch")]
        fn user_input_queue_fetch(
            &self,
            t: u32,
            g: u32,
            id: u32,
        ) -> zbus::Result<(u32, u32, u32, String, String, bool)>;
        #[zbus(name = "UserInputProvide")]
        fn user_input_provide(&self, t: u32, g: u32, id: u32, value: &str) -> zbus::Result<()>;

        // openvpn3-linux exposes its properties in snake_case; zbus
        // would otherwise PascalCase the Rust fn names.
        // Same caveat as `status` above — openvpn3 mutates these
        // properties without firing PropertiesChanged, so we must
        // bypass zbus' cache or the poller will see stale data forever.
        #[zbus(property(emits_changed_signal = "false"), name = "statistics")]
        fn statistics(&self) -> zbus::Result<HashMap<String, i64>>;
        #[zbus(property(emits_changed_signal = "false"), name = "device_name")]
        fn device_name(&self) -> zbus::Result<String>;
        #[zbus(property(emits_changed_signal = "false"), name = "device_path")]
        fn device_path(&self) -> zbus::Result<OwnedObjectPath>;
        #[zbus(property, name = "public_access")]
        fn public_access(&self) -> zbus::Result<bool>;
        #[zbus(property, name = "public_access")]
        fn set_public_access(&self, value: bool) -> zbus::Result<()>;

        /// Backend status changes (major, minor, message).
        #[zbus(signal)]
        fn status_change(&self, major: u32, minor: u32, message: String) -> zbus::Result<()>;

        /// User-input prompt (auth + 2FA), Plan 2.
        #[zbus(signal)]
        fn attention_required(&self, t: u32, g: u32, message: String) -> zbus::Result<()>;
    }

    /// Per-netcfg-device proxy (the DNS / IP push target).
    #[proxy(
        interface = "net.openvpn.v3.netcfg",
        default_service = "net.openvpn.v3.netcfg",
        assume_defaults = false
    )]
    pub trait NetCfgDevice {
        #[zbus(property, name = "dns_name_servers")]
        fn dns_name_servers(&self) -> zbus::Result<Vec<String>>;
        #[zbus(property, name = "dns_search_domains")]
        fn dns_search_domains(&self) -> zbus::Result<Vec<String>>;
    }
}
