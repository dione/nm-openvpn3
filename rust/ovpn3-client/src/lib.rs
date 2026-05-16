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

    /// Poll the session's `Ready` property by reading `status`; returns
    /// once the backend client has finished registering on the bus or
    /// `timeout` elapses.
    ///
    /// In the C client we polled `Ready`; here we accept that
    /// `get_status` succeeding is a sufficient readiness probe.
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
            match proxy.get_status().await {
                Ok(_) => return Ok(()),
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

    /// Read the per-session connected_to property — (proto, host, port).
    pub async fn session_get_connected_to(
        &self,
        session_path: &OwnedObjectPath,
    ) -> zbus::Result<Option<(String, String, u32)>> {
        // openvpn3 surfaces this as `(ssu)` directly on session; in the
        // C tree this was a method but the underlying property is the
        // same shape.  Once the property is wired we can swap to a
        // typed accessor; for Phase 3 we use the raw Properties
        // interface call.
        let conn = &self.connection;
        let reply = conn
            .call_method(
                Some(BUS_SESSIONS),
                session_path.as_ref(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("net.openvpn.v3.sessions", "last_connected"),
            )
            .await;
        // The session uses `connected_to` rather than `last_connected`;
        // fall back to a typed read on whichever name responds.
        let reply = match reply {
            Ok(r) => r,
            Err(_) => {
                conn.call_method(
                    Some(BUS_SESSIONS),
                    session_path.as_ref(),
                    Some("org.freedesktop.DBus.Properties"),
                    "Get",
                    &("net.openvpn.v3.sessions", "connected_to"),
                )
                .await?
            }
        };
        let body = reply.body();
        let value: zbus::zvariant::OwnedValue = body.deserialize()?;
        if let Ok((p, h, port)) = <(String, String, u32)>::try_from(value.clone()) {
            return Ok(Some((p, h, port)));
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

        #[zbus(property)]
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

        /// Returns `(major, minor, message)`.
        #[zbus(name = "GetStatus")]
        fn get_status(&self) -> zbus::Result<(u32, u32, String)>;

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

        #[zbus(property)]
        fn statistics(&self) -> zbus::Result<HashMap<String, i64>>;
        #[zbus(property)]
        fn device_name(&self) -> zbus::Result<String>;
        #[zbus(property)]
        fn device_path(&self) -> zbus::Result<OwnedObjectPath>;
        #[zbus(property)]
        fn public_access(&self) -> zbus::Result<bool>;
        #[zbus(property)]
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
        #[zbus(property)]
        fn dns_name_servers(&self) -> zbus::Result<Vec<String>>;
        #[zbus(property)]
        fn dns_search_domains(&self) -> zbus::Result<Vec<String>>;
    }
}
