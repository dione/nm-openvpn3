//! NMVpnServicePlugin D-Bus interface, Rust side.
//!
//! The interface name matches libnm-core's
//! `org.freedesktop.NetworkManager.VPN.Plugin` so NM dispatches Connect
//! / Disconnect / NeedSecrets / NewSecrets to us identically to how it
//! drives the C plugin.  Only the bus name differs (claimed via
//! `--bus-name`) so the two implementations can co-exist behind
//! distinct `.name` files.
//!
//! Phase 2 ships methods only — Connect / Disconnect dispatch through
//! openvpn3-linux but signals (StateChanged, Ip4Config, Failure,
//! SecretsRequired …) are deferred to Phase 3.  Without them NM will
//! see the plugin claim its bus and process method calls, but won't
//! see the connection flip to ACTIVATED.  That's expected — the
//! milestone here is "service compiles + connects to the openvpn3
//! backend"; full NM wire-up is a Phase 3 task.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context};
use ovpn3_client::Client;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::interface;

use crate::connection::{vpn_data, Settings};
use crate::state::NMVpnServiceState;

pub const NM_VPN_PLUGIN_PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
pub const NM_VPN_PLUGIN_IFACE: &str = "org.freedesktop.NetworkManager.VPN.Plugin";

/// vpn.data key that holds the path to a verbatim .ovpn file (Plan 3d
/// in the C tree).  When present we hand the file straight to
/// openvpn3-linux's Import; the legacy token-by-token export path is
/// not ported in Phase 2.
pub const KEY_PROFILE: &str = "nm-openvpn3-profile";
pub const KEY_OVERRIDE_LOG_LEVEL: &str = "override-log-level";

/// Bool override keys that map 1:1 onto openvpn3 SetOverride flags.
const OVERRIDE_BOOLS: &[(&str, &str)] = &[
    ("override-route-nopull", "route-nopull"),
    ("override-force-default-gateway", "force-default-gateway"),
    ("override-block-ipv6", "block-ipv6"),
    ("override-dns-setup-disabled", "dns-setup-disabled"),
    ("override-dco", "dco"),
];

#[derive(Default)]
struct SessionState {
    config_path: Option<OwnedObjectPath>,
    session_path: Option<OwnedObjectPath>,
}

pub struct Plugin {
    client: Client,
    state: Mutex<NMVpnServiceState>,
    session: Mutex<SessionState>,
}

impl Plugin {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: Mutex::new(NMVpnServiceState::Init),
            session: Mutex::new(SessionState::default()),
        }
    }

    async fn set_state(&self, new: NMVpnServiceState) {
        let mut s = self.state.lock().await;
        if *s != new {
            info!("state {:?} → {:?}", *s, new);
            *s = new;
        }
    }

    async fn apply_overrides(
        &self,
        config_path: &OwnedObjectPath,
        data: &HashMap<String, String>,
    ) {
        for (vpn_key, ovpn3_name) in OVERRIDE_BOOLS {
            if data.get(*vpn_key).map(|s| s.as_str()) != Some("yes") {
                continue;
            }
            match self
                .client
                .config_set_override_bool(config_path, ovpn3_name, true)
                .await
            {
                Ok(()) => info!("SetOverride({ovpn3_name})=TRUE"),
                Err(e) => warn!("SetOverride({ovpn3_name}) failed: {e}"),
            }
        }
        if let Some(level) = data.get(KEY_OVERRIDE_LOG_LEVEL) {
            if !level.is_empty() && level != "0" {
                match level.parse::<u8>() {
                    Ok(1..=6) => match self
                        .client
                        .config_set_override_string(config_path, "log-level", level)
                        .await
                    {
                        Ok(()) => info!("SetOverride(log-level={level}) ok"),
                        Err(e) => warn!("SetOverride(log-level={level}) failed: {e}"),
                    },
                    _ => warn!("invalid log-level override '{level}' (must be 1..6)"),
                }
            }
        }
    }

    async fn do_connect(&self, connection: Settings) -> anyhow::Result<()> {
        let data = vpn_data(&connection).context("parsing vpn.data")?;
        let profile_path = data
            .get(KEY_PROFILE)
            .ok_or_else(|| anyhow!("vpn.data['{KEY_PROFILE}'] is required in Phase 2"))?;
        info!("profile path: {profile_path}");

        let profile = std::fs::read_to_string(Path::new(profile_path))
            .with_context(|| format!("reading profile file {profile_path}"))?;

        self.set_state(NMVpnServiceState::Starting).await;

        let id = data
            .get("connection-name")
            .cloned()
            .unwrap_or_else(|| "nm-openvpn3-rust".to_string());

        let config_path = self
            .client
            .import_config(&id, &profile, true)
            .await
            .context("Import")?;
        info!("config path: {config_path}");

        self.apply_overrides(&config_path, &data).await;

        let session_path = self
            .client
            .new_tunnel(&config_path)
            .await
            .context("NewTunnel")?;
        info!("session path: {session_path}");

        self.client
            .session_wait_ready(&session_path, Duration::from_secs(5))
            .await
            .context("waiting for session")?;

        self.client
            .session_connect(&session_path)
            .await
            .context("session.Connect")?;

        {
            let mut s = self.session.lock().await;
            s.config_path = Some(config_path);
            s.session_path = Some(session_path);
        }

        info!("Connect dispatched; backend handshake in progress");
        Ok(())
    }
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl Plugin {
    async fn connect(&self, connection: Settings) -> zbus::fdo::Result<()> {
        match self.do_connect(connection).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("Connect failed: {e:#}");
                self.set_state(NMVpnServiceState::Stopped).await;
                Err(zbus::fdo::Error::Failed(format!("{e:#}")).into())
            }
        }
    }

    async fn connect_interactive(
        &self,
        connection: Settings,
        _details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        self.connect(connection).await
    }

    async fn need_secrets(&self, _connection: Settings) -> zbus::fdo::Result<String> {
        // Profile-file path needs no secrets up-front; openvpn3 may still
        // prompt via AttentionRequired after Connect (Plan 2 in C; not
        // ported yet).
        Ok(String::new())
    }

    async fn disconnect(&self) -> zbus::fdo::Result<()> {
        let session = {
            let mut s = self.session.lock().await;
            std::mem::take(&mut *s)
        };
        if let Some(path) = session.session_path.as_ref() {
            if let Err(e) = self.client.session_disconnect(path).await {
                warn!("session.Disconnect failed: {e}");
            }
        }
        self.set_state(NMVpnServiceState::Stopped).await;
        Ok(())
    }

    async fn new_secrets(&self, _connection: Settings) -> zbus::fdo::Result<()> {
        debug!("new_secrets: nop (Phase 2)");
        Ok(())
    }

    #[zbus(property)]
    async fn state(&self) -> u32 {
        let s = self.state.lock().await;
        s.as_u32()
    }
}
