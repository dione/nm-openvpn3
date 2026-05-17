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
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use futures_util::stream::StreamExt;
use ovpn3_client::Client;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};
use zbus::interface;
use zbus::object_server::SignalEmitter;

use crate::connection::{vpn_data, Settings};
use crate::state::{NMVpnPluginFailure, NMVpnServiceState};
use crate::status::status_to_nm_state;

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
    /// Background tasks (status poller, stats timer, signal listener).
    /// Aborted en masse from Disconnect so the binary can self-exit
    /// without leaving them spinning on a dead session.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

pub struct Plugin {
    client: Client,
    state: Arc<Mutex<NMVpnServiceState>>,
    session: Arc<Mutex<SessionState>>,
    /// Fires when Disconnect runs (or activation hard-fails) so main
    /// can drop the bus name and exit — NM only sends SIGTERM if we
    /// hang, and without --persist the C plugin self-exits the same
    /// way.
    quit_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

fn make_emitter(connection: &zbus::Connection) -> zbus::Result<SignalEmitter<'static>> {
    SignalEmitter::new(
        connection,
        ObjectPath::try_from(NM_VPN_PLUGIN_PATH)
            .expect("NM_VPN_PLUGIN_PATH must parse as ObjectPath"),
    )
}

/// Transition the cached state and emit StateChanged.  Free function
/// so background tasks can call it with their cloned Arc references.
async fn set_state_via(
    emitter: &SignalEmitter<'_>,
    state: &Arc<Mutex<NMVpnServiceState>>,
    new: NMVpnServiceState,
) {
    let changed = {
        let mut s = state.lock().await;
        if *s == new {
            false
        } else {
            info!("state {:?} → {:?}", *s, new);
            *s = new;
            true
        }
    };
    if changed {
        if let Err(e) = emitter.state_changed(new.as_u32()).await {
            warn!("StateChanged emit failed: {e}");
        }
    }
}

impl Plugin {
    pub fn new(
        client: Client,
        quit_tx: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> Self {
        Self {
            client,
            state: Arc::new(Mutex::new(NMVpnServiceState::Init)),
            session: Arc::new(Mutex::new(SessionState::default())),
            quit_tx,
        }
    }

    /// Spawn the StatusChange listener.  Takes only what the task
    /// needs — no `self` reference — so the spawned future is `'static`
    /// without us shaving Arc-of-Plugin onto the ObjectServer-owned
    /// instance.
    fn spawn_status_listener(
        &self,
        connection: zbus::Connection,
        session_path: OwnedObjectPath,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let state = self.state.clone();
        tokio::spawn::<_>(async move {
            let proxy = match client.session_proxy(&session_path).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("StatusChange subscribe failed: {e}");
                    return;
                }
            };
            let mut stream = match proxy.receive_status_change().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("receive_status_change failed: {e}");
                    return;
                }
            };
            info!("StatusChange listener attached to {session_path}");
            while let Some(signal) = stream.next().await {
                let Ok(args) = signal.args() else { continue };
                let (major, minor) = (args.major, args.minor);
                debug!(
                    "StatusChange: major={major} minor={minor} msg='{}'",
                    args.message
                );
                let Some(target) = status_to_nm_state(major, minor) else {
                    continue;
                };
                let Ok(emitter) = make_emitter(&connection) else {
                    warn!("dropping StatusChange — could not build emitter");
                    continue;
                };
                match target {
                    NMVpnServiceState::Started => {
                        if let Err(e) =
                            crate::ip4::emit(&emitter, &client, &session_path).await
                        {
                            warn!("Ip4Config emit failed: {e:#}");
                        }
                        set_state_via(&emitter, &state, target).await;
                    }
                    NMVpnServiceState::Stopped => {
                        set_state_via(&emitter, &state, target).await;
                        let reason = if major == crate::status::OVPN3_MAJOR_SESSION {
                            NMVpnPluginFailure::LoginFailed
                        } else {
                            NMVpnPluginFailure::ConnectFailed
                        };
                        let _ = emitter.failure(reason.as_u32()).await;
                        break;
                    }
                    other => set_state_via(&emitter, &state, other).await,
                }
            }
            debug!("StatusChange listener exited for {session_path}");
        })
    }

    /// Mutate the cached state and emit a StateChanged signal so NM can
    /// follow the activation FSM.  `emitter` is the per-call
    /// SignalEmitter taken from the interface method's #[zbus(signal_emitter)]
    /// parameter.
    async fn set_state(&self, emitter: &SignalEmitter<'_>, new: NMVpnServiceState) {
        set_state_via(emitter, &self.state, new).await;
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

    async fn do_connect(
        &self,
        emitter: &SignalEmitter<'_>,
        conn: &zbus::Connection,
        connection: Settings,
    ) -> anyhow::Result<()> {
        eprintln!("[nm-openvpn3-rust] do_connect: parsing vpn.data");
        let data = vpn_data(&connection).context("parsing vpn.data")?;
        let profile_path = data
            .get(KEY_PROFILE)
            .ok_or_else(|| anyhow!("vpn.data['{KEY_PROFILE}'] is required in Phase 2"))?;
        info!("profile path: {profile_path}");

        let profile = std::fs::read_to_string(Path::new(profile_path))
            .with_context(|| format!("reading profile file {profile_path}"))?;

        self.set_state(emitter, NMVpnServiceState::Starting).await;

        let id = data
            .get("connection-name")
            .cloned()
            .unwrap_or_else(|| "nm-openvpn3-rust".to_string());

        eprintln!("[nm-openvpn3-rust] importing config '{id}' ({} bytes)", profile.len());
        let config_path = self
            .client
            .import_config(&id, &profile, true)
            .await
            .context("Import")?;
        eprintln!("[nm-openvpn3-rust] config path: {config_path}");
        info!("config path: {config_path}");

        self.apply_overrides(&config_path, &data).await;

        eprintln!("[nm-openvpn3-rust] calling NewTunnel");
        let session_path = self
            .client
            .new_tunnel(&config_path)
            .await
            .context("NewTunnel")?;
        eprintln!("[nm-openvpn3-rust] session path: {session_path}");
        info!("session path: {session_path}");

        eprintln!("[nm-openvpn3-rust] waiting for session ready");
        self.client
            .session_wait_ready(&session_path, Duration::from_secs(5))
            .await
            .context("waiting for session")?;
        eprintln!("[nm-openvpn3-rust] session ready");

        eprintln!("[nm-openvpn3-rust] granting access");
        self.grant_access(&session_path).await;

        eprintln!("[nm-openvpn3-rust] calling session.Connect");
        self.client
            .session_connect(&session_path)
            .await
            .context("session.Connect")?;
        eprintln!("[nm-openvpn3-rust] session.Connect ok");

        {
            let mut s = self.session.lock().await;
            s.config_path = Some(config_path);
            s.session_path = Some(session_path.clone());
        }

        // Attach the StatusChange listener so the activation FSM (and
        // any subsequent backend failure) reaches NM.  openvpn3-linux
        // historically unicasts StatusChange to subscribers that
        // existed *before* the backend client registered (the C tree
        // documented this as the reason it kept a polling watchdog
        // alongside the signal), so we run a polling loop in parallel
        // as the source of truth and treat the signal stream as a
        // bonus low-latency path when it works.
        let h1 = self.spawn_status_listener(conn.clone(), session_path.clone());
        let h2 = self.spawn_status_poller(conn.clone(), session_path.clone());
        // Periodic statistics dump.
        let h3 = self.spawn_stats_timer(session_path);
        {
            let mut s = self.session.lock().await;
            s.tasks.extend([h1, h2, h3]);
        }

        info!("Connect dispatched; backend handshake in progress");
        Ok(())
    }

    /// Open the session up for the user's CLI (`openvpn3 sessions-list`)
    /// and grant per-property read access via AccessGrant.  Mirrors the
    /// C tree's `grant_access_for_connection()` — Phase 3 lands the
    /// `/run/user` fallback only; explicit `permissions=user:NAME`
    /// parsing waits for Phase 4 once a libc-bound name → uid lookup
    /// is wired in.
    async fn grant_access(&self, session_path: &OwnedObjectPath) {
        if let Err(e) = self
            .client
            .session_set_public_access(session_path, true)
            .await
        {
            warn!("set public_access=TRUE failed: {e}");
        }
        if let Some(uid) = lowest_run_user_uid() {
            match self
                .client
                .session_access_grant(session_path, uid)
                .await
            {
                Ok(()) => info!("AccessGrant uid={uid} (/run/user fallback) ok"),
                Err(e) => warn!("AccessGrant uid={uid} failed: {e}"),
            }
        } else {
            debug!("AccessGrant fallback: no non-root uid in /run/user");
        }
    }

    /// Poll the session's status every 500 ms (fast-poll) until the
    /// backend transitions to STARTED, then thin out to a 5 s
    /// watchdog tick.  Mirrors the C tree's poll_status_cb plus the
    /// idempotence gate around emit_started_ip4_config.
    fn spawn_status_poller(
        &self,
        connection: zbus::Connection,
        session_path: OwnedObjectPath,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let state = self.state.clone();
        tokio::spawn::<_>(async move {
            eprintln!("[nm-openvpn3-rust] poller task started for {session_path}");
            let proxy = match client.session_proxy(&session_path).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[nm-openvpn3-rust] poller proxy build failed: {e}");
                    return;
                }
            };
            eprintln!("[nm-openvpn3-rust] poller proxy ready");
            let mut ip4_emitted = false;
            let mut tick_interval = Duration::from_millis(500);
            let max_ticks_pre_started = 120; // 120 * 500ms = 60s
            let mut ticks = 0u32;
            loop {
                tokio::time::sleep(tick_interval).await;
                ticks += 1;
                match proxy.status().await {
                    Ok((major, minor, _msg)) => {
                        eprintln!("[nm-openvpn3-rust] poll status: major={major} minor={minor}");
                        let mut target = status_to_nm_state(major, minor);

                        // openvpn3-linux v27 does not always flip the
                        // session.status property to CONN_CONNECTED
                        // after the backend client transitions — the
                        // signal that would have triggered the update
                        // is unicast and the session manager misses
                        // it.  As a fallback, read device_name: it
                        // goes from "" to "tun*" exactly when the
                        // backend installs its tun device, which is
                        // the moment NM needs the Ip4Config.
                        if !ip4_emitted
                            && target != Some(NMVpnServiceState::Stopped)
                        {
                            match proxy.device_name().await {
                                Ok(dev) if dev.starts_with("tun") => {
                                    eprintln!(
                                        "[nm-openvpn3-rust] device_name='{dev}' → treating as Started"
                                    );
                                    target = Some(NMVpnServiceState::Started);
                                }
                                Ok(dev) => eprintln!(
                                    "[nm-openvpn3-rust] device_name='{dev}' (waiting for tun*)"
                                ),
                                Err(e) => eprintln!(
                                    "[nm-openvpn3-rust] device_name read failed: {e}"
                                ),
                            }
                        }

                        let Some(target) = target else { continue };
                        let Ok(emitter) = make_emitter(&connection) else {
                            continue;
                        };
                        match target {
                            NMVpnServiceState::Started if !ip4_emitted => {
                                if let Err(e) =
                                    crate::ip4::emit(&emitter, &client, &session_path).await
                                {
                                    warn!("Ip4Config emit failed: {e:#}");
                                }
                                set_state_via(&emitter, &state, target).await;
                                ip4_emitted = true;
                                tick_interval = Duration::from_secs(5);
                                ticks = 0;
                            }
                            NMVpnServiceState::Stopped => {
                                set_state_via(&emitter, &state, target).await;
                                let reason = if major == crate::status::OVPN3_MAJOR_SESSION {
                                    NMVpnPluginFailure::LoginFailed
                                } else {
                                    NMVpnPluginFailure::ConnectFailed
                                };
                                let _ = emitter.failure(reason.as_u32()).await;
                                break;
                            }
                            other if !ip4_emitted => {
                                set_state_via(&emitter, &state, other).await;
                            }
                            _ => {}
                        }
                    }
                    Err(e) if ip4_emitted => {
                        warn!(
                            "session disappeared post-connect ({e}); failing to NM"
                        );
                        if let Ok(emitter) = make_emitter(&connection) {
                            set_state_via(&emitter, &state, NMVpnServiceState::Stopped)
                                .await;
                            let _ = emitter
                                .failure(NMVpnPluginFailure::ConnectFailed.as_u32())
                                .await;
                        }
                        break;
                    }
                    Err(e) => {
                        eprintln!("[nm-openvpn3-rust] status poll err: {e}");
                        if !ip4_emitted && ticks >= max_ticks_pre_started {
                            warn!("status poll timed out after {ticks} ticks");
                            if let Ok(emitter) = make_emitter(&connection) {
                                let _ = emitter
                                    .failure(NMVpnPluginFailure::ConnectFailed.as_u32())
                                    .await;
                            }
                            break;
                        }
                    }
                }
            }
            debug!("status poller exited for {session_path}");
        })
    }

    /// Periodic openvpn3 session.statistics fetch, logged at INFO so
    /// `journalctl -t nm-openvpn3-rust-service | grep stats` shows
    /// live throughput.  Mirrors `stats_timer_cb` in the C tree (with
    /// the v0.5.11 TUN_BYTES_* addition).
    fn spawn_stats_timer(
        &self,
        session_path: OwnedObjectPath,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        tokio::spawn::<_>(async move {
            let mut last_bytes_in: i64 = 0;
            let mut last_bytes_out: i64 = 0;
            let mut last_tick = std::time::Instant::now();
            let mut first = true;
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let stats = match client.session_get_statistics(&session_path).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("stats fetch failed: {e}");
                        return;
                    }
                };
                let bin = *stats.get("BYTES_IN").unwrap_or(&0);
                let bout = *stats.get("BYTES_OUT").unwrap_or(&0);
                let tbin = *stats.get("TUN_BYTES_IN").unwrap_or(&0);
                let tbout = *stats.get("TUN_BYTES_OUT").unwrap_or(&0);
                let pkt_in = *stats.get("PACKETS_IN").unwrap_or(&0);
                let pkt_out = *stats.get("PACKETS_OUT").unwrap_or(&0);
                if first {
                    info!(
                        "stats: rx={bin}B tx={bout}B tun_rx={tbin}B tun_tx={tbout}B \
                         pkt_in={pkt_in} pkt_out={pkt_out}"
                    );
                    first = false;
                } else {
                    let now = std::time::Instant::now();
                    let dt = now.duration_since(last_tick).as_secs_f64().max(1e-3);
                    let rate_rx = ((bin - last_bytes_in) as f64 / dt) as i64;
                    let rate_tx = ((bout - last_bytes_out) as f64 / dt) as i64;
                    info!(
                        "stats: rx={bin}B tx={bout}B tun_rx={tbin}B tun_tx={tbout}B \
                         pkt_in={pkt_in} pkt_out={pkt_out} \
                         rate_rx={rate_rx}B/s rate_tx={rate_tx}B/s"
                    );
                    last_tick = now;
                }
                last_bytes_in = bin;
                last_bytes_out = bout;
            }
        })
    }
}

/// Read /run/user and return the lowest non-zero UID present.  systemd
/// creates per-user runtime dirs there, so the lowest UID is almost
/// always the human session that triggered NM's activation.
fn lowest_run_user_uid() -> Option<u32> {
    let entries = std::fs::read_dir("/run/user").ok()?;
    let mut best: Option<u32> = None;
    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else { continue };
        let Ok(uid) = name.parse::<u32>() else { continue };
        if uid == 0 {
            continue;
        }
        best = Some(best.map_or(uid, |b| b.min(uid)));
    }
    best
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl Plugin {
    async fn connect(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        connection: Settings,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[nm-openvpn3-rust] Connect dispatch entered");
        info!("Connect dispatch entered");
        let r = self.do_connect(&emitter, conn, connection).await;
        eprintln!("[nm-openvpn3-rust] Connect dispatch returned: {r:?}");
        match r {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("Connect failed: {e:#}");
                self.set_state(&emitter, NMVpnServiceState::Stopped).await;
                let _ = emitter
                    .failure(crate::state::NMVpnPluginFailure::ConnectFailed.as_u32())
                    .await;
                Err(zbus::fdo::Error::Failed(format!("{e:#}")))
            }
        }
    }

    async fn connect_interactive(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        connection: Settings,
        _details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        self.connect(emitter, conn, connection).await
    }

    async fn need_secrets(&self, _connection: Settings) -> zbus::fdo::Result<String> {
        // Profile-file path needs no secrets up-front; openvpn3 may still
        // prompt via AttentionRequired after Connect (Plan 2 in C; not
        // ported yet).
        Ok(String::new())
    }

    async fn disconnect(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[nm-openvpn3-rust] Disconnect dispatched");
        let session = {
            let mut s = self.session.lock().await;
            std::mem::take(&mut *s)
        };
        // Abort the poller / stats / signal-listener background tasks
        // so they stop talking to a session we are about to tear down.
        for h in session.tasks {
            h.abort();
        }
        if let Some(path) = session.session_path.as_ref() {
            if let Err(e) = self.client.session_disconnect(path).await {
                warn!("session.Disconnect failed: {e}");
            }
        }
        self.set_state(&emitter, NMVpnServiceState::Stopped).await;
        // NM's contract: the plugin process exits after Disconnect
        // unless it was started with --persist.  Tickle main to drop
        // the bus name and return from the signal-wait loop.
        let _ = self.quit_tx.send(());
        Ok(())
    }

    async fn new_secrets(&self, _connection: Settings) -> zbus::fdo::Result<()> {
        debug!("new_secrets: nop (Phase 2)");
        Ok(())
    }

    // Outbound signals (plugin → NM).  zbus 5 generates emit helpers
    // that take a SignalEmitter as first argument; we invoke them via
    // `Self::state_changed(&emitter, value).await` from method handlers.
    // Note: signal declarations take no self.

    #[zbus(signal)]
    async fn state_changed(emitter: SignalEmitter<'_>, state: u32) -> zbus::Result<()>;

    // libnm dispatch table maps the wire signal `Config(a{sv})` →
    // `NMVpnServicePlugin::config`; zbus would otherwise emit
    // `VpnConfig` and NM would silently drop it, leaving NM stuck
    // with "no VPN gateway address received".
    #[zbus(signal, name = "Config")]
    async fn vpn_config(
        emitter: SignalEmitter<'_>,
        config: std::collections::HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "Ip4Config")]
    async fn ip4_config(
        emitter: SignalEmitter<'_>,
        ip4_config: std::collections::HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn failure(emitter: SignalEmitter<'_>, reason: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn secrets_required(
        emitter: SignalEmitter<'_>,
        message: String,
        hints: Vec<String>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn login_banner(emitter: SignalEmitter<'_>, banner: String) -> zbus::Result<()>;
}
