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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use futures_util::stream::StreamExt;
use ovpn3_client::Client;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

use crate::connection::{vpn_data, Settings};
use crate::secrets::SecretsMap;
use crate::state::{NMVpnPluginFailure, NMVpnServiceState};
use crate::status::Status;
use ovpn3_client::InputSlot;

pub const NM_VPN_PLUGIN_PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
pub const NM_VPN_PLUGIN_IFACE: &str = "org.freedesktop.NetworkManager.VPN.Plugin";

/// vpn.data key that holds the path to a verbatim .ovpn file (Plan 3d
/// in the C tree).  When present we hand the file straight to
/// openvpn3-linux's Import; the legacy token-by-token export path is
/// not ported in Phase 2.
pub const KEY_PROFILE: &str = "nm-openvpn3-profile";
pub const KEY_OVERRIDE_LOG_LEVEL: &str = "override-log-level";

/// Hard cap on the inline .ovpn profile we'll slurp off disk.  NM passes
/// the path via attacker-controllable `vpn.data`, so an oversized or
/// special file (`/dev/zero`, a swap-backed FIFO) would otherwise drive
/// the service into unbounded allocation or an indefinite read.  1 MiB
/// is well past anything a legitimate OpenVPN profile reaches in
/// practice (CA bundle + inline cert/key tops out around 50 KiB).
const MAX_PROFILE_BYTES: u64 = 1 << 20;

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
    /// Slots queued by AttentionRequired that still need NM to prompt
    /// the user.  `new_secrets` walks this list and ProvideInputs each.
    pending_slots: Vec<InputSlot>,
    /// Most recent vpn.data half of the Settings dict, kept around so
    /// AttentionRequired can auto-fill non-secret slots (username,
    /// connection-name, …) without bouncing through NM.
    current_data: HashMap<String, String>,
    /// Most recent vpn.secrets half, wrapped in `Zeroizing` so the
    /// plaintext bytes are scrubbed when the map is replaced or the
    /// session torn down (rather than living in zbus' OwnedValue cache
    /// for the lifetime of the plugin).
    current_secrets: SecretsMap,
    /// Per-session emit guard.  Listener + poller race to publish
    /// Config / Ip4Config; the loser becomes a no-op.  Held on the
    /// session (not the plugin) so a Disconnect that finishes while
    /// the prior session's listener is mid-emit can't race a fresh
    /// Connect resetting a plugin-global flag — the old listeners
    /// hold their own Arc and the new Connect builds a new one.
    ip4_emitted: Arc<AtomicBool>,
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
    pub fn new(client: Client, quit_tx: tokio::sync::mpsc::UnboundedSender<()>) -> Self {
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
        ip4_emitted: Arc<AtomicBool>,
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
                debug!(
                    "StatusChange: major={} minor={} msg='{}'",
                    args.major, args.minor, args.message
                );
                let Some(status) = Status::from_wire(args.major, args.minor) else {
                    continue;
                };
                let Some(target) = status.to_nm_state() else {
                    continue;
                };
                let Ok(emitter) = make_emitter(&connection) else {
                    warn!("dropping StatusChange — could not build emitter");
                    continue;
                };
                match target {
                    NMVpnServiceState::Started => {
                        // Race-safe coordinate with spawn_status_poller —
                        // whichever spots CONNECTED first emits, the
                        // other becomes a no-op.  Memory-ordering:
                        //   * success = AcqRel — the winner publishes
                        //     "ip4 has been emitted" before NM sees the
                        //     SetConfig signal it triggers.
                        //   * failure = Acquire — the loser must see
                        //     every state write the winner made before
                        //     it stored `true`.
                        //   * roll-back path (Ip4Config emit failed)
                        //     stores `false` with Release — pairs with
                        //     the next CAS's Acquire on either path.
                        if ip4_emitted
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_err()
                        {
                            debug!("StatusChange: Started reached after poller emitted, skipping");
                            set_state_via(&emitter, &state, target).await;
                            continue;
                        }
                        if let Err(e) = crate::ip4::emit(&emitter, &client, &session_path).await {
                            warn!("Ip4Config emit failed: {e:#}; failing to NM");
                            // Roll back the guard so a recovery path
                            // (status re-poll) can still retry once
                            // openvpn3 fixes its state.
                            ip4_emitted.store(false, Ordering::Release);
                            set_state_via(&emitter, &state, NMVpnServiceState::Stopped).await;
                            let _ = emitter
                                .failure(NMVpnPluginFailure::BadIpConfig.as_u32())
                                .await;
                            break;
                        }
                        set_state_via(&emitter, &state, target).await;
                    }
                    NMVpnServiceState::Stopped => {
                        set_state_via(&emitter, &state, target).await;
                        let _ = emitter.failure(status.failure_reason().as_u32()).await;
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

    async fn apply_overrides(&self, config_path: &OwnedObjectPath, data: &HashMap<String, String>) {
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
        // Fresh per-session emit guard.  Prior listeners (if any are
        // mid-emit during a fast Disconnect/Connect cycle) keep
        // referencing the previous Arc; this Connect's listeners get a
        // brand-new flag they alone can flip.
        let ip4_emitted = Arc::new(AtomicBool::new(false));

        let data = vpn_data(&connection).context("parsing vpn.data")?;
        // Split secrets out early — build_profile may need them and we
        // want to stash the same Zeroizing'd map on session state below
        // either way.
        let (data_map, secret_map) = crate::secrets::split_vpn(&connection);

        // Two profile paths, matching the C tree's `build_profile_string`:
        //   1. `vpn.data['nm-openvpn3-profile']` set → read a verbatim
        //      .ovpn file off disk (preserves modern openvpn3 syntax the
        //      legacy exporter cannot reproduce — tls-crypt-v2,
        //      peer-fingerprint, etc.).
        //   2. Key absent → emit the .ovpn text from the settings dict
        //      via `build_profile::build_profile_string`.
        let profile = if let Some(profile_path) = data.get(KEY_PROFILE) {
            debug!("profile path: {profile_path}");
            let md = tokio::fs::metadata(Path::new(profile_path))
                .await
                .with_context(|| format!("stat'ing profile file {profile_path}"))?;
            if !md.is_file() {
                return Err(anyhow!("profile path {profile_path} is not a regular file"));
            }
            if md.len() > MAX_PROFILE_BYTES {
                return Err(anyhow!(
                    "profile {profile_path} is {} bytes; refusing (cap {MAX_PROFILE_BYTES})",
                    md.len()
                ));
            }
            let buf = tokio::fs::read_to_string(Path::new(profile_path))
                .await
                .with_context(|| format!("reading profile file {profile_path}"))?;
            if buf.len() as u64 > MAX_PROFILE_BYTES {
                // TOCTOU guard: file grew between metadata and read.
                return Err(anyhow!(
                    "profile {profile_path} grew past {MAX_PROFILE_BYTES} bytes during read"
                ));
            }
            buf
        } else {
            debug!("no profile path; building config from vpn.data");
            crate::build_profile::build_profile_string(&data_map, &secret_map)
                .context("building profile from vpn.data")?
        };

        self.set_state(emitter, NMVpnServiceState::Starting).await;

        let id = data
            .get("connection-name")
            .cloned()
            .unwrap_or_else(|| "nm-openvpn3-rust".to_string());

        debug!("importing config '{id}' ({} bytes)", profile.len());
        let config_path = self
            .client
            .import_config(&id, &profile, true)
            .await
            .context("Import")?;
        debug!("config path: {config_path}");

        self.apply_overrides(&config_path, &data).await;

        let session_path = self
            .client
            .new_tunnel(&config_path)
            .await
            .context("NewTunnel")?;
        debug!("session path: {session_path}");

        // Stash the session immediately so any subsequent failure can
        // tear it down — otherwise the openvpn3 daemon keeps a dangling
        // session around until process exit (it survives both NM's
        // failure dispatch and a fresh activation attempt).  The
        // pre-split (data, Zeroizing<secrets>) pair was taken at the
        // top of do_connect (so build_profile could see it without a
        // second clone of the OwnedValue secrets); just hand it to the
        // session here.  The raw `Settings` clone is no longer needed.
        drop(connection);
        {
            let mut s = self.session.lock().await;
            s.config_path = Some(config_path);
            s.session_path = Some(session_path.clone());
            s.current_data = data_map;
            s.current_secrets = secret_map;
            s.ip4_emitted = ip4_emitted.clone();
        }

        let bring_up: anyhow::Result<()> = async {
            self.client
                .session_wait_ready(&session_path, Duration::from_secs(5))
                .await
                .context("waiting for session")?;
            self.grant_access(&session_path).await;
            self.client
                .session_connect(&session_path)
                .await
                .context("session.Connect")?;
            Ok(())
        }
        .await;

        if let Err(e) = bring_up {
            warn!("activation failed after NewTunnel; tearing down session {session_path}");
            // openvpn3 drops sessions whose backend has yet to register;
            // an in-flight tear-down can return ObjectNotFound (handled
            // here) or transient bus errors that succeed on retry.  One
            // retry is enough — if openvpn3 still rejects the call the
            // session was probably already gone.
            if let Err(de) = self.client.session_disconnect(&session_path).await {
                warn!("cleanup session.Disconnect {session_path} failed: {de}; retrying once");
                if let Err(de2) = self.client.session_disconnect(&session_path).await {
                    warn!(
                        "cleanup session.Disconnect {session_path} failed twice ({de2}); leaving orphan session for openvpn3 to GC"
                    );
                }
            }
            let mut s = self.session.lock().await;
            s.config_path = None;
            s.session_path = None;
            s.current_data.clear();
            s.current_secrets.clear();
            return Err(e);
        }
        info!("session.Connect ok");

        // Attach the StatusChange listener so the activation FSM (and
        // any subsequent backend failure) reaches NM.  openvpn3-linux
        // historically unicasts StatusChange to subscribers that
        // existed *before* the backend client registered (the C tree
        // documented this as the reason it kept a polling watchdog
        // alongside the signal), so we run a polling loop in parallel
        // as the source of truth and treat the signal stream as a
        // bonus low-latency path when it works.
        //
        // Spawn under the session lock so a Disconnect arriving between
        // the first spawn and the tasks.push can't drop a fresh
        // listener on the floor (signal-driven listeners may otherwise
        // race state updates against an in-flight tear-down).
        {
            let mut s = self.session.lock().await;
            let h1 =
                self.spawn_status_listener(conn.clone(), session_path.clone(), ip4_emitted.clone());
            let h2 =
                self.spawn_status_poller(conn.clone(), session_path.clone(), ip4_emitted.clone());
            // Periodic statistics dump.
            let h3 = self.spawn_stats_timer(session_path.clone());
            // Plan 2: openvpn3 fires AttentionRequired whenever the
            // backend needs another credential slot filled (initial
            // password, dynamic challenge, 2FA code …).  We auto-
            // provide whatever is already in vpn.data/vpn.secrets and
            // ask NM (via SecretsRequired) for the rest.
            let h4 = self.spawn_attention_listener(conn.clone(), session_path);
            s.tasks.extend([h1, h2, h3, h4]);
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
            match self.client.session_access_grant(session_path, uid).await {
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
        ip4_emitted_shared: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let state = self.state.clone();
        tokio::spawn::<_>(async move {
            debug!("poller task started for {session_path}");
            let proxy = match client.session_proxy(&session_path).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("poller proxy build failed: {e}");
                    return;
                }
            };
            // Local mirror of the shared flag — once we've coordinated
            // the emit with the listener we treat ourselves as "past
            // Started" for our internal state machine (slow-tick mode,
            // budget reset, etc.).
            let mut ip4_emitted = false;
            let mut tick_interval = Duration::from_millis(500);
            let max_ticks_pre_started = 120; // 120 * 500ms = 60s
            let mut ticks = 0u32;
            // Consecutive post-STARTED status-read failures before we
            // declare the session lost.  A brief D-Bus blip (suspend/
            // resume, bus restart, openvpn3 daemon reload) can produce
            // one or two errors that recover on the next tick — only
            // fail NM if the session is *persistently* unreachable.
            let post_started_err_budget: u32 = 6; // ~30s at the 5s post-Started tick
            let mut post_started_errs: u32 = 0;
            loop {
                tokio::time::sleep(tick_interval).await;
                ticks += 1;
                // Hard cap on pre-Started polling.  Without this the
                // loop would sit happily on Ok(non-Started) status
                // forever if the backend gets wedged short of
                // CONNECTED — NM eventually trips its own activation
                // timeout and SIGKILLs us, but the poller would never
                // emit a clean Failure first.
                if !ip4_emitted && ticks >= max_ticks_pre_started {
                    warn!(
                        "session never reached Started within {ticks} polls ({}s); failing to NM",
                        (ticks as u64) * tick_interval.as_millis() as u64 / 1000
                    );
                    if let Ok(emitter) = make_emitter(&connection) {
                        set_state_via(&emitter, &state, NMVpnServiceState::Stopped).await;
                        let _ = emitter
                            .failure(NMVpnPluginFailure::ConnectFailed.as_u32())
                            .await;
                    }
                    break;
                }
                match proxy.status().await {
                    Ok((major, minor, _msg)) => {
                        post_started_errs = 0;
                        // Once we've reported Started to NM the poller
                        // is just a liveness watchdog — fold the every-
                        // 5s tick down to TRACE so the journal stays
                        // readable; only log at DEBUG during activation
                        // and on real status transitions.
                        if !ip4_emitted {
                            debug!("poll status: major={major} minor={minor}");
                        } else {
                            tracing::trace!("poll status: major={major} minor={minor}");
                        }
                        let status = Status::from_wire(major, minor);
                        let mut target = status.and_then(Status::to_nm_state);

                        // openvpn3-linux v27 does not always flip the
                        // session.status property to CONN_CONNECTED
                        // after the backend client transitions — the
                        // signal that would have triggered the update
                        // is unicast and the session manager misses
                        // it.  As a fallback, read device_name: it
                        // goes from "" to "tun*" exactly when the
                        // backend installs its tun device, which is
                        // the moment NM needs the Ip4Config.
                        if !ip4_emitted && target != Some(NMVpnServiceState::Stopped) {
                            match proxy.device_name().await {
                                Ok(dev) if dev.starts_with("tun") => {
                                    info!("device_name='{dev}' → treating as Started");
                                    target = Some(NMVpnServiceState::Started);
                                }
                                Ok(dev) => debug!("device_name='{dev}' (waiting for tun*)"),
                                Err(e) => warn!("device_name read failed: {e}"),
                            }
                        }

                        let Some(target) = target else { continue };
                        let Ok(emitter) = make_emitter(&connection) else {
                            continue;
                        };
                        match target {
                            NMVpnServiceState::Started if !ip4_emitted => {
                                // Race-safe handshake with
                                // spawn_status_listener.  If the
                                // listener already emitted, just slow
                                // down and stop probing — don't push a
                                // duplicate Config / Ip4Config pair to
                                // NM.
                                let we_emit = ip4_emitted_shared
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok();
                                if we_emit {
                                    if let Err(e) =
                                        crate::ip4::emit(&emitter, &client, &session_path).await
                                    {
                                        warn!("Ip4Config emit failed: {e:#}; failing to NM");
                                        ip4_emitted_shared.store(false, Ordering::Release);
                                        set_state_via(&emitter, &state, NMVpnServiceState::Stopped)
                                            .await;
                                        let _ = emitter
                                            .failure(NMVpnPluginFailure::BadIpConfig.as_u32())
                                            .await;
                                        break;
                                    }
                                    set_state_via(&emitter, &state, target).await;
                                } else {
                                    debug!(
                                        "poller: Started reached after listener emitted, switching to slow tick"
                                    );
                                }
                                ip4_emitted = true;
                                tick_interval = Duration::from_secs(5);
                                ticks = 0;
                            }
                            NMVpnServiceState::Stopped => {
                                set_state_via(&emitter, &state, target).await;
                                let reason = status.map_or(
                                    NMVpnPluginFailure::ConnectFailed,
                                    Status::failure_reason,
                                );
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
                        // Don't trip the failure path on the first
                        // hiccup — Plan-1c watchdogs the session, but
                        // brief D-Bus blips (suspend/resume, dbus
                        // reload) shouldn't kill the connection.
                        post_started_errs += 1;
                        if post_started_errs < post_started_err_budget {
                            warn!(
                                "status poll err ({e}); attempt {post_started_errs}/{post_started_err_budget}"
                            );
                            continue;
                        }
                        warn!(
                            "session unreachable for {post_started_errs} consecutive polls ({e}); failing to NM"
                        );
                        if let Ok(emitter) = make_emitter(&connection) {
                            set_state_via(&emitter, &state, NMVpnServiceState::Stopped).await;
                            let _ = emitter
                                .failure(NMVpnPluginFailure::ConnectFailed.as_u32())
                                .await;
                        }
                        break;
                    }
                    Err(e) => {
                        // Pre-Started: tolerate transient errors and
                        // let the loop-top timeout catch persistent
                        // ones.  Post-Started errors are handled by the
                        // `Err(e) if ip4_emitted` arm above.
                        warn!("status poll err (pre-Started): {e}");
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
    fn spawn_stats_timer(&self, session_path: OwnedObjectPath) -> tokio::task::JoinHandle<()> {
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

    /// Subscribe to the per-session `AttentionRequired` signal.  Each
    /// firing triggers a UserInputQueue drain; slots already present
    /// in vpn.data/vpn.secrets get auto-fed, the remainder are stashed
    /// for `new_secrets` and surfaced to NM via SecretsRequired.
    fn spawn_attention_listener(
        &self,
        connection: zbus::Connection,
        session_path: OwnedObjectPath,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let session_state = self.session.clone();
        tokio::spawn::<_>(async move {
            let proxy = match client.session_proxy(&session_path).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("AttentionRequired subscribe failed: {e}");
                    return;
                }
            };
            let mut stream = match proxy.receive_attention_required().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("receive_attention_required failed: {e}");
                    return;
                }
            };
            info!("AttentionRequired listener attached to {session_path}");
            while let Some(signal) = stream.next().await {
                let Ok(args) = signal.args() else { continue };
                let (t, g, msg) = (args.t, args.g, args.message);
                info!("AttentionRequired: type={t} group={g} msg='{msg}'");
                if let Err(e) =
                    handle_attention(&connection, &client, &session_path, &session_state, &msg)
                        .await
                {
                    warn!("AttentionRequired handler failed: {e:#}; failing to NM");
                    if let Ok(emitter) = make_emitter(&connection) {
                        let _ = emitter
                            .failure(NMVpnPluginFailure::LoginFailed.as_u32())
                            .await;
                    }
                    break;
                }
            }
            debug!("AttentionRequired listener exited for {session_path}");
        })
    }
}

/// Single firing of AttentionRequired: drain the input queue,
/// auto-provide what we already have, ask NM for the rest.
async fn handle_attention(
    connection: &zbus::Connection,
    client: &Client,
    session_path: &OwnedObjectPath,
    session_state: &Arc<Mutex<SessionState>>,
    msg: &str,
) -> anyhow::Result<()> {
    let slots = client.session_fetch_input_slots(session_path).await?;
    if slots.is_empty() {
        debug!("AttentionRequired: queue empty");
        return Ok(());
    }

    // Snapshot the stashed (data, secrets) so we don't hold the
    // session lock while talking to the backend.  Also verify the
    // session we're about to ProvideInput against is still the one the
    // plugin owns — a Disconnect can land between the signal stream
    // waking us and this point, leaving `session_path` stale and
    // ProvideInput racing an already-torn-down backend.
    let (data, secrets, still_owned) = {
        let s = session_state.lock().await;
        let owned = s.session_path.as_ref() == Some(session_path);
        (s.current_data.clone(), s.current_secrets.clone(), owned)
    };
    if !still_owned {
        debug!("AttentionRequired: session no longer owned by plugin (post-Disconnect); skipping");
        return Ok(());
    }

    let mut still_needed: Vec<InputSlot> = Vec::new();
    for slot in slots {
        let vkey = crate::secrets::slot_to_vpn_key(&slot);
        match crate::secrets::lookup_value(vkey, &data, &secrets) {
            Some(value) if !value.is_empty() => {
                match client
                    .session_provide_input(session_path, &slot, value)
                    .await
                {
                    Ok(()) => info!("auto-ProvideInput({})", slot.name),
                    Err(e) => {
                        // ProvideInput failed despite a value being on
                        // hand — re-queueing would loop (NM would
                        // prompt, we'd ProvideInput, it would fail,
                        // we'd ask NM again, …).  Surface this to NM
                        // as an auth failure so the user gets a real
                        // error instead of a hung dialog.
                        return Err(anyhow!(
                            "ProvideInput({}) failed with a persisted credential: {e}",
                            slot.name
                        ));
                    }
                }
            }
            _ => still_needed.push(slot),
        }
    }

    if still_needed.is_empty() {
        info!("AttentionRequired: all slots auto-provided");
        return Ok(());
    }

    // Stash the rest so new_secrets can pick them up.
    {
        let mut s = session_state.lock().await;
        s.pending_slots = still_needed.clone();
    }

    // Build hints in the order NM's auth-dialog expects: x-vpn-message
    // first (human prompt), then the vpn-secrets keys NM should ask
    // for.
    let mut hints: Vec<String> = Vec::with_capacity(still_needed.len() + 1);
    if !msg.is_empty() {
        hints.push(format!("x-vpn-message:{msg}"));
    }
    for slot in &still_needed {
        hints.push(crate::secrets::slot_to_vpn_key(slot).to_string());
    }
    let prompt = if msg.is_empty() {
        "OpenVPN 3 needs authentication".to_string()
    } else {
        msg.to_string()
    };
    let emitter = make_emitter(connection)?;
    emitter.secrets_required(prompt, hints).await?;
    Ok(())
}

/// Read /run/user and return the lowest non-zero UID present.  systemd
/// creates per-user runtime dirs there, so the lowest UID is almost
/// always the human session that triggered NM's activation.
fn lowest_run_user_uid() -> Option<u32> {
    let entries = std::fs::read_dir("/run/user").ok()?;
    let mut best: Option<u32> = None;
    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(uid) = name.parse::<u32>() else {
            continue;
        };
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
        info!("Connect dispatch entered");
        let r = self.do_connect(&emitter, conn, connection).await;
        match r {
            Ok(()) => {
                debug!("Connect dispatch returned Ok");
                Ok(())
            }
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
        details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        let _ = details;
        self.connect(emitter, conn, connection).await
    }

    async fn need_secrets(&self, connection: Settings) -> zbus::fdo::Result<String> {
        // Profile-file path needs no secrets up-front; openvpn3 may still
        // prompt via AttentionRequired after Connect (Plan 2 in C; not
        // ported yet).
        let _ = connection;
        Ok(String::new())
    }

    async fn disconnect(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        info!("Disconnect dispatched");
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
                warn!("session.Disconnect {path} failed: {e}; retrying once");
                if let Err(e2) = self.client.session_disconnect(path).await {
                    warn!("session.Disconnect {path} failed twice ({e2}); leaving orphan session");
                }
            }
        }
        self.set_state(&emitter, NMVpnServiceState::Stopped).await;
        // NM's contract: the plugin process exits after Disconnect
        // unless it was started with --persist.  Tickle main to drop
        // the bus name and return from the signal-wait loop.
        let _ = self.quit_tx.send(());
        Ok(())
    }

    /// NM delivers fresh credentials in response to the SecretsRequired
    /// signal we emitted from `handle_attention`.  Walk the slots we
    /// stashed, look each one up in the new vpn.secrets dict, and feed
    /// the values back to openvpn3 via ProvideInput.  Refreshes our
    /// settings snapshot so any subsequent AttentionRequired burst can
    /// auto-provide the credentials we just persisted.
    async fn new_secrets(&self, connection: Settings) -> zbus::fdo::Result<()> {
        let (data, secrets) = crate::secrets::split_vpn(&connection);
        drop(connection);

        let session_path;
        let pending;
        {
            let mut s = self.session.lock().await;
            s.current_data = data.clone();
            s.current_secrets = secrets.clone();
            session_path = s.session_path.clone();
            pending = std::mem::take(&mut s.pending_slots);
        }

        if pending.is_empty() {
            debug!("new_secrets: no pending slots");
            return Ok(());
        }
        let Some(path) = session_path else {
            warn!("new_secrets fired without an active session");
            return Ok(());
        };

        let mut sent = 0usize;
        let mut missing = 0usize;
        for slot in pending {
            let vkey = crate::secrets::slot_to_vpn_key(&slot);
            match crate::secrets::lookup_value(vkey, &data, &secrets) {
                Some(value) if !value.is_empty() => {
                    match self.client.session_provide_input(&path, &slot, value).await {
                        Ok(()) => {
                            info!("ProvideInput({}) ok", slot.name);
                            sent += 1;
                        }
                        Err(e) => {
                            warn!("ProvideInput({}) failed: {e}", slot.name);
                            missing += 1;
                        }
                    }
                }
                _ => {
                    debug!(
                        "new_secrets: slot '{}' has no value in vpn.{vkey}",
                        slot.name
                    );
                    missing += 1;
                }
            }
        }
        if missing > 0 {
            return Err(zbus::fdo::Error::Failed(format!(
                "could not provide {missing} authentication slot(s)"
            )));
        }
        debug!("new_secrets: provided {sent} slots");
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
