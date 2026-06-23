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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use futures_util::stream::StreamExt;
use ovpn3_client::Client;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, Instrument};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

use crate::connect_coord::ConnectCoordinator;
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
    /// Set when NM (or an internal failure path) initiates teardown.
    /// The StatusChange listener / poller check this before emitting a
    /// Failure on the openvpn3 `Disconnected` event so a user-requested
    /// Disconnect doesn't surface to NM as a spurious ConnectFailed.
    /// Per-session for the same reason as `ip4_emitted`.
    disconnect_requested: Arc<AtomicBool>,
    /// Per-session "a Failure has already been signalled" guard.  The
    /// StatusChange listener and the status poller both watch for the
    /// same terminal backend events; without this they each emit a
    /// Failure and NM receives two for one event.  Also lets the stats
    /// timer self-exit once the session has failed instead of polling a
    /// dead session until Disconnect.  Per-session like `ip4_emitted`.
    failure_emitted: Arc<AtomicBool>,
}

pub struct Plugin {
    client: Client,
    state: Arc<Mutex<NMVpnServiceState>>,
    session: Arc<Mutex<SessionState>>,
    /// Serialises Connect vs Disconnect and carries the mid-connect
    /// teardown request.  zbus runs method handlers concurrently; this
    /// coordinator's lock is held for the whole of both `do_connect` and
    /// `disconnect` so they can never interleave, and its teardown flag
    /// lets `do_connect` bail before bringing a tunnel up when a
    /// Disconnect has already arrived.  See [`ConnectCoordinator`] for the
    /// orphaned-tunnel failure mode it closes.
    coord: ConnectCoordinator,
    /// Fires when Disconnect runs (or activation hard-fails) so main
    /// can drop the bus name and exit — NM only sends SIGTERM if we
    /// hang, and without --persist the C plugin self-exits the same
    /// way.
    quit_tx: tokio::sync::mpsc::UnboundedSender<()>,
    /// `--persist`: keep the process alive across a Disconnect so NM can
    /// reuse it for the next activation (the stale-teardown reset in
    /// `do_connect`/`clear_teardown` exists precisely for this reuse).
    /// When false (the default) Disconnect tickles `quit_tx` and the
    /// process exits, matching NM's contract.
    persist: bool,
}

fn make_emitter(connection: &zbus::Connection) -> zbus::Result<SignalEmitter<'static>> {
    SignalEmitter::new(
        connection,
        ObjectPath::try_from(NM_VPN_PLUGIN_PATH)
            .expect("NM_VPN_PLUGIN_PATH must parse as ObjectPath"),
    )
}

/// Emit a Failure to NM at most once per session.  The StatusChange
/// listener and the status poller both watch for terminal states and
/// would otherwise each emit a Failure for the same backend event,
/// sending NM two signals for one failure.  The first to win the CAS
/// emits; the other becomes a no-op.  Ordering mirrors `ip4_emitted`:
/// AcqRel on success so the winner's prior state writes are published,
/// Acquire on failure so the loser observes them.
async fn emit_failure_once(
    emitter: &SignalEmitter<'_>,
    failure_emitted: &Arc<AtomicBool>,
    reason: NMVpnPluginFailure,
) {
    if failure_emitted
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let _ = emitter.failure(reason.as_u32()).await;
    } else {
        debug!("Failure already signalled for this session; suppressing duplicate");
    }
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
        persist: bool,
    ) -> Self {
        Self {
            client,
            state: Arc::new(Mutex::new(NMVpnServiceState::Init)),
            session: Arc::new(Mutex::new(SessionState::default())),
            coord: ConnectCoordinator::new(),
            quit_tx,
            persist,
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
        disconnect_requested: Arc<AtomicBool>,
        failure_emitted: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let state = self.state.clone();
        let span =
            tracing::info_span!("vpn-session", task = "status-listener", path = %session_path);
        tokio::spawn(
            async move {
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
                                debug!(
                                    "StatusChange: Started reached after poller emitted, skipping"
                                );
                                set_state_via(&emitter, &state, target).await;
                                continue;
                            }
                            if let Err(e) = crate::ip4::emit(&emitter, &client, &session_path).await
                            {
                                warn!("Ip4Config emit failed: {e:#}; failing to NM");
                                // Roll back the guard so a recovery path
                                // (status re-poll) can still retry once
                                // openvpn3 fixes its state.
                                ip4_emitted.store(false, Ordering::Release);
                                set_state_via(&emitter, &state, NMVpnServiceState::Stopped).await;
                                emit_failure_once(
                                    &emitter,
                                    &failure_emitted,
                                    NMVpnPluginFailure::BadIpConfig,
                                )
                                .await;
                                break;
                            }
                            set_state_via(&emitter, &state, target).await;
                        }
                        NMVpnServiceState::Stopped => {
                            set_state_via(&emitter, &state, target).await;
                            // Suppress the Failure signal when teardown was
                            // NM-initiated — otherwise a normal Disconnect
                            // races this Disconnected event and surfaces as
                            // a spurious ConnectFailed in NM's UI.
                            if !disconnect_requested.load(Ordering::Acquire) {
                                emit_failure_once(
                                    &emitter,
                                    &failure_emitted,
                                    status.failure_reason(),
                                )
                                .await;
                            }
                            break;
                        }
                        other => set_state_via(&emitter, &state, other).await,
                    }
                }
                debug!("StatusChange listener exited for {session_path}");
            }
            .instrument(span),
        )
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
        // Refuse a second Connect while a session is already live.  zbus
        // dispatches method calls concurrently, so two Connects could
        // otherwise race on self.session and orphan the loser's openvpn3
        // session.  The check is cheap and the common case (one Connect
        // per activation) is unaffected.
        {
            let s = self.session.lock().await;
            if s.session_path.is_some() {
                return Err(anyhow!(
                    "a session is already active; refusing concurrent Connect"
                ));
            }
        }

        // Clear any stale teardown request.  Under `--persist` the
        // process survives a Disconnect (which leaves the flag set), so a
        // fresh Connect must reset it or it would bail immediately at the
        // mid-connect check below.  We hold the connect guard here; a
        // concurrent Disconnect parks on the same lock, so the symmetric
        // lock still tears that session down afterwards even if its store
        // lands just before ours.
        self.coord.clear_teardown();

        // Fresh per-session emit guard.  Prior listeners (if any are
        // mid-emit during a fast Disconnect/Connect cycle) keep
        // referencing the previous Arc; this Connect's listeners get a
        // brand-new flag they alone can flip.
        let ip4_emitted = Arc::new(AtomicBool::new(false));
        let disconnect_requested = Arc::new(AtomicBool::new(false));
        let failure_emitted = Arc::new(AtomicBool::new(false));

        let data = vpn_data(&connection).context("parsing vpn.data")?;
        // Split secrets out early — build_profile may need them and we
        // want to stash the same Zeroizing'd map on session state below
        // either way.
        let (data_map, secret_map) = crate::secrets::split_vpn(&connection);

        // Resolve who to AccessGrant the session to, while we still hold
        // the connection dict.  Prefer NM's connection.permissions
        // (user:NAME) over the /run/user heuristic — the former is the
        // authoritative owner, the latter a guess that misfires on
        // multi-user / multi-seat hosts.
        let grant_uid = crate::connection::permission_users(&connection)
            .into_iter()
            .find_map(|u| username_to_uid(&u))
            .or_else(lowest_run_user_uid);

        // Two profile paths, matching the C tree's `build_profile_string`:
        //   1. `vpn.data['nm-openvpn3-profile']` set → read a verbatim
        //      .ovpn file off disk (preserves modern openvpn3 syntax the
        //      legacy exporter cannot reproduce — tls-crypt-v2,
        //      peer-fingerprint, etc.).
        //   2. Key absent → emit the .ovpn text from the settings dict
        //      via `build_profile::build_profile_string`.
        let profile = if let Some(profile_path) = data.get(KEY_PROFILE) {
            debug!("profile path: {profile_path}");
            let path_owned = profile_path.clone();
            // Open with O_NOFOLLOW so a symlink-swap between the stat
            // and the read can't redirect us into /etc/shadow or a
            // FIFO; then fstat the FD (no second namespace lookup) so
            // size + file-type checks operate on the same inode the
            // read will consume.
            let buf = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
                use std::io::Read;
                use std::os::unix::fs::OpenOptionsExt;
                // O_NONBLOCK so opening a FIFO (or any pipe-like special
                // file) returns immediately instead of blocking this
                // spawn_blocking thread forever waiting for a writer —
                // vpn.data is attacker-controllable, so the path could
                // name a named pipe.  The is_file() check below then
                // rejects it.  O_NONBLOCK has no effect on regular-file
                // reads, so the legitimate path is unchanged.
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(&path_owned)
                    .with_context(|| format!("opening profile file {path_owned}"))?;
                let md = file
                    .metadata()
                    .with_context(|| format!("fstat profile file {path_owned}"))?;
                if !md.is_file() {
                    return Err(anyhow!("profile path {path_owned} is not a regular file"));
                }
                if md.len() > MAX_PROFILE_BYTES {
                    return Err(anyhow!(
                        "profile {path_owned} is {} bytes; refusing (cap {MAX_PROFILE_BYTES})",
                        md.len()
                    ));
                }
                let cap = (md.len() as usize).saturating_add(1);
                let mut buf = String::with_capacity(cap);
                // read_to_string enforces UTF-8.  Cap the read at
                // MAX_PROFILE_BYTES+1 — a shrink-then-grow race can't
                // produce more bytes than the file's current size on
                // disk before EOF, but we still want a deterministic
                // ceiling.
                let mut limited = (&file).take(MAX_PROFILE_BYTES + 1);
                limited
                    .read_to_string(&mut buf)
                    .with_context(|| format!("reading profile file {path_owned}"))?;
                if buf.len() as u64 > MAX_PROFILE_BYTES {
                    return Err(anyhow!(
                        "profile {path_owned} grew past {MAX_PROFILE_BYTES} bytes during read"
                    ));
                }
                Ok(buf)
            })
            .await
            .context("profile-read task join")??;
            buf
        } else {
            debug!("no profile path; building config from vpn.data");
            crate::build_profile::build_profile_string(&data_map, &secret_map)
                .context("building profile from vpn.data")?
        };

        self.set_state(emitter, NMVpnServiceState::Starting).await;

        // openvpn3 config name, in preference order:
        //   1. vpn.data['connection-name'] — explicit override, if a
        //      profile ever wants to decouple the two.
        //   2. connection.id — NM's user-facing name (`nmcli up NAME`),
        //      so `openvpn3 sessions-list` matches what the user typed.
        //   3. static fallback when neither is present.
        let id = data
            .get("connection-name")
            .cloned()
            .or_else(|| crate::connection::connection_id(&connection))
            .unwrap_or_else(|| "nm-openvpn3-rust".to_string());

        // Early teardown check, BEFORE we create anything at the backend.
        // import_config / new_tunnel are remote calls that can be slow (or
        // hang) against openvpn3; since Disconnect now parks on the connect
        // lock for our whole duration, bailing here keeps it responsive in
        // the common "Disconnect during a slow connect" case.  No session
        // exists yet, so there is nothing to clean up.
        if self.coord.teardown_requested() {
            return Err(anyhow!("disconnect requested during Connect (pre-import)"));
        }

        debug!("importing config '{id}' ({} bytes)", profile.len());
        let config_path = self
            .client
            .import_config(&id, &profile, true)
            .await
            .context("Import")?;
        debug!("config path: {config_path}");

        self.apply_overrides(&config_path, &data).await;

        let session_path = match self.client.new_tunnel(&config_path).await {
            Ok(p) => p,
            Err(e) => {
                // NewTunnel failed: the single_use config we imported above
                // was never consumed by a backend (no Fetch), so openvpn3
                // won't auto-GC it.  Remove it before returning or it
                // orphans in `openvpn3 configs-list`, one per failed
                // activation as NM retries (pass-6 M6).  config_path isn't
                // stashed on the session yet, so this local is the only
                // handle to it.  Safe even on the lost-reply edge (NewTunnel
                // ran server-side but the reply was lost): we are failing
                // the activation regardless, so removing the config can't
                // corrupt a connection we are keeping.
                self.remove_config(&config_path).await;
                return Err(e.context("NewTunnel"));
            }
        };
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
            s.disconnect_requested = disconnect_requested.clone();
            s.failure_emitted = failure_emitted.clone();
        }

        // A Disconnect that arrived while we were mid-connect parks on the
        // connect lock (which we hold) after setting the teardown flag.
        // Honour it now — before we wait on / Connect the session — so we
        // tear the freshly-created backend session down instead of
        // bringing a tunnel up the user already asked to drop.  The
        // session_path is stashed above, so the Disconnect that follows
        // (once we release the connect lock) sees an empty session and the
        // cleanup here is the authoritative teardown.
        if self.coord.teardown_requested() {
            warn!("teardown requested during Connect; tearing down {session_path}");
            self.cleanup_session(&session_path).await;
            return Err(anyhow!("disconnect requested during Connect"));
        }

        // Wait for the session manager to publish the session, then
        // subscribe to the StatusChange + AttentionRequired signals
        // BEFORE session.Connect runs.  Without this the backend can
        // race us to CONNECTED and the first transition fires before
        // our subscription is live — we'd then wait up to the 500 ms
        // polling tick for the device_name fallback to spot the tun
        // device, and DNS shows up that much later in NM.  Matches the
        // C tree's commit "subscribe StatusChange signal to cut
        // activation latency".
        if let Err(e) = self
            .client
            .session_wait_ready(&session_path, Duration::from_secs(5))
            .await
            .context("waiting for session")
        {
            // wait_ready failed → no listeners to clean up yet.
            warn!("session_wait_ready failed; tearing down {session_path}");
            self.cleanup_session(&session_path).await;
            return Err(e);
        }
        {
            let mut s = self.session.lock().await;
            let h1 = self.spawn_status_listener(
                conn.clone(),
                session_path.clone(),
                ip4_emitted.clone(),
                disconnect_requested.clone(),
                failure_emitted.clone(),
            );
            let h2 = self.spawn_attention_listener(
                conn.clone(),
                session_path.clone(),
                disconnect_requested.clone(),
                failure_emitted.clone(),
            );
            s.tasks.extend([h1, h2]);
        }
        self.grant_access(&session_path, grant_uid).await;

        // Final checkpoint before we actually bring the tunnel up: a
        // Disconnect could have arrived during the up-to-5s
        // session_wait_ready above (it is parked on the connect lock).
        // Catching it here means we tear the session down instead of
        // completing session.Connect — cleanup_session also aborts the
        // listeners spawned just above.
        if self.coord.teardown_requested() {
            warn!("teardown requested before session.Connect; tearing down {session_path}");
            self.cleanup_session(&session_path).await;
            return Err(anyhow!("disconnect requested during Connect"));
        }

        if let Err(e) = self
            .client
            .session_connect(&session_path)
            .await
            .context("session.Connect")
        {
            warn!("session.Connect failed; tearing down {session_path}");
            // Listeners spawned above hold session_path Arcs and exit
            // on the Disconnect path; cleanup_session below aborts
            // their handles via SessionState::tasks.
            self.cleanup_session(&session_path).await;
            return Err(e);
        }
        info!("session.Connect ok");

        // Now arm the poller (fallback for missed signals) and stats
        // timer.  Both are post-Connect because they only watch for
        // state we explicitly drove.
        {
            let mut s = self.session.lock().await;
            let h3 = self.spawn_status_poller(
                conn.clone(),
                session_path.clone(),
                ip4_emitted.clone(),
                disconnect_requested.clone(),
                failure_emitted.clone(),
            );
            let h4 = self.spawn_stats_timer(session_path, failure_emitted.clone());
            s.tasks.extend([h3, h4]);
        }

        info!("Connect dispatched; backend handshake in progress");
        Ok(())
    }

    /// Abort all spawned tasks for the current session, clear cached
    /// state, and best-effort tear down the openvpn3 session.  Used by
    /// the activation-failure paths so a half-attached listener can't
    /// keep referencing a dead session.
    async fn cleanup_session(&self, session_path: &OwnedObjectPath) {
        // Abort the background tasks AND clear the cached state under a
        // single lock acquisition: splitting them around the D-Bus
        // disconnect call below would leave a window where a concurrent
        // Connect (--persist) or Disconnect observes aborted tasks with
        // session_path still set — a half-cleaned session.  The
        // disconnect itself runs on the local path argument afterwards,
        // same pattern `disconnect()` uses (mem::take, then act on
        // locals).
        let config_path = {
            let mut s = self.session.lock().await;
            s.disconnect_requested.store(true, Ordering::Release);
            for h in s.tasks.drain(..) {
                h.abort();
            }
            let config_path = s.config_path.take();
            s.session_path = None;
            s.current_data.clear();
            s.current_secrets.clear();
            config_path
        };
        // openvpn3 drops sessions whose backend has yet to register;
        // an in-flight tear-down can return ObjectNotFound or a
        // transient bus error.  One retry is enough.
        if let Err(de) = self.client.session_disconnect(session_path).await {
            warn!("cleanup session.Disconnect {session_path} failed: {de}; retrying once");
            if let Err(de2) = self.client.session_disconnect(session_path).await {
                warn!(
                    "cleanup session.Disconnect {session_path} failed twice ({de2}); leaving orphan session for openvpn3 to GC"
                );
            }
        }
        // Drop the imported config too: cleanup_session runs on
        // activation-failure paths where the backend may never have
        // Fetched the single_use config, so openvpn3 won't auto-GC it
        // (pass-6 M6).  Best-effort — already-gone is benign.
        if let Some(cp) = config_path {
            self.remove_config(&cp).await;
        }
    }

    /// Best-effort removal of an imported openvpn3 config object.  Used on
    /// activation-failure / teardown paths to drop a `single_use` config
    /// the backend may never have Fetched (openvpn3 only auto-GCs such a
    /// config once a backend Fetches it).  An already-removed config
    /// yields a benign error we log at debug and ignore.
    async fn remove_config(&self, config_path: &OwnedObjectPath) {
        if let Err(e) = self.client.config_remove(config_path).await {
            debug!("config Remove {config_path} failed (likely already gone): {e}");
        }
    }

    /// Grant the activating user per-property access to the openvpn3
    /// session via AccessGrant, so their `openvpn3 sessions-list` CLI
    /// can see and manage it.
    ///
    /// `public_access` is deliberately NOT set: it would open session
    /// management (Disconnect, statistics) to *every* local UID, which
    /// is over-broad on multi-user systems.  A single targeted
    /// AccessGrant to the owning UID is sufficient and far tighter.
    /// The UID comes from NM's `connection.permissions` when present,
    /// falling back to the `/run/user` heuristic only for system-wide
    /// connections that carry no permissions.
    async fn grant_access(&self, session_path: &OwnedObjectPath, uid: Option<u32>) {
        match uid {
            Some(uid) => match self.client.session_access_grant(session_path, uid).await {
                Ok(()) => info!("AccessGrant uid={uid} ok"),
                Err(e) => warn!("AccessGrant uid={uid} failed: {e}"),
            },
            None => warn!(
                "no activating UID resolved (no connection.permissions, no /run/user); \
                 session left owner-only — `openvpn3 sessions-list` won't show it to the user"
            ),
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
        disconnect_requested: Arc<AtomicBool>,
        failure_emitted: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let state = self.state.clone();
        let span = tracing::info_span!("vpn-session", task = "poller", path = %session_path);
        tokio::spawn(async move {
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
            // 100 * 500ms = 50s — deliberately under NM's own 60s
            // activation timeout so our clean Failure signal reaches NM
            // before it SIGKILLs the service (which would make the
            // Failure unreachable and surface as a generic timeout).
            let max_ticks_pre_started = 100;
            let mut ticks = 0u32;
            // Consecutive post-STARTED status-read failures before we
            // declare the session lost.  A brief D-Bus blip (suspend/
            // resume, bus restart, openvpn3 daemon reload) can produce
            // one or two errors that recover on the next tick — only
            // fail NM if the session is *persistently* unreachable.
            let post_started_err_budget: u32 = 6; // ~30s at the 5s post-Started tick
            let mut post_started_errs: u32 = 0;
            // Poll immediately on entry — the signal listener spawned
            // alongside us may already have missed a CONNECTED event
            // from a fast handshake (cached creds, instant tunnel).
            // Subsequent iterations sleep first per the cadence below.
            let mut first_pass = true;
            // Last status openvpn3 reported + last device_name seen,
            // surfaced in the pre-Started timeout warning below so a
            // "never reached Started" failure shows what the backend was
            // actually reporting and whether a tun device ever appeared —
            // distinguishes a plugin-side bug from the openvpn3 backend
            // simply never connecting (server/network/netcfg).
            let mut last_major = 0u32;
            let mut last_minor = 0u32;
            let mut last_device = String::new();
            loop {
                if !first_pass {
                    tokio::time::sleep(tick_interval).await;
                }
                first_pass = false;
                ticks += 1;
                // Hard cap on pre-Started polling.  Without this the
                // loop would sit happily on Ok(non-Started) status
                // forever if the backend gets wedged short of
                // CONNECTED — NM eventually trips its own activation
                // timeout and SIGKILLs us, but the poller would never
                // emit a clean Failure first.
                if !ip4_emitted && ticks >= max_ticks_pre_started {
                    warn!(
                        "session never reached Started within {ticks} polls ({}s); \
                         last openvpn3 status major={last_major} minor={last_minor}, \
                         device_name={last_device:?}; failing to NM",
                        (ticks as u64) * tick_interval.as_millis() as u64 / 1000
                    );
                    if let Ok(emitter) = make_emitter(&connection) {
                        set_state_via(&emitter, &state, NMVpnServiceState::Stopped).await;
                        emit_failure_once(
                            &emitter,
                            &failure_emitted,
                            NMVpnPluginFailure::ConnectFailed,
                        )
                        .await;
                    }
                    break;
                }
                match proxy.status().await {
                    Ok((major, minor, _msg)) => {
                        post_started_errs = 0;
                        last_major = major;
                        last_minor = minor;
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
                                Ok(dev) => {
                                    last_device = dev.clone();
                                    if dev.starts_with("tun") {
                                        info!("device_name='{dev}' → treating as Started");
                                        target = Some(NMVpnServiceState::Started);
                                    } else {
                                        debug!("device_name='{dev}' (waiting for tun*)");
                                    }
                                }
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
                                        emit_failure_once(
                                            &emitter,
                                            &failure_emitted,
                                            NMVpnPluginFailure::BadIpConfig,
                                        )
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
                                // See spawn_status_listener — don't fire
                                // Failure for an NM-initiated teardown.
                                if !disconnect_requested.load(Ordering::Acquire) {
                                    let reason = status.map_or(
                                        NMVpnPluginFailure::ConnectFailed,
                                        Status::failure_reason,
                                    );
                                    emit_failure_once(&emitter, &failure_emitted, reason).await;
                                }
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
                            emit_failure_once(
                                &emitter,
                                &failure_emitted,
                                NMVpnPluginFailure::ConnectFailed,
                            )
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
        }.instrument(span))
    }

    /// Periodic openvpn3 session.statistics fetch, logged at INFO so
    /// `journalctl -t nm-openvpn3-rust-service | grep stats` shows
    /// live throughput.  Mirrors `stats_timer_cb` in the C tree (with
    /// the v0.5.11 TUN_BYTES_* addition).
    fn spawn_stats_timer(
        &self,
        session_path: OwnedObjectPath,
        failure_emitted: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let span = tracing::info_span!("vpn-session", task = "stats", path = %session_path);
        tokio::spawn(
            async move {
                let mut last_bytes_in: i64 = 0;
                let mut last_bytes_out: i64 = 0;
                let mut last_tick = std::time::Instant::now();
                let mut first = true;
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    // A poller/listener failure path may have already
                    // signalled Failure to NM and broken out.  Disconnect
                    // normally aborts this handle, but if NM hasn't sent
                    // it yet there's no point polling stats off a dead
                    // session — self-exit instead of looping forever.
                    if failure_emitted.load(Ordering::Acquire) {
                        debug!("stats timer exiting — session already failed");
                        break;
                    }
                    let stats = match client.session_get_statistics(&session_path).await {
                        Ok(s) => s,
                        Err(e) => {
                            // A single failed read is usually a transient
                            // D-Bus blip (suspend/resume, daemon reload) —
                            // don't kill the timer over it or throughput
                            // logging stays dead for the rest of the
                            // session.  The poller owns real liveness; this
                            // task just skips a tick.  When the session is
                            // actually gone the poller fails to NM and
                            // Disconnect aborts this handle.
                            debug!("stats fetch failed: {e}; skipping tick");
                            continue;
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
                        let dt = now.duration_since(last_tick).as_secs_f64();
                        let rate_rx = byte_rate(last_bytes_in, bin, dt);
                        let rate_tx = byte_rate(last_bytes_out, bout, dt);
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
            }
            .instrument(span),
        )
    }

    /// Subscribe to the per-session `AttentionRequired` signal.  Each
    /// firing triggers a UserInputQueue drain; slots already present
    /// in vpn.data/vpn.secrets get auto-fed, the remainder are stashed
    /// for `new_secrets` and surfaced to NM via SecretsRequired.
    fn spawn_attention_listener(
        &self,
        connection: zbus::Connection,
        session_path: OwnedObjectPath,
        disconnect_requested: Arc<AtomicBool>,
        failure_emitted: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let session_state = self.session.clone();
        let span = tracing::info_span!("vpn-session", task = "attention", path = %session_path);
        tokio::spawn(
            async move {
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
                        // Suppress the Failure when teardown is in progress
                        // — a Disconnect racing an in-flight ProvideInput
                        // makes the call fail against the dead session, and
                        // surfacing that as a LoginFailed would be a
                        // spurious ConnectFailed for a deliberate disconnect
                        // (the disconnect handler owns the Stopped sequence).
                        if disconnect_requested.load(Ordering::Acquire) {
                            debug!(
                                "AttentionRequired handler failed during teardown ({e:#}); \
                                 suppressing Failure"
                            );
                        } else {
                            // Route through emit_failure_once so this path
                            // is CAS-gated like the listener/poller (R5):
                            // without it the attention path emitted a raw
                            // Failure, NM could receive a second from a
                            // sibling, and the failure_emitted flag stayed
                            // clear so the stats timer kept polling a dead
                            // session (pass-6 M1).
                            warn!("AttentionRequired handler failed: {e:#}; failing to NM");
                            if let Ok(emitter) = make_emitter(&connection) {
                                emit_failure_once(
                                    &emitter,
                                    &failure_emitted,
                                    NMVpnPluginFailure::LoginFailed,
                                )
                                .await;
                            }
                        }
                        break;
                    }
                }
                debug!("AttentionRequired listener exited for {session_path}");
            }
            .instrument(span),
        )
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

/// Resolve a username to its UID via the system passwd database
/// (`getpwnam_r`).  Returns `None` for an unknown user or on any libc
/// error.  Used to turn NM's `connection.permissions` (`user:NAME`)
/// into the UID we AccessGrant the openvpn3 session to.
fn username_to_uid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam_r writes into the caller-provided passwd struct +
    // scratch buffer; we pass valid pointers and a buffer sized from the
    // libc-suggested minimum (fallback 4 KiB).  `result` is set to NULL
    // when no entry matches, which we treat as "unknown user".
    unsafe {
        let mut bufsize = match libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) {
            n if n > 0 => n as usize,
            _ => 4096,
        };
        loop {
            let mut buf = vec![0u8; bufsize];
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            );
            if rc == 0 && !result.is_null() {
                return Some(pwd.pw_uid);
            }
            // POSIX: ERANGE means the scratch buffer was too small for
            // this passwd entry (long GECOS/shell), NOT "unknown user" —
            // retry with a doubled buffer instead of silently skipping
            // the AccessGrant for a perfectly valid user.
            if rc == libc::ERANGE && bufsize < (1 << 20) {
                bufsize *= 2;
                continue;
            }
            return None;
        }
    }
}

/// Read /run/user and return the lowest non-zero UID present.  systemd
/// creates per-user runtime dirs there, so the lowest UID is almost
/// always the human session that triggered NM's activation.  Fallback
/// only — `connection.permissions` is preferred when present.
fn lowest_run_user_uid() -> Option<u32> {
    std::fs::read_dir("/run/user")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .filter(|&uid| uid != 0)
        .min()
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
        let _connect_guard = self.coord.lock_connect().await;
        let r = self.do_connect(&emitter, conn, connection).await;
        match r {
            Ok(()) => {
                debug!("Connect dispatch returned Ok");
                Ok(())
            }
            Err(e) => {
                // When do_connect bailed because a Disconnect arrived
                // mid-connect, this is NOT an activation failure — the
                // user asked to drop the connection.  The Disconnect
                // handler owns the Stopped → quit sequence, so suppress
                // the Failure/StateChanged emit here to avoid surfacing a
                // spurious ConnectFailed to NM for a deliberate disconnect.
                // Still return an error reply so the Connect method itself
                // reflects that it did not complete.
                if self.coord.teardown_requested() {
                    info!(
                        "Connect aborted by Disconnect; deferring teardown to disconnect handler"
                    );
                    return Err(zbus::fdo::Error::Failed(
                        "connect aborted by disconnect".to_string(),
                    ));
                }
                // Full chain (incl. backend / openvpn3 detail) goes to the
                // service log only.  Return a generic message to the D-Bus
                // caller so backend internals aren't disclosed across the
                // bus; NM already learns the failure class via the Failure
                // signal emitted just below.
                warn!("Connect failed: {e:#}");
                self.set_state(&emitter, NMVpnServiceState::Stopped).await;
                let _ = emitter
                    .failure(crate::state::NMVpnPluginFailure::ConnectFailed.as_u32())
                    .await;
                Err(zbus::fdo::Error::Failed(
                    "VPN activation failed; see the nm-openvpn3 service log for details"
                        .to_string(),
                ))
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
        // Flag teardown so an in-flight Connect bails at its next
        // checkpoint, then take the connect lock to serialise against
        // do_connect — zbus dispatches method handlers concurrently, and
        // without this a Disconnect interleaving do_connect's await window
        // left a live tunnel up after the process exited.  Both steps live
        // in `lock_disconnect`.
        let _connect_guard = self.coord.lock_disconnect().await;
        let session = {
            let mut s = self.session.lock().await;
            // Flag teardown BEFORE taking the session so the background
            // tasks (which hold their own Arc clone of this flag) see it
            // and suppress the Failure signal on the openvpn3
            // `Disconnected` event this Disconnect triggers.
            s.disconnect_requested.store(true, Ordering::Release);
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
        // Drop the imported config.  For an established session the backend
        // already Fetched-and-removed the single_use config (Remove is then
        // a benign no-op); for a Disconnect that raced the backend's first
        // fetch this is what reclaims it (pass-6 M6).
        if let Some(cp) = session.config_path.as_ref() {
            self.remove_config(cp).await;
        }
        self.set_state(&emitter, NMVpnServiceState::Stopped).await;
        // NM's contract: the plugin process exits after Disconnect
        // unless it was started with --persist.  Under --persist we keep
        // the process alive for NM to reuse on the next Connect (the
        // session was just torn down above, so state is clean and a
        // fresh Connect's clear_teardown resets the coordinator flag).
        if self.persist {
            info!("Disconnect complete; --persist set, staying alive for reuse");
        } else {
            // Tickle main to drop the bus name and return from the
            // signal-wait loop.
            let _ = self.quit_tx.send(());
        }
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
            session_path = s.session_path.clone();
            // Only refresh the credential snapshot while a session is
            // live — the refresh exists so a subsequent AttentionRequired
            // burst can auto-provide.  With no session there is nothing to
            // feed, so stashing plaintext secrets would just keep them in
            // memory longer than necessary.
            if session_path.is_some() {
                s.current_data = data.clone();
                s.current_secrets = secrets.clone();
            }
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
            // A Disconnect can race new_secrets (they don't share the
            // connect lock).  Check the teardown flag BEFORE each
            // ProvideInput, not only in its error path — otherwise the
            // first slot of a batch can land on a half-torn-down
            // session and earlier slots' errors are misattributed.
            if self.coord.teardown_requested() {
                debug!("new_secrets: teardown in progress; dropping remaining slots");
                return Ok(());
            }
            let vkey = crate::secrets::slot_to_vpn_key(&slot);
            match crate::secrets::lookup_value(vkey, &data, &secrets) {
                Some(value) if !value.is_empty() => {
                    match self.client.session_provide_input(&path, &slot, value).await {
                        Ok(()) => {
                            info!("ProvideInput({}) ok", slot.name);
                            sent += 1;
                        }
                        Err(e) => {
                            // A Disconnect can race new_secrets (they don't
                            // share the connect lock): lock_disconnect sets
                            // the teardown flag before mem::take'ing the
                            // session, so ProvideInput against the now-dead
                            // session fails.  Don't surface that as a
                            // spurious auth failure for a deliberate
                            // disconnect — the disconnect handler owns the
                            // Stopped sequence.
                            if self.coord.teardown_requested() {
                                debug!(
                                    "new_secrets: ProvideInput({}) failed during teardown; ignoring",
                                    slot.name
                                );
                                return Ok(());
                            }
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

/// Per-tick throughput from two cumulative byte counters.  openvpn3
/// counters reset to 0 on a daemon reload / session resume, so a naive
/// `cur - prev` goes negative and renders as a wildly negative
/// throughput; clamp the delta at 0 across a reset instead.
fn byte_rate(prev: i64, cur: i64, dt_secs: f64) -> i64 {
    (cur.saturating_sub(prev).max(0) as f64 / dt_secs.max(1e-3)) as i64
}

#[cfg(test)]
mod tests {
    use super::byte_rate;

    #[test]
    fn byte_rate_normal_delta() {
        assert_eq!(byte_rate(0, 3000, 30.0), 100);
        assert_eq!(byte_rate(1000, 1000, 30.0), 0);
    }

    #[test]
    fn byte_rate_counter_reset_clamps_to_zero() {
        // openvpn3 reset: counter drops from 1 MB back toward 0 — the
        // rate must clamp to 0 (unknowable across a reset), not report
        // i64::MIN-ish garbage.
        assert_eq!(byte_rate(1_000_000, 0, 30.0), 0);
        assert_eq!(byte_rate(1_000_000, 500, 30.0), 0);
    }

    #[test]
    fn byte_rate_zero_dt_does_not_divide_by_zero() {
        let r = byte_rate(0, 1000, 0.0);
        assert!(r > 0, "dt clamped to a small epsilon, got {r}");
    }
}
