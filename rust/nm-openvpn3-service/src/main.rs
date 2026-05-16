//! nm-openvpn3-service — Rust port (Phase 1: skeleton).
//!
//! This binary is not wired to NetworkManager yet — that requires
//! exporting the `NMVpnServicePlugin` D-Bus contract, which lives in
//! Phase 2.  For now it verifies the toolchain + ovpn3-client crate
//! compile, opens the system bus, and sits on a GLib main loop so the
//! eventual NM activation hooks land in the right runtime.

use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "NetworkManager openvpn3 plugin service (Rust port)")]
struct Args {
    /// D-Bus bus name to claim (matches the C plugin's --bus-name flag).
    #[arg(long, default_value = "org.freedesktop.NetworkManager.openvpn3")]
    bus_name: String,

    /// Verbose tracing.  Maps to `RUST_LOG=debug` if RUST_LOG is unset.
    #[arg(long)]
    debug: bool,

    /// Stay running after the first session disconnects.  NM toggles
    /// this on for long-lived services; we honour it so behaviour
    /// matches the C plugin's --persist.
    #[arg(long)]
    persist: bool,
}

fn init_logging(debug: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(if debug { "debug" } else { "info" })
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_logging(args.debug);

    info!(
        "nm-openvpn3-service (rust {}) starting; bus_name={} persist={} debug={}",
        env!("CARGO_PKG_VERSION"),
        args.bus_name,
        args.persist,
        args.debug
    );

    let _client = ovpn3_client::Client::new()
        .await
        .context("opening system bus")?;
    info!("openvpn3 D-Bus client ready");

    // Phase 1 placeholder: sit on signals until killed.  Phase 2 will
    // replace this with the NMVpnServicePlugin D-Bus interface export +
    // the connect / disconnect dispatcher.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
        _ = sigint.recv() => info!("SIGINT received, shutting down"),
        // Cap the sit-here loop in case we're launched standalone — NM
        // would normally send SIGTERM on connection teardown.  Without a
        // bus-name claim there is no auto-activation contract to honour.
        _ = tokio::time::sleep(Duration::from_secs(60 * 60 * 24)) => {
            error!("idle timeout (24h) — exiting; Phase 2 will replace this with proper NM dispatch");
        }
    }

    Ok(())
}
