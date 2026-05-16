//! nm-openvpn3-service — Rust port (Phase 2: NMVpnPlugin wired).

mod connection;
mod plugin;
mod state;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "NetworkManager openvpn3 plugin service (Rust port)")]
struct Args {
    /// D-Bus bus name to claim.  NM passes this via the `program=` line
    /// in the plugin's .name file; the default matches the side-by-side
    /// Rust .name we install, so the C tree's claim is undisturbed.
    #[arg(long, default_value = "org.freedesktop.NetworkManager.openvpn3rust")]
    bus_name: String,

    /// Verbose tracing (RUST_LOG=debug if RUST_LOG is unset).
    #[arg(long)]
    debug: bool,

    /// Stay running after the first session disconnects (NM contract).
    #[arg(long)]
    persist: bool,
}

fn init_logging(debug: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if debug { "debug" } else { "info" }));
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

    let client = ovpn3_client::Client::new()
        .await
        .context("opening system bus")?;

    let plugin = plugin::Plugin::new(client);

    let connection = zbus::connection::Builder::session()
        .context("zbus builder")?
        .name(args.bus_name.as_str())
        .context("requesting bus name")?
        .serve_at(plugin::NM_VPN_PLUGIN_PATH, plugin)
        .context("registering Plugin at NM_VPN_PLUGIN_PATH")?
        .build()
        .await
        .with_context(|| format!("claiming bus name '{}'", args.bus_name))?;
    info!(
        "registered {} at {}",
        plugin::NM_VPN_PLUGIN_IFACE,
        plugin::NM_VPN_PLUGIN_PATH
    );

    // Hold the connection alive — dropping it tears down the bus claim.
    let _connection_holder = connection;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
        _ = sigint.recv() => info!("SIGINT received, shutting down"),
    }

    if !args.persist {
        info!("exiting (--persist not set)");
    } else {
        error!("--persist requested but Phase 2 still exits on signal");
    }

    Ok(())
}
