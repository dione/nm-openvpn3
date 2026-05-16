//! nm-openvpn3-service — Rust port (Phase 3: signals + StatusChange).

mod connection;
mod ip4;
mod plugin;
mod routes;
mod state;
mod status;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "NetworkManager openvpn3 plugin service (Rust port)")]
struct Args {
    #[arg(long, default_value = "org.freedesktop.NetworkManager.openvpn3rust")]
    bus_name: String,

    #[arg(long)]
    debug: bool,

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

    // Build the bus connection first so the Plugin can stash a clone
    // for background-task signal emission; register the interface
    // after the fact via object_server().at(...).
    let connection = zbus::connection::Builder::session()
        .context("zbus builder")?
        .name(args.bus_name.as_str())
        .context("requesting bus name")?
        .build()
        .await
        .with_context(|| format!("claiming bus name '{}'", args.bus_name))?;

    let plugin = plugin::Plugin::new(client, connection.clone());
    connection
        .object_server()
        .at(plugin::NM_VPN_PLUGIN_PATH, plugin)
        .await
        .context("registering Plugin on object server")?;
    info!(
        "registered {} at {}",
        plugin::NM_VPN_PLUGIN_IFACE,
        plugin::NM_VPN_PLUGIN_PATH
    );

    let _connection_holder = connection;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
        _ = sigint.recv() => info!("SIGINT received, shutting down"),
    }

    Ok(())
}
