//! nm-openvpn3-service — Rust port (Phase 3: signals + StatusChange).

mod build_profile;
mod connect_coord;
mod connection;
mod ip4;
mod plugin;
mod routes;
mod secrets;
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
    #[arg(long, default_value = "org.freedesktop.NetworkManager.openvpn3")]
    bus_name: String,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    persist: bool,
}

fn init_logging(debug: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if debug { "debug" } else { "info" }));
    // NM kills the binary on the 60 s activation timeout; if stderr
    // buffers messages they are lost.  Force the writer to flush on
    // every event so the journal sees diagnostics even when NM is
    // about to SIGKILL us.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_logging(args.debug);

    info!(
        "nm-openvpn3-service {} starting; bus_name={} persist={} debug={}",
        env!("CARGO_PKG_VERSION"),
        args.bus_name,
        args.persist,
        args.debug
    );

    let client = ovpn3_client::Client::new()
        .await
        .context("opening system bus")?;

    // Channel used by the Disconnect handler to signal main to exit
    // once the session is torn down — matches how the C plugin
    // self-exits after NM sends the final Disconnect RPC.
    let (quit_tx, mut quit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // NM dispatches VPN plugin RPCs over the system bus.  Register
    // the interface DURING build (serve_at + name + build in one
    // chain) so the very first method call NM sends has a handler
    // ready; otherwise zbus warns about lost messages and the first
    // Connect can race the .at() that comes after build.
    let plugin = plugin::Plugin::new(client, quit_tx, args.persist);
    let connection = zbus::connection::Builder::system()
        .context("zbus builder")?
        .serve_at(plugin::NM_VPN_PLUGIN_PATH, plugin)
        .context("registering Plugin on object server")?
        .name(args.bus_name.as_str())
        .context("requesting bus name")?
        .build()
        .await
        .with_context(|| format!("claiming bus name '{}'", args.bus_name))?;
    info!(
        "registered {} at {}",
        plugin::NM_VPN_PLUGIN_IFACE,
        plugin::NM_VPN_PLUGIN_PATH
    );

    // The zbus Connection must outlive every method call and signal
    // emission this process performs.  Dropping it releases the bus
    // name and tears down dispatch, so in-flight RPCs silently fail.
    // The leading underscore only suppresses the unused-variable lint;
    // it is NOT a hint that the value is safe to discard — the binding
    // must stay live until the select! below returns.
    let _connection_holder = connection;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
        _ = sigint.recv() => info!("SIGINT received, shutting down"),
        _ = quit_rx.recv() => info!("Disconnect dispatched, shutting down"),
    }

    Ok(())
}
