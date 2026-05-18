//! Retry wrapper for D-Bus calls against auto-activated openvpn3 daemons.
//!
//! The configuration / sessions managers are activated on first use, so
//! the very first call after `systemctl reload dbus` (or after they
//! exited idle) can race the bus daemon's activation step and surface
//! as `ServiceUnknown`, `NoReply`, `Timeout`, or `UnknownMethod ("Object
//! does not exist at path …")`.  This mirrors the
//! `dbus_call_with_retry()` helper in the C client.

use std::future::Future;
use std::time::Duration;

use tracing::debug;
use zbus::fdo;

/// Try the operation up to `attempts` times, sleeping `backoff` between
/// retries.  Returns the last error on permanent failure.
pub async fn with_transient_retry<F, Fut, T>(
    attempts: u32,
    backoff: Duration,
    mut op: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = zbus::Result<T>>,
{
    if attempts == 0 {
        return Err(anyhow::anyhow!(
            "with_transient_retry called with attempts=0; nothing tried"
        ));
    }
    let mut last_err: Option<zbus::Error> = None;
    for i in 0..attempts {
        match op().await {
            Ok(t) => return Ok(t),
            Err(e) => {
                if !is_transient(&e) {
                    return Err(anyhow::Error::from(e));
                }
                debug!("attempt {} hit transient error: {e}; retrying", i + 1);
                last_err = Some(e);
                if i + 1 < attempts {
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(anyhow::Error::from(
        last_err.expect("attempts > 0 guarantees we recorded an error"),
    ))
}

fn is_transient(e: &zbus::Error) -> bool {
    let Some(fdo_err) = fdo::Error::from(e.clone()).into() else {
        return false;
    };
    matches!(
        fdo_err,
        fdo::Error::ServiceUnknown(_)
            | fdo::Error::NoReply(_)
            | fdo::Error::Timeout(_)
            | fdo::Error::SpawnChildExited(_)
            | fdo::Error::Disconnected(_)
            | fdo::Error::UnknownObject(_)
    ) || matches!(&fdo_err, fdo::Error::UnknownMethod(msg)
        if msg.contains("Object does not exist at path"))
}
