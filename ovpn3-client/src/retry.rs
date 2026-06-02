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

/// Activation-only retry — only the errors the bus daemon itself
/// generates BEFORE the call reaches openvpn3 are considered transient.
/// Use this for stateful operations (Import, NewTunnel) where a
/// NoReply or Disconnect can mean the call already took effect on the
/// other side and a blind retry would create a duplicate config /
/// session object.
pub async fn with_activation_retry<F, Fut, T>(
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
            "with_activation_retry called with attempts=0; nothing tried"
        ));
    }
    let mut last_err: Option<zbus::Error> = None;
    for i in 0..attempts {
        match op().await {
            Ok(t) => return Ok(t),
            Err(e) => {
                if !is_pre_dispatch_transient(&e) {
                    return Err(anyhow::Error::from(e));
                }
                debug!(
                    "activation attempt {} hit pre-dispatch error: {e}; retrying",
                    i + 1
                );
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

/// Errors that arise BEFORE the destination method handler runs — safe
/// to retry for stateful operations because the receiver never saw the
/// message, so no side-effect can have leaked through:
///
///   * `ServiceUnknown` — bus daemon doesn't know the service name yet.
///   * `SpawnChildExited` — bus-activation child died before owning the
///     name.
///   * `UnknownObject` — service is alive, but the object path the
///     call targets isn't registered yet (openvpn3-linux config /
///     sessions managers register their objects a few ms after the
///     service claims its bus name on cold start).
///   * `UnknownMethod ("Object does not exist at path …")` — same
///     thing, openvpn3 raises this variant on some builds when the
///     object exists in the manifest but the live registration hasn't
///     happened yet.
///
/// Deliberately excluded: `NoReply`, `Timeout`, `Disconnected` — those
/// can mean the call already executed on the receiver and the reply
/// was lost in transit, so a blind retry would leave a duplicate
/// config / session object behind.
fn is_pre_dispatch_transient(e: &zbus::Error) -> bool {
    let fdo_err = fdo::Error::from(e.clone());
    matches!(
        fdo_err,
        fdo::Error::ServiceUnknown(_)
            | fdo::Error::SpawnChildExited(_)
            | fdo::Error::UnknownObject(_)
    ) || matches!(&fdo_err, fdo::Error::UnknownMethod(msg)
        if msg.contains("Object does not exist at path"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the openvpn3-linux cold-start race: the
    /// configuration-manager registers its object path a few ms after
    /// it claims the bus name.  The first Import call after a cold
    /// boot can hit `UnknownObject` or `UnknownMethod ("Object does
    /// not exist at path …")` even though the service is alive.  Both
    /// MUST be retried by `with_activation_retry` so the user's first
    /// `nmcli connection up` doesn't surface a raw D-Bus error.
    #[test]
    fn cold_start_object_not_yet_registered_is_pre_dispatch() {
        let unknown_object =
            zbus::Error::from(fdo::Error::UnknownObject("no such object".to_string()));
        assert!(
            is_pre_dispatch_transient(&unknown_object),
            "UnknownObject must be retried (config manager cold-start race)"
        );

        let unknown_method = zbus::Error::from(fdo::Error::UnknownMethod(
            "Object does not exist at path /net/openvpn/v3/configuration".to_string(),
        ));
        assert!(
            is_pre_dispatch_transient(&unknown_method),
            "UnknownMethod with 'Object does not exist at path' must be retried"
        );

        let service_unknown = zbus::Error::from(fdo::Error::ServiceUnknown(
            "net.openvpn.v3.configuration".to_string(),
        ));
        assert!(is_pre_dispatch_transient(&service_unknown));
    }

    /// Stateful retries must NOT cover errors that can mean the call
    /// already executed on the other side.  Retrying NoReply / Timeout
    /// / Disconnected on Import would leave an orphan config object.
    #[test]
    fn ambiguous_failures_are_not_pre_dispatch() {
        let no_reply = zbus::Error::from(fdo::Error::NoReply("timeout".to_string()));
        assert!(!is_pre_dispatch_transient(&no_reply));

        let timeout = zbus::Error::from(fdo::Error::Timeout("hung".to_string()));
        assert!(!is_pre_dispatch_transient(&timeout));

        let disconnected = zbus::Error::from(fdo::Error::Disconnected("bus".to_string()));
        assert!(!is_pre_dispatch_transient(&disconnected));
    }

    /// An unrelated UnknownMethod (e.g. "Method 'Foo' not implemented")
    /// is a permanent error and must NOT be retried.
    #[test]
    fn unknown_method_without_object_marker_is_permanent() {
        let no_such_method = zbus::Error::from(fdo::Error::UnknownMethod(
            "Method 'Foo' not implemented".to_string(),
        ));
        assert!(!is_pre_dispatch_transient(&no_such_method));
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// attempts=0 is a programmer error: return the guard error WITHOUT
    /// ever invoking `op`.
    #[tokio::test]
    async fn attempts_zero_never_calls_op() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let r: anyhow::Result<()> = with_activation_retry(0, Duration::ZERO, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// An ambiguous (non-pre-dispatch) error must NOT be retried — one
    /// op call, then surface it.  Retrying NoReply on a stateful Import
    /// would risk a duplicate config object.
    #[tokio::test]
    async fn permanent_error_not_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let r: anyhow::Result<()> = with_activation_retry(3, Duration::ZERO, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err(zbus::Error::from(fdo::Error::NoReply("x".into()))) }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "NoReply is ambiguous; must not retry"
        );
    }

    /// A pre-dispatch transient error is retried exactly `attempts`
    /// times, then the last error surfaces.
    #[tokio::test]
    async fn transient_retried_then_last_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let r: anyhow::Result<()> = with_activation_retry(3, Duration::ZERO, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err(zbus::Error::from(fdo::Error::ServiceUnknown("svc".into()))) }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// A transient-then-success sequence returns Ok and stops early.
    #[tokio::test]
    async fn transient_then_success_stops_early() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let r: anyhow::Result<u8> = with_activation_retry(5, Duration::ZERO, || {
            let n = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(zbus::Error::from(fdo::Error::UnknownObject("o".into())))
                } else {
                    Ok(7u8)
                }
            }
        })
        .await;
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
