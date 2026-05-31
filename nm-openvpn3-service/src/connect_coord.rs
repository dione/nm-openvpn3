//! Connect ↔ Disconnect coordination.
//!
//! NM dispatches VPN-plugin RPCs concurrently (zbus runs each method
//! handler on its own task).  A naive Connect/Disconnect pair therefore
//! races: a Disconnect arriving while `do_connect` is still in its
//! await-heavy stretch (profile read, Import, NewTunnel) used to flip a
//! teardown flag held on the *per-session* state — which `do_connect`'s
//! later `mem::take` then discarded — and fire `quit_tx`.  `do_connect`
//! would resume, bring a tunnel up, and the process would exit leaving a
//! live, orphaned openvpn3 session that NM believed was torn down.
//!
//! This type encapsulates the fix so the protocol lives in one place and
//! can be unit-tested without standing up a D-Bus backend:
//!
//!   * `lock` — held for the WHOLE of both `do_connect` and `disconnect`,
//!     so the two can never interleave.  This is the correctness
//!     guarantee: even if a Disconnect misses the flag window below, it
//!     serialises *after* the Connect, observes the stashed session, and
//!     tears it down normally.
//!   * `teardown` — set by Disconnect *before* it contends for `lock`;
//!     checked by `do_connect` at each checkpoint so it bails (and tears
//!     down its half-built session) before bringing a tunnel up the user
//!     already asked to drop.  This is an optimisation layered on top of
//!     the lock — it avoids connecting-then-immediately-disconnecting in
//!     the common case; it is *not* relied on for correctness.
//!
//! `teardown` is owned here (on the long-lived `Plugin`), NOT on the
//! `SessionState` that `mem::take` replaces — that ownership is the crux
//! of the fix.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Mutex, MutexGuard};

#[derive(Default)]
pub(crate) struct ConnectCoordinator {
    lock: Mutex<()>,
    teardown: AtomicBool,
}

impl ConnectCoordinator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `connect()` entry — serialise Connect dispatch end-to-end.  Hold
    /// the returned guard for the whole of `do_connect`.
    pub(crate) async fn lock_connect(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().await
    }

    /// Called by `do_connect` once, just after the concurrent-Connect
    /// refusal gate: clear any stale teardown request.  Under `--persist`
    /// the process survives a Disconnect (which leaves the flag set), so
    /// a fresh Connect must reset it or it would bail at the first
    /// checkpoint.  Safe to call only while holding the connect guard.
    pub(crate) fn clear_teardown(&self) {
        self.teardown.store(false, Ordering::Release);
    }

    /// `do_connect` checkpoint — true if a Disconnect has requested
    /// teardown since this Connect began.
    pub(crate) fn teardown_requested(&self) -> bool {
        self.teardown.load(Ordering::Acquire)
    }

    /// `disconnect()` entry — flag teardown so an in-flight Connect bails
    /// at its next checkpoint, THEN take the lock so we serialise against
    /// `do_connect`.  Hold the returned guard for the whole teardown.
    pub(crate) async fn lock_disconnect(&self) -> MutexGuard<'_, ()> {
        // Order matters: set the flag BEFORE awaiting the lock.  An
        // in-flight do_connect holds the lock, so it sees this store at
        // its checkpoint while we block here; once it bails (or finishes)
        // and drops the guard, we acquire and run the authoritative
        // teardown.
        self.teardown.store(true, Ordering::Release);
        self.lock.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    /// A Disconnect arriving while a Connect is mid-flight must be
    /// observed at the Connect's checkpoint, so do_connect bails before
    /// bringing the tunnel up.  This is the optimisation path that
    /// prevents the connect-then-immediately-disconnect waste — and, more
    /// importantly, exercises the exact store/load the real fix relies on.
    #[tokio::test]
    async fn teardown_set_during_connect_is_seen_at_checkpoint() {
        let coord = Arc::new(ConnectCoordinator::new());

        let entered = Arc::new(Notify::new()); // connect signals it is "mid-flight"
        let release = Arc::new(Notify::new()); // test releases the simulated slow work
        let saw_teardown = Arc::new(AtomicBool::new(false));

        let connect = {
            let coord = coord.clone();
            let entered = entered.clone();
            let release = release.clone();
            let saw_teardown = saw_teardown.clone();
            tokio::spawn(async move {
                let _g = coord.lock_connect().await;
                coord.clear_teardown(); // fresh connect
                entered.notify_one();
                // Simulate the await-heavy NewTunnel/Import stretch.
                release.notified().await;
                // Checkpoint, as do_connect does before session.Connect.
                saw_teardown.store(coord.teardown_requested(), Ordering::SeqCst);
                // guard drops here
            })
        };

        // Wait until the Connect holds the lock and has cleared the flag.
        entered.notified().await;

        // Disconnect arrives now: it sets the flag, then blocks on the
        // lock the Connect still holds.
        let disconnect = {
            let coord = coord.clone();
            tokio::spawn(async move {
                let _g = coord.lock_disconnect().await;
            })
        };

        // Give the disconnect task a chance to run its synchronous store
        // and park on the lock.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Let the Connect reach its checkpoint.
        release.notify_one();
        connect.await.unwrap();
        disconnect.await.unwrap();

        assert!(
            saw_teardown.load(Ordering::SeqCst),
            "do_connect's checkpoint must observe the teardown requested mid-flight"
        );
    }

    /// The lock is the correctness guarantee: Disconnect's teardown body
    /// can never run concurrently with do_connect.  Even if a Disconnect
    /// misses the flag window, it must serialise strictly AFTER the
    /// in-flight Connect releases the lock.
    #[tokio::test]
    async fn disconnect_is_serialised_after_connect() {
        let coord = Arc::new(ConnectCoordinator::new());
        let order = Arc::new(AtomicUsize::new(0));
        let connect_released_at = Arc::new(AtomicUsize::new(0));
        let disconnect_entered_at = Arc::new(AtomicUsize::new(0));

        let entered = Arc::new(Notify::new());

        let connect = {
            let coord = coord.clone();
            let order = order.clone();
            let connect_released_at = connect_released_at.clone();
            let entered = entered.clone();
            tokio::spawn(async move {
                let g = coord.lock_connect().await;
                coord.clear_teardown();
                entered.notify_one();
                // Hold the lock across an await to force the disconnect to
                // wait.
                tokio::time::sleep(Duration::from_millis(30)).await;
                connect_released_at.store(order.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
                drop(g);
            })
        };

        entered.notified().await;

        let disconnect = {
            let coord = coord.clone();
            let order = order.clone();
            let disconnect_entered_at = disconnect_entered_at.clone();
            tokio::spawn(async move {
                let _g = coord.lock_disconnect().await;
                disconnect_entered_at.store(order.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
            })
        };

        connect.await.unwrap();
        disconnect.await.unwrap();

        assert!(
            connect_released_at.load(Ordering::SeqCst)
                < disconnect_entered_at.load(Ordering::SeqCst),
            "disconnect body must run only after connect releases the lock"
        );
    }

    /// Under `--persist` a prior Disconnect leaves the teardown flag set
    /// and the process alive.  A subsequent Connect must clear it, or it
    /// would bail immediately at its first checkpoint.
    #[tokio::test]
    async fn persist_reconnect_clears_stale_teardown() {
        let coord = ConnectCoordinator::new();

        // Simulate a completed Disconnect: flag set, lock released.
        {
            let _g = coord.lock_disconnect().await;
        }
        assert!(
            coord.teardown_requested(),
            "precondition: prior disconnect left the flag set"
        );

        // Fresh Connect (the --persist reconnect).
        let _g = coord.lock_connect().await;
        coord.clear_teardown();
        assert!(
            !coord.teardown_requested(),
            "a fresh connect must clear the stale teardown request"
        );
    }
}
