//! Map openvpn3 StatusChange (major, minor) tuples onto NMVpnServiceState.
//!
//! Mirrors the C `ovpn3_status_to_nm_state()` helper plus the v0.5.13
//! signature change that dropped the unused NMVpnConnectionStateReason
//! out-param.

use crate::state::NMVpnServiceState;

// openvpn3-linux v27 StatusMajor enum (src/dbus/constants.hpp).
pub const OVPN3_MAJOR_CONNECTION: u32 = 2;
pub const OVPN3_MAJOR_SESSION: u32 = 3;

// v27 StatusMinor — every value advances by one because UNSET=0 takes
// the slot the older docs sometimes omit.  Cross-checked against
// `(uus) status = (2, 7, '')` introspected on a live session.
pub const OVPN3_MINOR_CONN_CONNECTING: u32 = 6;
pub const OVPN3_MINOR_CONN_CONNECTED: u32 = 7;
#[allow(dead_code)]
pub const OVPN3_MINOR_CONN_DISCONNECTING: u32 = 8;
pub const OVPN3_MINOR_CONN_DISCONNECTED: u32 = 9;
pub const OVPN3_MINOR_CONN_FAILED: u32 = 10;
pub const OVPN3_MINOR_CONN_AUTH_FAILED: u32 = 11;
pub const OVPN3_MINOR_CONN_RECONNECTING: u32 = 12;
pub const OVPN3_MINOR_CONN_DONE: u32 = 16;

// MinorSession we treat as terminal login failure.  v27 puts
// SESS_AUTH_USERPASS / SESS_AUTH_CHALLENGE here but those are inputs
// to the Plan 2 auth flow, not failures.
pub const OVPN3_MINOR_SESS_AUTH_FAILED: u32 = 11;

/// Returns `Some(NMVpnServiceState)` for actionable events, `None` for
/// log-only transitions the dispatcher should ignore.
pub fn status_to_nm_state(major: u32, minor: u32) -> Option<NMVpnServiceState> {
    if major == OVPN3_MAJOR_CONNECTION {
        return Some(match minor {
            OVPN3_MINOR_CONN_CONNECTING | OVPN3_MINOR_CONN_RECONNECTING => {
                NMVpnServiceState::Starting
            }
            // CONN_DONE shows up post-CONNECTED on some openvpn3
            // versions; treat both as "tunnel is up".
            OVPN3_MINOR_CONN_CONNECTED | OVPN3_MINOR_CONN_DONE => NMVpnServiceState::Started,
            OVPN3_MINOR_CONN_DISCONNECTED
            | OVPN3_MINOR_CONN_FAILED
            | OVPN3_MINOR_CONN_AUTH_FAILED => NMVpnServiceState::Stopped,
            _ => return None,
        });
    }
    if major == OVPN3_MAJOR_SESSION && minor == OVPN3_MINOR_SESS_AUTH_FAILED {
        return Some(NMVpnServiceState::Stopped);
    }
    None
}
