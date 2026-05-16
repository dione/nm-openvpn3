//! Map openvpn3 StatusChange (major, minor) tuples onto NMVpnServiceState.
//!
//! Mirrors the C `ovpn3_status_to_nm_state()` helper plus the v0.5.13
//! signature change that dropped the unused NMVpnConnectionStateReason
//! out-param.

use crate::state::NMVpnServiceState;

// openvpn3-linux StatusMajor enum.
pub const OVPN3_MAJOR_CONNECTION: u32 = 2;
pub const OVPN3_MAJOR_SESSION: u32 = 3;

// MinorConnection subset we actually translate to NM service state.
pub const OVPN3_MINOR_CONN_CONNECTING: u32 = 2;
pub const OVPN3_MINOR_CONN_CONNECTED: u32 = 7;
pub const OVPN3_MINOR_CONN_DISCONNECTED: u32 = 8;
pub const OVPN3_MINOR_CONN_RECONNECTING: u32 = 9;

// MinorSession we care about (login failure).
pub const OVPN3_MINOR_SESS_AUTH_FAILED: u32 = 4;

/// Returns `Some(NMVpnServiceState)` for actionable events, `None` for
/// log-only transitions the dispatcher should ignore.
pub fn status_to_nm_state(major: u32, minor: u32) -> Option<NMVpnServiceState> {
    if major == OVPN3_MAJOR_CONNECTION {
        return Some(match minor {
            OVPN3_MINOR_CONN_CONNECTING | OVPN3_MINOR_CONN_RECONNECTING => {
                NMVpnServiceState::Starting
            }
            OVPN3_MINOR_CONN_CONNECTED => NMVpnServiceState::Started,
            OVPN3_MINOR_CONN_DISCONNECTED => NMVpnServiceState::Stopped,
            _ => return None,
        });
    }
    if major == OVPN3_MAJOR_SESSION && minor == OVPN3_MINOR_SESS_AUTH_FAILED {
        return Some(NMVpnServiceState::Stopped);
    }
    None
}
