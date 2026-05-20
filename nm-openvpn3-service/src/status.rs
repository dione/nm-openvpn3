//! Typed wrapper for openvpn3-linux's `StatusChange (uus)` events.
//!
//! Wire format is `(major, minor, message)` of raw u32s.  Modelling the
//! pair as `Status::Connection(ConnectionMinor) | Status::Session(SessionMinor)`
//! buys two things:
//!
//! 1. `to_nm_state` becomes an exhaustive `match` — when openvpn3 grows
//!    a new minor value the compiler points at every site that needs to
//!    classify it.
//! 2. Failure-reason classification (Session auth-failed vs Connection
//!    transport-failed) lives next to the state mapping instead of
//!    leaking back to callers via raw-u32 equality on the major.
//!
//! Values cross-checked against openvpn3-linux v27
//! (`src/dbus/constants.hpp`).

use crate::state::{NMVpnPluginFailure, NMVpnServiceState};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusMajor {
    Connection = 2,
    Session = 3,
}

impl StatusMajor {
    const fn from_u32(v: u32) -> Option<Self> {
        match v {
            2 => Some(Self::Connection),
            3 => Some(Self::Session),
            _ => None,
        }
    }
}

/// StatusMinor values that fire with `StatusMajor::Connection`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMinor {
    Connecting = 6,
    Connected = 7,
    #[allow(dead_code)]
    Disconnecting = 8,
    Disconnected = 9,
    Failed = 10,
    AuthFailed = 11,
    Reconnecting = 12,
    /// `CONN_DONE` shows up post-CONNECTED on some openvpn3 builds;
    /// treat as "tunnel is up" same as Connected.
    Done = 16,
}

impl ConnectionMinor {
    const fn from_u32(v: u32) -> Option<Self> {
        match v {
            6 => Some(Self::Connecting),
            7 => Some(Self::Connected),
            8 => Some(Self::Disconnecting),
            9 => Some(Self::Disconnected),
            10 => Some(Self::Failed),
            11 => Some(Self::AuthFailed),
            12 => Some(Self::Reconnecting),
            16 => Some(Self::Done),
            _ => None,
        }
    }
}

/// StatusMinor values that fire with `StatusMajor::Session`.  Only the
/// subset we currently act on is enumerated; auth-prompt minors
/// (SESS_AUTH_USERPASS, SESS_AUTH_CHALLENGE) are intentionally absent —
/// those drive the AttentionRequired flow, not the state machine.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMinor {
    AuthFailed = 11,
}

impl SessionMinor {
    const fn from_u32(v: u32) -> Option<Self> {
        match v {
            11 => Some(Self::AuthFailed),
            _ => None,
        }
    }
}

/// A typed `(major, minor)` pair this service can act on.  `from_wire`
/// returns `None` for any pair the dispatcher should silently log and
/// move past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Connection(ConnectionMinor),
    Session(SessionMinor),
}

impl Status {
    pub const fn from_wire(major: u32, minor: u32) -> Option<Self> {
        match StatusMajor::from_u32(major) {
            Some(StatusMajor::Connection) => match ConnectionMinor::from_u32(minor) {
                Some(m) => Some(Self::Connection(m)),
                None => None,
            },
            Some(StatusMajor::Session) => match SessionMinor::from_u32(minor) {
                Some(m) => Some(Self::Session(m)),
                None => None,
            },
            None => None,
        }
    }

    /// Map the typed status to the NM-side service-state transition NM
    /// expects on `StateChanged`.  `None` means "no transition — log
    /// only".
    pub const fn to_nm_state(self) -> Option<NMVpnServiceState> {
        match self {
            Self::Connection(ConnectionMinor::Connecting | ConnectionMinor::Reconnecting) => {
                Some(NMVpnServiceState::Starting)
            }
            Self::Connection(ConnectionMinor::Connected | ConnectionMinor::Done) => {
                Some(NMVpnServiceState::Started)
            }
            Self::Connection(
                ConnectionMinor::Disconnected
                | ConnectionMinor::Failed
                | ConnectionMinor::AuthFailed,
            )
            | Self::Session(SessionMinor::AuthFailed) => Some(NMVpnServiceState::Stopped),
            Self::Connection(ConnectionMinor::Disconnecting) => None,
        }
    }

    /// Failure-reason NM should report alongside a Stopped transition.
    /// Auth-class failures (either major) → `LoginFailed`; everything
    /// else on the Stopped path is a transport/setup failure.
    pub const fn failure_reason(self) -> NMVpnPluginFailure {
        match self {
            Self::Connection(ConnectionMinor::AuthFailed)
            | Self::Session(SessionMinor::AuthFailed) => NMVpnPluginFailure::LoginFailed,
            _ => NMVpnPluginFailure::ConnectFailed,
        }
    }
}
