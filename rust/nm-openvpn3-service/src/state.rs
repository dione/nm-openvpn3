//! NMVpnServiceState + NMVpnPluginFailure enums.
//!
//! The Phase 2 build only constructs a subset of these variants
//! directly; the rest exist because they are part of the libnm wire
//! contract that Phase 3 will exercise via signal emission.

#![allow(dead_code)]

//!
//! Values match libnm-core's `NMVpnConnectionState` / `NMVpnPluginFailure`
//! wire format so signal payloads round-trip with NM without translation.

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NMVpnServiceState {
    Unknown = 0,
    Init = 1,
    Shutdown = 2,
    Starting = 3,
    Started = 4,
    Stopping = 5,
    Stopped = 6,
}

impl NMVpnServiceState {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NMVpnPluginFailure {
    LoginFailed = 0,
    ConnectFailed = 1,
    BadIpConfig = 2,
}

impl NMVpnPluginFailure {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}
