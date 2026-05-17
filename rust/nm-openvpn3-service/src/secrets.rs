//! Slot ↔ vpn.secrets mapping for the Plan 2 AttentionRequired flow.
//!
//! openvpn3 exposes its credential prompts via UserInputQueue slots
//! identified by free-form names ("username", "password",
//! "static_challenge", ...).  NM, on the other hand, persists secrets
//! under a fixed key set declared in `shared/nm-service-defines.h`.
//! These helpers translate between the two and look up persisted
//! values in the NMConnection settings dict.

use std::collections::HashMap;

use ovpn3_client::InputSlot;
use zbus::zvariant::OwnedValue;

// vpn.data / vpn.secrets keys — must match the C tree's
// `NM_OPENVPN3_KEY_*` macros from shared/nm-service-defines.h.
pub const KEY_USERNAME: &str = "username";
pub const KEY_PASSWORD: &str = "password";
pub const KEY_CERTPASS: &str = "cert-pass";
pub const KEY_HTTP_PROXY_PASSWORD: &str = "http-proxy-password";
pub const KEY_CHALLENGE_RESPONSE: &str = "challenge-response";

/// Heuristic map openvpn3 slot name → NM vpn-secrets key.  Mirrors C
/// `slot_name_to_vpn_key()`; unknown names fall back to PASSWORD so the
/// user still gets a generic prompt.
pub fn slot_to_vpn_key(slot: &InputSlot) -> &'static str {
    let n = slot.name.as_str();
    if n == "username" {
        KEY_USERNAME
    } else if n == "password" {
        KEY_PASSWORD
    } else if n.contains("challenge") || n.contains("response") {
        KEY_CHALLENGE_RESPONSE
    } else if n.contains("private_key") || n.contains("key_pass") {
        KEY_CERTPASS
    } else if n.contains("http_proxy_user") {
        // No first-class NM key for the proxy username — we surface it
        // through the proxy-password slot so NM still prompts.
        KEY_HTTP_PROXY_PASSWORD
    } else if n.contains("http_proxy_pass") {
        KEY_HTTP_PROXY_PASSWORD
    } else {
        KEY_PASSWORD
    }
}

/// Read the value backing @vkey: username lives in vpn.data, every
/// other secrets-style key in vpn.secrets.  Returns `None` when unset.
pub fn lookup_value<'a>(
    vkey: &str,
    data: &'a HashMap<String, String>,
    secrets: &'a HashMap<String, String>,
) -> Option<&'a str> {
    if vkey == KEY_USERNAME {
        data.get(KEY_USERNAME).map(String::as_str)
    } else {
        secrets.get(vkey).map(String::as_str)
    }
}

/// Pull vpn.data and vpn.secrets sub-dicts out of a Connection
/// settings dictionary (the `a{sa{sv}}` NM hands us).  Either slot
/// missing → empty HashMap.
pub fn split_vpn(
    settings: &HashMap<String, HashMap<String, OwnedValue>>,
) -> (HashMap<String, String>, HashMap<String, String>) {
    let mut data = HashMap::new();
    let mut secrets = HashMap::new();
    if let Some(vpn) = settings.get("vpn") {
        if let Some(inner) = vpn.get("data").and_then(|v| flatten_str_map(v.try_clone().ok()?)) {
            data = inner;
        }
        if let Some(inner) = vpn.get("secrets").and_then(|v| flatten_str_map(v.try_clone().ok()?)) {
            secrets = inner;
        }
    }
    (data, secrets)
}

fn flatten_str_map(v: OwnedValue) -> Option<HashMap<String, String>> {
    <HashMap<String, String>>::try_from(v).ok()
}
