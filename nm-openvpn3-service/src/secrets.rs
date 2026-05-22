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
use zeroize::Zeroizing;

// vpn.data / vpn.secrets keys — must match the C tree's
// `NM_OPENVPN3_KEY_*` macros from shared/nm-service-defines.h.
pub const KEY_USERNAME: &str = "username";
pub const KEY_PASSWORD: &str = "password";
pub const KEY_CERTPASS: &str = "cert-pass";
pub const KEY_HTTP_PROXY_USERNAME: &str = "http-proxy-username";
pub const KEY_HTTP_PROXY_PASSWORD: &str = "http-proxy-password";
pub const KEY_CHALLENGE_RESPONSE: &str = "challenge-response";

/// Heuristic map openvpn3 slot name → NM vpn key.  Mirrors C
/// `slot_name_to_vpn_key()`; unknown names fall back to PASSWORD so the
/// user still gets a generic prompt.  Both proxy slots map to their
/// dedicated keys — the username key lives in vpn.data per
/// `shared/nm-service-defines.h`, so [`lookup_value`] routes it
/// accordingly.
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
        KEY_HTTP_PROXY_USERNAME
    } else if n.contains("http_proxy_pass") {
        KEY_HTTP_PROXY_PASSWORD
    } else {
        KEY_PASSWORD
    }
}

/// Map of plaintext credentials whose values are scrubbed from memory
/// on drop (Zeroizing-wrapped Strings).  Username is non-secret, so the
/// `data` half is a plain HashMap; everything in `secrets` is wrapped.
pub type SecretsMap = HashMap<String, Zeroizing<String>>;

/// Read the value backing @vkey: usernames (regular + proxy) live in
/// vpn.data, every other secrets-style key in vpn.secrets.  Returns
/// `None` when unset.
pub fn lookup_value<'a>(
    vkey: &str,
    data: &'a HashMap<String, String>,
    secrets: &'a SecretsMap,
) -> Option<&'a str> {
    if vkey == KEY_USERNAME || vkey == KEY_HTTP_PROXY_USERNAME {
        data.get(vkey).map(String::as_str)
    } else {
        secrets.get(vkey).map(|z| z.as_str())
    }
}

/// Pull vpn.data and vpn.secrets sub-dicts out of a Connection
/// settings dictionary (the `a{sa{sv}}` NM hands us).  Either slot
/// missing → empty HashMap.  The secrets half is wrapped in `Zeroizing`
/// so credential bytes are scrubbed when the map is dropped.
pub fn split_vpn(
    settings: &HashMap<String, HashMap<String, OwnedValue>>,
) -> (HashMap<String, String>, SecretsMap) {
    let mut data = HashMap::new();
    let mut secrets: SecretsMap = HashMap::new();
    if let Some(vpn) = settings.get("vpn") {
        if let Some(inner) = vpn
            .get("data")
            .and_then(|v| flatten_str_map(v.try_clone().ok()?))
        {
            data = inner;
        }
        if let Some(inner) = vpn
            .get("secrets")
            .and_then(|v| flatten_str_map(v.try_clone().ok()?))
        {
            secrets = inner
                .into_iter()
                .map(|(k, v)| (k, Zeroizing::new(v)))
                .collect();
        }
    }
    (data, secrets)
}

fn flatten_str_map(v: OwnedValue) -> Option<HashMap<String, String>> {
    <HashMap<String, String>>::try_from(v).ok()
}
