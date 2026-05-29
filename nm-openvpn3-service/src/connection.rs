//! Helpers for the `a{sa{sv}}` NMConnection dictionaries that NM passes
//! to `Connect` / `ConnectInteractive` / `NeedSecrets` / `NewSecrets`.

use std::collections::HashMap;

use anyhow::{bail, Context};
use zbus::zvariant::OwnedValue;

pub type Settings = HashMap<String, HashMap<String, OwnedValue>>;

/// Extract the `vpn` settings group and return its `data` sub-dict
/// (`a{ss}`-shaped — keys and values are strings even though the wire
/// representation uses variant values).
pub fn vpn_data(settings: &Settings) -> anyhow::Result<HashMap<String, String>> {
    let vpn = settings
        .get("vpn")
        .context("missing 'vpn' settings group")?;
    let raw = vpn.get("data").context("missing vpn.data dict")?;
    string_string_dict(raw)
}

/// Same shape, but pulled from the `secrets` field.  Returns an empty
/// map (not an error) when the connection has no secrets attached.
/// Plan 2 (auth) consumer; Phase 2 does not call it yet.
#[allow(dead_code)]
pub fn vpn_secrets(settings: &Settings) -> anyhow::Result<HashMap<String, String>> {
    let Some(vpn) = settings.get("vpn") else {
        return Ok(HashMap::new());
    };
    match vpn.get("secrets") {
        None => Ok(HashMap::new()),
        Some(raw) => string_string_dict(raw),
    }
}

/// Pull the usernames out of the connection's `connection.permissions`
/// (`as` of `user:NAME[:...]`).  NM records which local user a
/// connection belongs to here, so this is the authoritative source for
/// who to AccessGrant the openvpn3 session to — far better than guessing
/// from `/run/user`.  Returns an empty vec when the connection is
/// system-wide (no permissions) or the field is malformed.
pub fn permission_users(settings: &Settings) -> Vec<String> {
    let Some(conn) = settings.get("connection") else {
        return Vec::new();
    };
    let Some(raw) = conn.get("permissions") else {
        return Vec::new();
    };
    let Ok(entries) = Vec::<String>::try_from(raw.clone()) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|e| {
            // Format is "user:NAME[:reserved]"; take the NAME field.
            let rest = e.strip_prefix("user:")?;
            let name = rest.split(':').next().unwrap_or("");
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// Pull the connection's display name from `connection.id`.  NM stores
/// the user-facing connection name (the one `nmcli connection up NAME`
/// uses) here; the VPN `vpn.data` hash does not carry it, so this is the
/// only place the plugin can recover it for use as the openvpn3 config
/// name.  Returns `None` when the group/key is absent or not a string.
pub fn connection_id(settings: &Settings) -> Option<String> {
    let raw = settings.get("connection")?.get("id")?;
    String::try_from(raw.clone()).ok().filter(|s| !s.is_empty())
}

fn string_string_dict(value: &OwnedValue) -> anyhow::Result<HashMap<String, String>> {
    // The wire type is a{ss} but NM wraps it as a variant inside the
    // outer a{sv} settings dict.  zbus surfaces that as OwnedValue;
    // try the typed conversion first, fall back to the dict form for
    // older NM versions that send a{sv}.
    if let Ok(map) = HashMap::<String, String>::try_from(value.clone()) {
        return Ok(map);
    }
    if let Ok(map) = HashMap::<String, OwnedValue>::try_from(value.clone()) {
        let mut out = HashMap::with_capacity(map.len());
        for (k, v) in map {
            let s = match String::try_from(v.clone()) {
                Ok(s) => s,
                Err(_) => bail!("vpn settings value for '{k}' is not a string"),
            };
            out.insert(k, s);
        }
        return Ok(out);
    }
    bail!("vpn settings entry is not a string→string dict");
}
