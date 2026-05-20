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
