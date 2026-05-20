//! Build the SetConfig + SetIp4Config payloads NM expects after a
//! successful STARTED transition.
//!
//! Mirrors the C `emit_started_ip4_config()` helper from
//! `src/nm-openvpn3-service.c`.  Each `a{sv}` entry uses the
//! `NM_VPN_PLUGIN_CONFIG_*` / `NM_VPN_PLUGIN_IP4_CONFIG_*` key set
//! defined in libnm-core (see `nm-vpn-service-plugin.h`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use if_addrs::{IfAddr, Ifv4Addr};
use ovpn3_client::Client;
use tracing::{debug, warn};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{Array, OwnedValue, Type, Value};

// Trait synthesized by zbus' `#[interface]` macro on `Plugin`; carries
// the signal-emit helpers (`vpn_config`, `ip4_config`, `failure`, ...)
// that get dispatched against `SignalEmitter` below.
use crate::plugin::PluginSignals;
use crate::routes::{self, Route};

// libnm-core NM_VPN_PLUGIN_CONFIG_* keys
const NM_KEY_CONFIG_TUNDEV: &str = "tundev";
const NM_KEY_CONFIG_EXT_GATEWAY: &str = "gateway";
const NM_KEY_CONFIG_HAS_IP4: &str = "has-ip4";
const NM_KEY_CONFIG_HAS_IP6: &str = "has-ip6";
const NM_KEY_CONFIG_CAN_PERSIST: &str = "can-persist";

// libnm-core NM_VPN_PLUGIN_IP4_CONFIG_* keys
const NM_KEY_IP4_TUNDEV: &str = "tundev";
const NM_KEY_IP4_ADDRESS: &str = "address";
const NM_KEY_IP4_PREFIX: &str = "prefix";
const NM_KEY_IP4_INT_GATEWAY: &str = "internal-gateway";
const NM_KEY_IP4_PRESERVE_ROUTES: &str = "preserve-routes";
const NM_KEY_IP4_NEVER_DEFAULT: &str = "never-default";
const NM_KEY_IP4_DNS: &str = "dns";
const NM_KEY_IP4_DOMAINS: &str = "domains";
const NM_KEY_IP4_ROUTES: &str = "routes";

/// Look up the IPv4 address + prefix openvpn3's netcfg installed on
/// the tun device.  Returns `None` if the device is missing or not v4.
fn lookup_tun_ipv4(tundev: &str) -> Option<(u32, u32)> {
    let addrs = if_addrs::get_if_addrs().ok()?;
    for ifa in addrs {
        if ifa.name != tundev {
            continue;
        }
        if let IfAddr::V4(Ifv4Addr { ip, netmask, .. }) = ifa.addr {
            let addr_be: u32 = u32::from(ip).to_be();
            let mask_he: u32 = u32::from(netmask);
            let prefix = mask_he.count_ones();
            return Some((addr_be, prefix));
        }
    }
    None
}

/// Build the routes array NM consumes (`aau` of `[dest, prefix, next, metric]`).
fn build_routes_array(routes: &[Route], addr_be: u32, prefix: u32) -> Result<OwnedValue> {
    let mut emitted: Vec<Value<'static>> = Vec::with_capacity(routes.len());
    let mask_be = if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        0xFFFF_FFFFu32
    } else {
        (0xFFFF_FFFFu32 << (32 - prefix)).to_be()
    };
    for r in routes {
        // Skip the auto on-link route for the tun's own subnet — NM
        // derives it from ADDRESS/PREFIX.
        if r.prefix == prefix && (r.dest_be & mask_be) == (addr_be & mask_be) && r.next_hop_be == 0
        {
            continue;
        }
        let row: Vec<Value<'static>> = vec![
            Value::U32(r.dest_be),
            Value::U32(r.prefix),
            Value::U32(r.next_hop_be),
            Value::U32(r.metric),
        ];
        let mut row_arr = Array::new(<u32 as Type>::SIGNATURE);
        for v in row {
            row_arr.append(v).map_err(|e| anyhow!("route push: {e}"))?;
        }
        emitted.push(Value::Array(row_arr));
    }
    let sig = zbus::zvariant::Signature::try_from("au").expect("\"au\" is a valid D-Bus signature");
    let mut outer = Array::new(&sig);
    for row in emitted {
        outer.append(row).map_err(|e| anyhow!("routes push: {e}"))?;
    }
    Ok(OwnedValue::try_from(Value::Array(outer))?)
}

/// Convert dotted-quad strings (whatever openvpn3 netcfg hands us) to
/// the `u32 BE` form NM expects in its DNS array.
fn dns_strings_to_array(servers: &[String]) -> Result<OwnedValue> {
    let mut arr = Array::new(<u32 as Type>::SIGNATURE);
    for s in servers {
        match s.parse::<Ipv4Addr>() {
            Ok(a) => arr
                .append(Value::U32(u32::from(a).to_be()))
                .map_err(|e| anyhow!("dns push: {e}"))?,
            Err(_) => debug!("DNS skip non-IPv4 entry '{s}'"),
        }
    }
    Ok(OwnedValue::try_from(Value::Array(arr))?)
}

/// Build the search-domain array NM expects (`as`).
fn search_to_array(domains: &[String]) -> Result<OwnedValue> {
    let mut arr = Array::new(<String as Type>::SIGNATURE);
    for d in domains {
        arr.append(Value::Str(d.as_str().into()))
            .map_err(|e| anyhow!("search push: {e}"))?;
    }
    Ok(OwnedValue::try_from(Value::Array(arr))?)
}

fn owned_u32(v: u32) -> OwnedValue {
    OwnedValue::try_from(Value::U32(v)).expect("u32 into OwnedValue is infallible")
}

fn owned_bool(v: bool) -> OwnedValue {
    OwnedValue::try_from(Value::Bool(v)).expect("bool into OwnedValue is infallible")
}

fn owned_str(v: &str) -> OwnedValue {
    OwnedValue::try_from(Value::Str(v.into())).expect("str into OwnedValue is infallible")
}

/// Build the SetConfig + SetIp4Config dictionaries and emit both
/// signals.  Called from the StatusChange listener when the backend
/// reaches CONNECTED.
pub async fn emit(
    emitter: &SignalEmitter<'_>,
    client: &Client,
    session_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<()> {
    let tundev = client
        .session_get_device_name(session_path)
        .await
        .map_err(|e| anyhow!("session.device_name read failed: {e}"))?;
    if tundev.is_empty() {
        return Err(anyhow!(
            "session reported empty device_name; cannot build Ip4Config"
        ));
    }
    debug!("STARTED: device='{tundev}'");

    let (addr_be, prefix) = lookup_tun_ipv4(&tundev).ok_or_else(|| {
        anyhow!("tun device '{tundev}' has no IPv4 address; aborting Ip4Config emit")
    })?;
    let have_ip = true;

    // NM rejects the SetConfig payload with "no VPN gateway address
    // received" if `gateway` is missing or 0, so we always try hard to
    // produce an IPv4 here — parse first (cheap path), then fall back
    // to a synchronous DNS lookup against the FQDN.
    let connected = client
        .session_get_connected_to(session_path)
        .await
        .ok()
        .flatten();
    debug!("last_connection={connected:?}");
    let ext_gw_be = match connected.as_ref() {
        Some((_, host, _)) if !host.is_empty() => match host.parse::<Ipv4Addr>() {
            Ok(ip) => u32::from(ip).to_be(),
            Err(_) => {
                // Bound the async resolver so a slow / hung DNS server
                // can't outlast NM's activation timeout.  tokio's
                // lookup_host runs the resolution on the blocking
                // pool, so the timeout cancels the *wait*, not the
                // outstanding getaddrinfo call.
                let host_port = format!("{host}:0");
                let lookup = tokio::net::lookup_host(host_port.as_str());
                let resolved = tokio::time::timeout(Duration::from_secs(5), lookup).await;
                match resolved {
                    Ok(Ok(mut it)) => it
                        .find_map(|sa| match sa.ip() {
                            std::net::IpAddr::V4(v4) => Some(u32::from(v4).to_be()),
                            _ => None,
                        })
                        .unwrap_or_else(|| {
                            warn!("VPN gateway host '{host}' resolved but had no IPv4 record");
                            0
                        }),
                    Ok(Err(e)) => {
                        warn!("VPN gateway host '{host}' resolve failed: {e}");
                        0
                    }
                    Err(_) => {
                        warn!("VPN gateway host '{host}' resolve timed out after 5s");
                        0
                    }
                }
            }
        },
        _ => 0,
    };
    if ext_gw_be == 0 {
        return Err(anyhow!(
            "could not produce an IPv4 gateway for the SetConfig payload \
             (last_connection={connected:?}); NM would reject this as \
             'no VPN gateway address received'"
        ));
    }

    let dev_path = client.session_get_device_path(session_path).await.ok();
    let (dns_servers, dns_search) = match dev_path {
        Some(ref p) => {
            let servers = client.netcfg_get_dns_servers(p).await.unwrap_or_else(|e| {
                warn!("netcfg dns_name_servers read failed: {e}; emitting empty list");
                Vec::new()
            });
            let search = client.netcfg_get_dns_search(p).await.unwrap_or_else(|e| {
                warn!("netcfg dns_search_domains read failed: {e}; emitting empty list");
                Vec::new()
            });
            (servers, search)
        }
        None => {
            warn!("session has no device_path; skipping DNS push to NM");
            (Vec::new(), Vec::new())
        }
    };

    let routes = routes::for_tun_device(&tundev);
    let has_default = routes::has_default_route(&routes);

    // SetConfig dictionary.
    let mut cfg: HashMap<String, OwnedValue> = HashMap::new();
    cfg.insert(NM_KEY_CONFIG_TUNDEV.into(), owned_str(&tundev));
    cfg.insert(NM_KEY_CONFIG_EXT_GATEWAY.into(), owned_u32(ext_gw_be));
    cfg.insert(NM_KEY_CONFIG_HAS_IP4.into(), owned_bool(have_ip));
    cfg.insert(NM_KEY_CONFIG_HAS_IP6.into(), owned_bool(false));
    cfg.insert(NM_KEY_CONFIG_CAN_PERSIST.into(), owned_bool(false));
    emitter.vpn_config(cfg).await?;

    // SetIp4Config dictionary.
    let mut ip4: HashMap<String, OwnedValue> = HashMap::new();
    ip4.insert(NM_KEY_IP4_TUNDEV.into(), owned_str(&tundev));
    ip4.insert(NM_KEY_IP4_ADDRESS.into(), owned_u32(addr_be));
    ip4.insert(NM_KEY_IP4_PREFIX.into(), owned_u32(prefix));
    ip4.insert(NM_KEY_IP4_INT_GATEWAY.into(), owned_u32(0));
    ip4.insert(NM_KEY_IP4_PRESERVE_ROUTES.into(), owned_bool(true));
    if !dns_servers.is_empty() {
        ip4.insert(NM_KEY_IP4_DNS.into(), dns_strings_to_array(&dns_servers)?);
    }
    if !dns_search.is_empty() {
        ip4.insert(NM_KEY_IP4_DOMAINS.into(), search_to_array(&dns_search)?);
    }
    if !has_default {
        ip4.insert(NM_KEY_IP4_NEVER_DEFAULT.into(), owned_bool(true));
        debug!("split-tunnel: emit never-default=TRUE (no 0.0.0.0/0 on tun)");
    }
    if !routes.is_empty() {
        ip4.insert(
            NM_KEY_IP4_ROUTES.into(),
            build_routes_array(&routes, addr_be, prefix)?,
        );
    }
    emitter.ip4_config(ip4).await?;
    debug!(
        "emitted Ip4Config (have_ip={have_ip}, routes={}, never_default={})",
        routes.len(),
        !has_default
    );
    Ok(())
}
