//! `/proc/net/route` parser used by the Ip4Config emitter.
//!
//! Mirrors the C `ovpn3_read_proc_routes()` helper.  Each row in the
//! procfs file has hex-encoded little-endian dotted-quads in
//! `sin_addr.s_addr` order on a little-endian host, which is exactly
//! the `u32 BE` shape NM wants in its
//! `NM_VPN_PLUGIN_IP4_CONFIG_ROUTES` payload — so no byte-order
//! conversion is needed (the file already prints what `inet_pton`
//! would store).

use std::fs;

#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Destination network address, big-endian (`sin_addr.s_addr` shape).
    pub dest_be: u32,
    /// Prefix length derived from the row's Mask column.
    pub prefix: u32,
    /// Next-hop / gateway, big-endian; 0 for on-link routes.  Read but
    /// not currently emitted to NM (netcfg owns the route table — see
    /// `ip4::emit`).
    #[allow(dead_code)]
    pub next_hop_be: u32,
    /// Metric column.  Same caveat as `next_hop_be`.
    #[allow(dead_code)]
    pub metric: u32,
}

/// Read `/proc/net/route` and return rows whose Iface matches `tundev`.
/// Logs a warning and returns an empty vec if the file is missing
/// (no routes to emit yet).
pub fn for_tun_device(tundev: &str) -> Vec<Route> {
    let raw = match fs::read_to_string("/proc/net/route") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("/proc/net/route unreadable: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if i == 0 {
            continue; // header row
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 11 {
            continue;
        }
        if cols[0] != tundev {
            continue;
        }
        let Ok(dest_be) = u32::from_str_radix(cols[1], 16) else {
            continue;
        };
        let Ok(next_hop_be) = u32::from_str_radix(cols[2], 16) else {
            continue;
        };
        let Ok(metric) = cols[6].parse::<u32>() else {
            continue;
        };
        let Ok(mask_be) = u32::from_str_radix(cols[7], 16) else {
            continue;
        };
        // popcount is byte-order-agnostic.
        let prefix = mask_be.count_ones();
        out.push(Route {
            dest_be,
            prefix,
            next_hop_be,
            metric,
        });
    }
    out
}

/// True when the route table for `tundev` contains a 0.0.0.0/0 entry —
/// indicates the profile expects a full-tunnel default route.  The C
/// tree uses this to drive `NEVER_DEFAULT=TRUE` when absent.
pub fn has_default_route(routes: &[Route]) -> bool {
    routes.iter().any(|r| r.prefix == 0 && r.dest_be == 0)
}
