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
    parse_proc_routes(&raw, tundev)
}

/// Pure parser for `/proc/net/route` content, split out from
/// [`for_tun_device`] so it can be unit-tested without a live procfs.
fn parse_proc_routes(raw: &str, tundev: &str) -> Vec<Route> {
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

/// True when the route table for `tundev` covers the whole IPv4 space —
/// indicates the profile expects a full-tunnel default route.  Drives
/// `NEVER_DEFAULT=TRUE` when false.
///
/// openvpn3's netcfg does NOT install a literal `0.0.0.0/0` for a
/// redirect-gateway full tunnel; `core-tunbuilder.cpp` installs the
/// "def1" split (`0.0.0.0/1` + `128.0.0.0/1`), which together cover the
/// entire address space.  Treat either form as a default route, else a
/// full tunnel is mis-reported to NM as never-default (DNS-priority /
/// primary-connection regression).
pub fn has_default_route(routes: &[Route]) -> bool {
    // Literal default route.
    if routes.iter().any(|r| r.prefix == 0 && r.dest_be == 0) {
        return true;
    }
    // def1 split: 0.0.0.0/1 + 128.0.0.0/1.  dest_be uses the
    // no-byteswap /proc/net/route convention, so 128.0.0.0 == 0x80.
    let lower_half = routes.iter().any(|r| r.prefix == 1 && r.dest_be == 0);
    let upper_half = routes.iter().any(|r| r.prefix == 1 && r.dest_be == 0x80);
    lower_half && upper_half
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dest_be: u32, prefix: u32) -> Route {
        Route {
            dest_be,
            prefix,
            next_hop_be: 0,
            metric: 0,
        }
    }

    #[test]
    fn parses_default_and_filters_iface() {
        let raw =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            tun0\t00000000\t0100000A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
            eth0\t0000FE0A\t00000000\t0001\t0\t0\t100\tFFFFFFFF\t0\t0\t0\n";
        let routes = parse_proc_routes(raw, "tun0");
        assert_eq!(routes.len(), 1, "only tun0 rows");
        assert_eq!(routes[0].dest_be, 0);
        assert_eq!(routes[0].prefix, 0, "mask 0x00000000 -> /0");
        assert_eq!(routes[0].metric, 50);
        assert!(has_default_route(&routes));
    }

    #[test]
    fn skips_short_and_malformed_rows() {
        let raw = "hdr\n\
            tun0\tZZZZ\t0\t0\t0\t0\t0\t00000000\t0\t0\t0\n\
            tun0\ttoofew\tcols\n\
            tun0\tFFFFFFFF\t0\t0\t0\t0\t10\tFFFFFF00\t0\t0\t0\n";
        let routes = parse_proc_routes(raw, "tun0");
        assert_eq!(routes.len(), 1, "bad-hex and short rows dropped");
        assert_eq!(routes[0].prefix, 24, "mask 0xFFFFFF00 -> 24 ones");
    }

    #[test]
    fn default_route_literal_and_negatives() {
        assert!(!has_default_route(&[]));
        assert!(has_default_route(&[route(0, 0)]));
        // dest 0 but /8 is NOT a default route.
        assert!(!has_default_route(&[route(0, 8)]));
        // split tunnel 10.0.0.0/8.
        let split = route(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)).to_be(), 8);
        assert!(!has_default_route(&[split]));
    }

    /// Regression for B5: the def1 split must count as a default route.
    #[test]
    fn default_route_def1_split() {
        let lower = route(0, 1); // 0.0.0.0/1
        let upper = route(0x80, 1); // 128.0.0.0/1
        assert!(has_default_route(&[lower, upper]));
        // Only one half present → not a full tunnel.
        assert!(!has_default_route(&[lower]));
        assert!(!has_default_route(&[upper]));
    }
}
