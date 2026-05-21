//! Integration tests: parse every .ovpn fixture under
//! `tests/fixtures/`, then re-emit the parsed structure and parse the
//! emission a second time.  Asserts the second parse equals the first.
//! That gives us "parser/emitter agree on the directive stream" without
//! requiring byte-identical round-trip (which is impossible — the C
//! exporter normalises whitespace + quoting too).

use std::path::Path;

use nm_vpn_plugin_openvpn3::import_export::OvpnConfig;

fn fixtures_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

fn fixtures() -> impl Iterator<Item = std::path::PathBuf> {
    let dir = fixtures_dir();
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({}): {e}", dir.display()))
        .filter_map(|res| {
            let e = res.ok()?;
            let p = e.path();
            if p.extension().is_some_and(|x| x == "ovpn") {
                Some(p)
            } else {
                None
            }
        })
}

#[test]
fn every_fixture_parses() {
    let mut count = 0;
    for path in fixtures() {
        let text = std::fs::read_to_string(&path).expect("read");
        OvpnConfig::parse(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        count += 1;
    }
    assert!(count > 0, "no fixtures found");
    eprintln!("parsed {count} fixtures");
}

#[test]
fn every_fixture_round_trips() {
    for path in fixtures() {
        let text = std::fs::read_to_string(&path).expect("read");
        let first =
            OvpnConfig::parse(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        let emitted = first.emit();
        let second = OvpnConfig::parse(&emitted)
            .unwrap_or_else(|e| panic!("re-parse {}: {e}\nemitted:\n{emitted}", path.display()));
        assert_eq!(
            first.directives,
            second.directives,
            "directive stream drifted on re-parse of {}",
            path.display()
        );
    }
}

#[test]
fn port_fixture_extracts_port_value() {
    let text = std::fs::read_to_string(fixtures_dir().join("port.ovpn")).unwrap();
    let cfg = OvpnConfig::parse(&text).unwrap();
    let nm = cfg.as_nm_data();
    assert_eq!(nm.get("port").map(String::as_str), Some("2345"));
}

#[test]
fn proto_tcp_fixture_sets_proto_tcp_yes() {
    let text = std::fs::read_to_string(fixtures_dir().join("proto-tcp.ovpn")).unwrap();
    let cfg = OvpnConfig::parse(&text).unwrap();
    let nm = cfg.as_nm_data();
    assert_eq!(nm.get("proto-tcp").map(String::as_str), Some("yes"));
}

#[test]
fn pkcs12_fixture_fills_ca_cert_key_with_same_path() {
    let text = std::fs::read_to_string(fixtures_dir().join("pkcs12.ovpn")).unwrap();
    let cfg = OvpnConfig::parse(&text).unwrap();
    let nm = cfg.as_nm_data();
    let ca = nm.get("ca").map(String::as_str);
    let cert = nm.get("cert").map(String::as_str);
    let key = nm.get("key").map(String::as_str);
    assert!(ca.is_some(), "ca missing");
    assert_eq!(ca, cert);
    assert_eq!(cert, key);
}

#[test]
fn proxy_http_fixture_sets_proxy_keys() {
    let text = std::fs::read_to_string(fixtures_dir().join("proxy-http.ovpn")).unwrap();
    let cfg = OvpnConfig::parse(&text).unwrap();
    let nm = cfg.as_nm_data();
    assert_eq!(nm.get("proxy-type").map(String::as_str), Some("http"));
    assert!(nm.contains_key("proxy-server"));
}
