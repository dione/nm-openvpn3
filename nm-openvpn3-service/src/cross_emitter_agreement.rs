//! Cross-emitter agreement test (pass-6).
//!
//! The project has TWO independent `.ovpn` emitters that must produce
//! equivalent output for the same `vpn.data`:
//!
//!   * connect side — [`crate::build_profile::build_profile_string`], the
//!     root service's live-connect path (when no verbatim profile is
//!     pinned);
//!   * export side — `import_export::OvpnConfig::from_nm_data` + `emit`,
//!     the user-side properties cdylib's Save-As / export path.
//!
//! They are hand-maintained in two separate crates and have drifted
//! before: B1 (auth dropped on connect), B6 (keysize dropped on import),
//! R2 (UDP→TCP), R3 (key-direction), and the pass-6 L4 (TLS-directive
//! gating) and L5 (route allow-list) findings are all the same bug class
//! — emitter disagreement. This test pins the contract.
//!
//! Comparison is **structural, not textual**: each emitted profile is
//! re-parsed with `OvpnConfig::parse` (which strips quoting) and the
//! resulting directives are compared as an order-independent multiset.
//! That deliberately ignores cosmetic differences — the connect side
//! re-emits preserved route lines verbatim while the export side
//! re-escapes each argument, so `route 10.0.0.0 255.0.0.0` vs
//! `route '10.0.0.0' '255.0.0.0'` are wire-equivalent and must compare
//! equal.
//!
//! Deliberately-excluded divergence: the PKCS#12 collapse predicate
//! differs between the emitters (connect collapses on `cert==key`, export
//! on `ca==cert==key`) — pass-6 M3, deferred pending openvpn3 validation.
//! The corpus avoids the `cert==key && ca!=cert` edge; add a case here
//! once M3 is resolved.

use std::collections::{BTreeMap, HashMap};

use nm_vpn_plugin_openvpn3::import_export::{Directive, OvpnConfig};

use crate::build_profile::build_profile_string;
use crate::secrets::SecretsMap;

/// Re-parse an emitted profile and reduce it to a sorted, quoting-
/// normalised list of `name arg1 arg2 …` strings for order-independent
/// comparison.  Parsing must succeed — a valid emitter never produces
/// text its own parser rejects (which would itself be a bug worth
/// failing on).
fn canonical(profile: &str) -> Vec<String> {
    let cfg = OvpnConfig::parse(profile)
        .unwrap_or_else(|e| panic!("emitted profile must parse: {e}\n{profile}"));
    let mut out: Vec<String> = cfg
        .directives
        .iter()
        .map(|d| match d {
            Directive::Option { name, args } => {
                if args.is_empty() {
                    name.clone()
                } else {
                    format!("{name} {}", args.join(" "))
                }
            }
            Directive::Blob { name, .. } => format!("<{name}>"),
        })
        .collect();
    out.sort();
    out
}

fn connect_emit(pairs: &[(&str, &str)]) -> String {
    let data: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    build_profile_string(&data, &SecretsMap::new()).expect("build_profile_string")
}

fn export_emit(pairs: &[(&str, &str)]) -> String {
    let data: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    OvpnConfig::from_nm_data(&data).emit()
}

#[track_caller]
fn assert_agree(label: &str, pairs: &[(&str, &str)]) {
    let connect = canonical(&connect_emit(pairs));
    let export = canonical(&export_emit(pairs));
    assert_eq!(
        connect, export,
        "cross-emitter disagreement for `{label}`\n\
         connect (build_profile):\n{connect:#?}\n\
         export   (from_nm_data):\n{export:#?}"
    );
}

#[test]
fn agreement_tls_full() {
    assert_agree(
        "tls",
        &[
            ("connection-type", "tls"),
            ("remote", "vpn.example.com:1194:udp"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("cert", "/etc/ovpn/client.crt"),
            ("key", "/etc/ovpn/client.key"),
            ("cipher", "AES-256-GCM"),
            ("auth", "SHA256"),
            ("keysize", "256"),
            ("remote-cert-tls", "server"),
            ("ns-cert-type", "server"),
            ("reneg-seconds", "3600"),
            ("port", "1194"),
            ("ping", "10"),
            ("ping-restart", "60"),
            ("tls-version-min", "1.2"),
            ("tls-version-max", "1.3"),
            ("extra-certs", "/etc/ovpn/extra.pem"),
            ("verify-x509-name", "name-prefix:server"),
        ],
    );
}

#[test]
fn agreement_password_tls() {
    assert_agree(
        "password-tls",
        &[
            ("connection-type", "password-tls"),
            ("remote", "vpn.example.com"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("cert", "/etc/ovpn/client.crt"),
            ("key", "/etc/ovpn/client.key"),
            ("ta", "/etc/ovpn/ta.key"),
            ("ta-dir", "1"),
            ("tls-crypt", "/etc/ovpn/tc.key"),
        ],
    );
}

#[test]
fn agreement_password_only() {
    assert_agree(
        "password",
        &[
            ("connection-type", "password"),
            ("remote", "vpn.example.com"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("proto-tcp", "yes"),
        ],
    );
}

/// L4 regression: a static-key connection carrying STALE TLS-context keys
/// (left in vpn.data after a TLS→static-key switch) must drop them on BOTH
/// emitters.  Before the L4 fix, the export emitter emitted them
/// unconditionally while the connect emitter gated them on is_tls_like.
#[test]
fn agreement_static_key_drops_stale_tls_directives() {
    assert_agree(
        "static-key+stale-tls",
        &[
            ("connection-type", "static-key"),
            ("remote", "vpn.example.com"),
            ("static-key", "/etc/ovpn/static.key"),
            ("static-key-direction", "1"),
            ("local-ip", "10.8.0.2"),
            ("remote-ip", "10.8.0.1"),
            // Stale TLS keys — both emitters must gate these out.
            ("remote-cert-tls", "server"),
            ("ns-cert-type", "server"),
            ("tls-remote", "/CN=server"),
            ("tls-version-max", "1.3"),
            ("extra-certs", "/etc/ovpn/extra.pem"),
            ("crl-verify-file", "/etc/ovpn/crl.pem"),
        ],
    );
}

/// L5 regression: an unsafe directive smuggled into the preserved-routes
/// key must be dropped by BOTH emitters (and the safe route lines kept).
/// Before the L5 fix the export emitter re-emitted `route-up …` verbatim
/// while the connect emitter's allow-list dropped it.
#[test]
fn agreement_extra_routes_allowlist() {
    assert_agree(
        "extra-routes",
        &[
            ("connection-type", "tls"),
            ("remote", "vpn.example.com"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("cert", "/etc/ovpn/client.crt"),
            ("key", "/etc/ovpn/client.key"),
            (
                "nm-openvpn3-extra-routes",
                "route 10.0.0.0 255.0.0.0\n\
                 route-up /tmp/evil.sh\n\
                 route 192.168.1.0 255.255.255.0 10.0.0.1\n\
                 route-gateway 10.8.0.1",
            ),
        ],
    );
}

/// Sanity: the comparison is real — a config where the emitters genuinely
/// agree must produce a non-empty directive set (guards against
/// `canonical` silently returning empty and the asserts passing
/// vacuously).
#[test]
fn corpus_is_non_trivial() {
    let lines = canonical(&connect_emit(&[
        ("connection-type", "tls"),
        ("remote", "vpn.example.com"),
        ("ca", "/etc/ovpn/ca.pem"),
        ("cert", "/etc/ovpn/client.crt"),
        ("key", "/etc/ovpn/client.key"),
    ]));
    assert!(
        lines.len() > 5,
        "expected a substantive directive set, got {lines:?}"
    );
    assert!(lines.iter().any(|l| l == "client"));
}
