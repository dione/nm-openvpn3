//! Rust port of the C tree's `src/build-profile.c`.
//!
//! Builds an OpenVPN profile string from the NM vpn.data / vpn.secrets
//! settings dict the plugin receives over D-Bus.  Called from
//! `do_connect` when `vpn.data['nm-openvpn3-profile']` is absent — the
//! caller hands the resulting string straight to openvpn3-linux's
//! Import method, so no file-system round-trip is needed (the C tree
//! wrote a tempfile + read it back; we accumulate into a `String` in
//! process memory).
//!
//! The option set mirrors `do_export_create()` in
//! `properties/import-export.c` on the C side.  See the test fixtures
//! in `properties/tests/conf/*.ovpn` for the expected shape of each
//! option; this module's snapshot tests cover the common cases.
//!
//! Deferred:
//!   * NMSettingIPConfig routes — those live in `connection['ipv4']
//!     ['route-data']`, not vpn.data, and need a settings-dict
//!     argument on this entrypoint to surface.  Tracked as a TODO on
//!     `do_connect`.
//!   * HTTP-proxy authfile write — the C tree splats username+password
//!     into `<path>-httpauthfile` next to the export tempfile.  We
//!     have no tempfile and openvpn3 won't read a path that doesn't
//!     yet exist at Import time; need a different sink, e.g. a
//!     per-session file under `$XDG_RUNTIME_DIR`.

use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::secrets::SecretsMap;

// vpn.data / vpn.secrets keys.  Source of truth is C
// `shared/nm-service-defines.h` (`NM_OPENVPN3_KEY_*`).
const KEY_REMOTE: &str = "remote";
const KEY_CONNECTION_TYPE: &str = "connection-type";
const KEY_REMOTE_RANDOM: &str = "remote-random";
const KEY_REMOTE_RANDOM_HOSTNAME: &str = "remote-random-hostname";
const KEY_ALLOW_PULL_FQDN: &str = "allow-pull-fqdn";
const KEY_TUN_IPV6: &str = "tun-ipv6";
const KEY_PUSH_PEER_INFO: &str = "push-peer-info";
const KEY_CA: &str = "ca";
const KEY_CERT: &str = "cert";
const KEY_KEY: &str = "key";
const KEY_STATIC_KEY: &str = "static-key";
const KEY_STATIC_KEY_DIRECTION: &str = "static-key-direction";
const KEY_RENEG_SECONDS: &str = "reneg-seconds";
const KEY_MAX_ROUTES: &str = "max-routes";
const KEY_CIPHER: &str = "cipher";
const KEY_DATA_CIPHERS: &str = "data-ciphers";
const KEY_DATA_CIPHERS_FALLBACK: &str = "data-ciphers-fallback";
const KEY_TLS_CIPHER: &str = "tls-cipher";
const KEY_KEYSIZE: &str = "keysize";
const KEY_ALLOW_COMPRESSION: &str = "allow-compression";
const KEY_COMP_LZO: &str = "comp-lzo";
const KEY_COMPRESS: &str = "compress";
const KEY_FLOAT: &str = "float";
const KEY_MSSFIX: &str = "mssfix";
const KEY_MTU_DISC: &str = "mtu-disc";
const KEY_TUNNEL_MTU: &str = "tunnel-mtu";
const KEY_CONNECT_TIMEOUT: &str = "connect-timeout";
const KEY_FRAGMENT_SIZE: &str = "fragment-size";
const KEY_CRL_VERIFY_FILE: &str = "crl-verify-file";
const KEY_CRL_VERIFY_DIR: &str = "crl-verify-dir";
const KEY_DEV: &str = "dev";
const KEY_DEV_TYPE: &str = "dev-type";
const KEY_TAP_DEV: &str = "tap-dev";
const KEY_PROTO_TCP: &str = "proto-tcp";
const KEY_PORT: &str = "port";
const KEY_PING: &str = "ping";
const KEY_PING_EXIT: &str = "ping-exit";
const KEY_PING_RESTART: &str = "ping-restart";
const KEY_LOCAL_IP: &str = "local-ip";
const KEY_REMOTE_IP: &str = "remote-ip";
const KEY_REMOTE_CERT_TLS: &str = "remote-cert-tls";
const KEY_NS_CERT_TYPE: &str = "ns-cert-type";
const KEY_TLS_REMOTE: &str = "tls-remote";
const KEY_VERIFY_X509_NAME: &str = "verify-x509-name";
const KEY_TA: &str = "ta";
const KEY_TA_DIR: &str = "ta-dir";
const KEY_TLS_CRYPT: &str = "tls-crypt";
const KEY_TLS_CRYPT_V2: &str = "tls-crypt-v2";
const KEY_TLS_VERSION_MIN: &str = "tls-version-min";
const KEY_TLS_VERSION_MIN_OR_HIGHEST: &str = "tls-version-min-or-highest";
const KEY_TLS_VERSION_MAX: &str = "tls-version-max";
const KEY_EXTRA_CERTS: &str = "extra-certs";
const KEY_PROXY_TYPE: &str = "proxy-type";
const KEY_PROXY_SERVER: &str = "proxy-server";
const KEY_PROXY_PORT: &str = "proxy-port";
const KEY_PROXY_RETRY: &str = "proxy-retry";
const KEY_HTTP_PROXY_USERNAME: &str = "http-proxy-username";
/// Newline-joined extra `route …` lines that survive a round-trip from
/// the importer's directive vector (the editor has no UI for routes,
/// so we preserve them as raw text in vpn.data and re-emit verbatim).
const KEY_EXTRA_ROUTES: &str = "nm-openvpn3-extra-routes";

const CONTYPE_TLS: &str = "tls";
const CONTYPE_PASSWORD: &str = "password";
const CONTYPE_PASSWORD_TLS: &str = "password-tls";
const CONTYPE_STATIC_KEY: &str = "static-key";

// Matches NM_OPENVPN3_USER / NM_OPENVPN3_GROUP from C
// shared/nm-service-defines.h.
const NM_OPENVPN3_USER: &str = "nm-openvpn3";
const NM_OPENVPN3_GROUP: &str = "nm-openvpn3";

/// Build an OpenVPN config file as a string from the NM settings dict.
///
/// Mirrors the C plugin's `build_profile_string()` ->
/// `do_export_create()` path.  Errors when the connection is missing a
/// `remote` (matches the C tree — without a server address there is no
/// useful config to emit).
pub fn build_profile_string(
    data: &HashMap<String, String>,
    _secrets: &SecretsMap,
) -> Result<String> {
    let mut w = Writer::new();
    let get = |k: &str| arg_is_set(data.get(k).map(String::as_str));

    let gateways =
        get(KEY_REMOTE).ok_or_else(|| anyhow!("vpn.data['{KEY_REMOTE}'] is required"))?;
    let connection_type = get(KEY_CONNECTION_TYPE);

    let is_tls_like = matches!(
        connection_type,
        Some(CONTYPE_TLS) | Some(CONTYPE_PASSWORD) | Some(CONTYPE_PASSWORD_TLS)
    );
    let is_password_like = matches!(
        connection_type,
        Some(CONTYPE_PASSWORD) | Some(CONTYPE_PASSWORD_TLS)
    );
    let needs_user_cert = matches!(
        connection_type,
        Some(CONTYPE_TLS) | Some(CONTYPE_PASSWORD_TLS)
    );

    if is_tls_like {
        w.line(&["client"]);
    }

    // remote ... — comma/space/tab-separated list, each entry parsed as
    // host[:port[:proto]].  Mirrors C `nmovpn_remote_parse`.
    for gw in gateways.split([' ', '\t', ',']) {
        let gw = gw.trim();
        if gw.is_empty() {
            continue;
        }
        let (host, port, proto) = parse_remote(gw);
        let port_or_default = match (port, proto) {
            (Some(p), _) => Some(p),
            (None, Some(_)) => Some("1194"),
            (None, None) => None,
        };
        w.line_opt(&[Some("remote"), Some(host), port_or_default, proto]);
    }

    if get(KEY_REMOTE_RANDOM) == Some("yes") {
        w.line(&["remote-random"]);
    }
    if get(KEY_REMOTE_RANDOM_HOSTNAME) == Some("yes") {
        w.line(&["remote-random-hostname"]);
    }
    if get(KEY_ALLOW_PULL_FQDN) == Some("yes") {
        w.line(&["allow-pull-fqdn"]);
    }
    if get(KEY_TUN_IPV6) == Some("yes") {
        w.line(&["tun-ipv6"]);
    }
    if get(KEY_PUSH_PEER_INFO) == Some("yes") {
        w.line(&["push-peer-info"]);
    }

    // CA / cert / key.  PKCS#12 collapsed form: when cert == key and
    // the file ends in `.p12` / `.pfx`, the C tree emits a single
    // `pkcs12 <path>` line and skips `ca` (a PKCS#12 bundle carries
    // the CA inside).  Mirror that here — otherwise emit the split
    // form openvpn3 accepts equally well.
    let cert_v = if needs_user_cert { get(KEY_CERT) } else { None };
    let key_v = if needs_user_cert { get(KEY_KEY) } else { None };
    let pkcs12_collapse =
        matches!((cert_v, key_v), (Some(c), Some(k)) if c == k && is_pkcs12_path(c));

    if pkcs12_collapse {
        // Safe to unwrap: pkcs12_collapse implies cert_v == key_v == Some.
        w.line(&["pkcs12", cert_v.unwrap()]);
    } else {
        if is_tls_like {
            if let Some(ca) = get(KEY_CA) {
                w.line(&["ca", ca]);
            }
        }
        if needs_user_cert {
            if let Some(cert) = cert_v {
                w.line(&["cert", cert]);
            }
            if let Some(key) = key_v {
                w.line(&["key", key]);
            }
        }
    }

    if is_password_like {
        w.line(&["auth-user-pass"]);
    }

    if connection_type == Some(CONTYPE_STATIC_KEY) {
        if let Some(secret) = get(KEY_STATIC_KEY) {
            w.line_opt(&[Some("secret"), Some(secret), get(KEY_STATIC_KEY_DIRECTION)]);
        }
    }

    line_int(&mut w, "reneg-sec", get(KEY_RENEG_SECONDS));
    line_int(&mut w, "max-routes", get(KEY_MAX_ROUTES));
    line_str(&mut w, "cipher", get(KEY_CIPHER));
    line_str(&mut w, "data-ciphers", get(KEY_DATA_CIPHERS));
    line_str(
        &mut w,
        "data-ciphers-fallback",
        get(KEY_DATA_CIPHERS_FALLBACK),
    );
    line_str(&mut w, "tls-cipher", get(KEY_TLS_CIPHER));
    line_int(&mut w, "keysize", get(KEY_KEYSIZE));
    line_str(&mut w, "allow-compression", get(KEY_ALLOW_COMPRESSION));

    if get(KEY_ALLOW_COMPRESSION) != Some("no") {
        if let Some(lzo) = get(KEY_COMP_LZO) {
            // Internal NM value "no-by-default" maps to plain "no" on
            // the wire — matches the C export path.
            let lzo = if lzo == "no-by-default" { "no" } else { lzo };
            w.line(&["comp-lzo", lzo]);
        }
        match get(KEY_COMPRESS) {
            Some("yes") => w.line(&["compress"]),
            Some(v) => w.line(&["compress", v]),
            None => {}
        }
    }

    if get(KEY_FLOAT) == Some("yes") {
        w.line(&["float"]);
    }

    match get(KEY_MSSFIX) {
        Some("yes") => w.line(&["mssfix"]),
        Some(v) => match v.parse::<i64>() {
            Ok(n) => w.line(&["mssfix", &n.to_string()]),
            Err(_) => w.line(&["mssfix", v]),
        },
        None => {}
    }

    line_str(&mut w, "mtu-disc", get(KEY_MTU_DISC));
    line_int(&mut w, "tun-mtu", get(KEY_TUNNEL_MTU));
    line_int(&mut w, "connect-timeout", get(KEY_CONNECT_TIMEOUT));
    line_int(&mut w, "fragment", get(KEY_FRAGMENT_SIZE));

    if is_tls_like {
        if let Some(file) = get(KEY_CRL_VERIFY_FILE) {
            w.line(&["crl-verify", file]);
        } else if let Some(dir) = get(KEY_CRL_VERIFY_DIR) {
            w.line(&["crl-verify", dir, "dir"]);
        }
    }

    // dev / dev-type — pick first non-empty of:
    //   1. explicit `dev=...`
    //   2. explicit `dev-type=...`
    //   3. legacy `tap-dev=yes` → "tap", else default "tun"
    let dev = get(KEY_DEV);
    let dev_type = get(KEY_DEV_TYPE);
    let tap_dev = get(KEY_TAP_DEV) == Some("yes");
    let chosen_dev = dev
        .or(dev_type)
        .unwrap_or(if tap_dev { "tap" } else { "tun" });
    w.line(&["dev", chosen_dev]);
    if let Some(dt) = dev_type {
        w.line(&["dev-type", dt]);
    }

    w.line(&[
        "proto",
        if get(KEY_PROTO_TCP) == Some("yes") {
            "tcp"
        } else {
            "udp"
        },
    ]);

    line_int(&mut w, "port", get(KEY_PORT));
    line_int(&mut w, "ping", get(KEY_PING));
    line_int(&mut w, "ping-exit", get(KEY_PING_EXIT));
    line_int(&mut w, "ping-restart", get(KEY_PING_RESTART));

    if let (Some(local), Some(remote)) = (get(KEY_LOCAL_IP), get(KEY_REMOTE_IP)) {
        w.line(&["ifconfig", local, remote]);
    }

    // Extra static routes preserved from the imported .ovpn.  Each
    // entry is a verbatim "route …" line — pre-tokenised, already
    // escape_arg'd as needed by the parser.  Re-emit as raw text so we
    // don't double-quote.
    if let Some(routes) = get(KEY_EXTRA_ROUTES) {
        for line in routes.lines() {
            let line = line.trim();
            if !line.is_empty() {
                w.raw_line(line);
            }
        }
    }

    if is_tls_like {
        line_str(&mut w, "remote-cert-tls", get(KEY_REMOTE_CERT_TLS));
        line_str(&mut w, "ns-cert-type", get(KEY_NS_CERT_TYPE));
        line_str(&mut w, "tls-remote", get(KEY_TLS_REMOTE));

        if let Some(x509_name) = get(KEY_VERIFY_X509_NAME) {
            // The C tree encodes the optional name-type as a `<type>:`
            // prefix on the same NM key.
            if let Some((ty, name)) = x509_name.split_once(':') {
                w.line(&["verify-x509-name", name, ty]);
            } else {
                w.line(&["verify-x509-name", x509_name]);
            }
        }

        if let Some(ta) = get(KEY_TA) {
            w.line_opt(&[Some("tls-auth"), Some(ta), get(KEY_TA_DIR)]);
        }
        if let Some(k) = get(KEY_TLS_CRYPT) {
            w.line(&["tls-crypt", k]);
        }
        if let Some(k) = get(KEY_TLS_CRYPT_V2) {
            w.line(&["tls-crypt-v2", k]);
        }
        if let Some(v) = get(KEY_TLS_VERSION_MIN) {
            let or_highest = get(KEY_TLS_VERSION_MIN_OR_HIGHEST) == Some("yes");
            w.line_opt(&[
                Some("tls-version-min"),
                Some(v),
                if or_highest { Some("or-highest") } else { None },
            ]);
        }
        if let Some(v) = get(KEY_TLS_VERSION_MAX) {
            w.line(&["tls-version-max", v]);
        }
        if let Some(k) = get(KEY_EXTRA_CERTS) {
            w.line(&["extra-certs", k]);
        }
    }

    // HTTP / SOCKS proxy.  The C tree also writes an `<path>-httpauthfile`
    // next to its export tempfile when a proxy username is set; we have
    // no path here (Rust hands openvpn3 the profile string directly).
    // Emit the proxy line itself so connections without an authfile
    // still work; proxy auth is a follow-up.
    if let Some(proxy_type) = get(KEY_PROXY_TYPE) {
        let server = get(KEY_PROXY_SERVER);
        if let Some(server) = server {
            match proxy_type {
                "http" => {
                    let port = get(KEY_PROXY_PORT).unwrap_or("8080");
                    let user = get(KEY_HTTP_PROXY_USERNAME);
                    if user.is_some() {
                        tracing::warn!(
                            "http-proxy authfile generation is not yet supported; \
                             emitting `http-proxy {server} {port}` without auth"
                        );
                    }
                    w.line(&["http-proxy", server, port]);
                    if get(KEY_PROXY_RETRY) == Some("yes") {
                        w.line(&["http-proxy-retry"]);
                    }
                }
                "socks" => {
                    let port = get(KEY_PROXY_PORT).unwrap_or("1080");
                    w.line(&["socks-proxy", server, port]);
                    if get(KEY_PROXY_RETRY) == Some("yes") {
                        w.line(&["socks-proxy-retry"]);
                    }
                }
                other => tracing::warn!("unknown proxy-type '{other}', skipping"),
            }
        }
    }

    // Hard-coded tail — matches do_export_create()'s closing block.
    w.line(&["nobind"]);
    w.line(&["auth-nocache"]);
    w.line(&["script-security", "2"]);
    w.line(&["persist-key"]);
    w.line(&["persist-tun"]);
    w.line(&["user", NM_OPENVPN3_USER]);
    w.line(&["group", NM_OPENVPN3_GROUP]);

    Ok(w.into_inner())
}

/// `Some(s)` iff `s` is `Some` and non-empty.  Matches C
/// `nmovpn_arg_is_set` — empty strings are not arguments.
fn arg_is_set(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.is_empty())
}

/// Heuristic match of the C tree's `is_pkcs12()` — by file extension
/// only.  openvpn3 itself sniffs the content, so a false positive
/// here just lands a slightly less terse emission than the C
/// exporter would have produced; a false negative is harmless too
/// (split form parses fine).
fn is_pkcs12_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".p12") || lower.ends_with(".pfx")
}

/// Best-effort `host[:port[:proto]]` decomposition.  The C
/// `nmovpn_remote_parse()` is stricter (validates port range, recognises
/// `udp4`/`tcp4`/etc.), but openvpn3 itself does the same checks at
/// Import time, so anything we mis-split here gets rejected with a clear
/// error rather than silently misbehaving.
fn parse_remote(input: &str) -> (&str, Option<&str>, Option<&str>) {
    // Bracketed IPv6 literal: `[2001:db8::1]:1194:tcp` — split host from
    // the trailing `:port[:proto]` after the closing bracket.  Treat
    // anything outside the brackets as the colon-separated tail.
    if let Some(rest) = input.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let mut tail_it = tail.strip_prefix(':').unwrap_or(tail).splitn(2, ':');
            let port = tail_it.next().filter(|s| !s.is_empty());
            let proto = tail_it.next().filter(|s| !s.is_empty());
            return (host, port, proto);
        }
    }
    // Bare colon-separated form: `host:port[:proto]`.  IPv6 literals
    // without brackets are ambiguous (`fe80::1` has 2 colons but so
    // does `host:port:proto`); the user is expected to bracket IPv6 if
    // they want it parsed correctly, matching C nmovpn_remote_parse.
    let mut it = input.splitn(3, ':');
    let host = it.next().unwrap_or("");
    // Empty port (e.g. `host::tcp`) is treated as unset so the caller
    // can fall back to the openvpn default — matches the C tree, which
    // returns NULL from `nmovpn_remote_parse` for the empty-port slot.
    let port = it.next().filter(|s| !s.is_empty());
    let proto = it.next().filter(|s| !s.is_empty());
    (host, port, proto)
}

fn line_str(w: &mut Writer, tag: &'static str, value: Option<&str>) {
    if let Some(v) = value {
        w.line(&[tag, v]);
    }
}

fn line_int(w: &mut Writer, tag: &'static str, value: Option<&str>) {
    // The C tree's `args_write_line_setting_value_int` parses the NM
    // dict value as int64 and only emits the line on success.  Mirror
    // that — skip non-numeric values silently so an editor that wrote
    // a typoed override doesn't poison the profile.
    if let Some(v) = value {
        if v.parse::<i64>().is_ok() {
            w.line(&[tag, v]);
        }
    }
}

/// Profile-text accumulator.  Each `line*` call appends one option line
/// with C-equivalent quoting.
struct Writer {
    buf: String,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: String::with_capacity(512),
        }
    }

    fn into_inner(self) -> String {
        self.buf
    }

    /// Emit `tag arg1 arg2 …\n` with arg quoting (mirrors C
    /// `args_write_line_v`).  All args required.
    fn line(&mut self, args: &[&str]) {
        debug_assert!(!args.is_empty(), "args_write_line expects at least a tag");
        let mut first = true;
        for a in args {
            if !first {
                self.buf.push(' ');
            }
            first = false;
            push_escaped(&mut self.buf, a);
        }
        self.buf.push('\n');
    }

    /// Same as `line`, but each arg is `Option<&str>` — `None` entries
    /// are skipped.  Matches the C tree's habit of passing trailing
    /// `NULL` to mark optional args.  The tag (args[0]) must still be
    /// `Some`.
    fn line_opt(&mut self, args: &[Option<&str>]) {
        let mut first = true;
        for a in args.iter().flatten() {
            if !first {
                self.buf.push(' ');
            }
            first = false;
            push_escaped(&mut self.buf, a);
        }
        self.buf.push('\n');
    }

    /// Append a verbatim line.  Caller is responsible for any escaping;
    /// used only for already-shaped text we preserved from the source
    /// .ovpn (e.g. extra `route` lines).
    fn raw_line(&mut self, line: &str) {
        self.buf.push_str(line);
        self.buf.push('\n');
    }
}

/// Port of C `escape_arg()`.  Returns the value unchanged if it only
/// contains the "benign" charset; otherwise single-quotes the value
/// (no inline `'` or newline → quotation just wraps), or double-quotes
/// + escapes if the value needs it.
fn push_escaped(buf: &mut String, value: &str) {
    if value.is_empty() {
        buf.push_str("''");
        return;
    }
    let mut needs_quote = false;
    let mut needs_double = false;
    for c in value.chars() {
        if matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | ':' | '/') {
            continue;
        }
        needs_quote = true;
        if c == '\'' || c == '\n' {
            needs_double = true;
        }
    }
    if !needs_quote {
        buf.push_str(value);
        return;
    }
    if !needs_double {
        buf.push('\'');
        buf.push_str(value);
        buf.push('\'');
        return;
    }
    buf.push('"');
    for c in value.chars() {
        match c {
            '\n' => {
                // OpenVPN cannot represent literal newlines; emit the
                // escape sequence the C tree emits and let openvpn3's
                // parser surface the warning.
                buf.push('\\');
                buf.push('n');
            }
            '\\' | '"' => {
                buf.push('\\');
                buf.push(c);
            }
            other => buf.push(other),
        }
    }
    buf.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn assert_contains(profile: &str, line: &str) {
        assert!(
            profile.lines().any(|l| l == line),
            "expected line `{line}` in profile, got:\n{profile}"
        );
    }

    fn tail() -> &'static [&'static str] {
        &[
            "nobind",
            "auth-nocache",
            "script-security 2",
            "persist-key",
            "persist-tun",
            "user nm-openvpn3",
            "group nm-openvpn3",
        ]
    }

    #[test]
    fn minimal_tls() {
        // Dotted paths/hostnames trip escape_arg's needs-quote path —
        // matches what the C exporter emits.  openvpn3's import parser
        // strips the quotes so both forms are wire-equivalent.
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "vpn.example.com"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("cert", "/etc/ovpn/client.crt"),
            ("key", "/etc/ovpn/client.key"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "client");
        assert_contains(&out, "remote 'vpn.example.com'");
        assert_contains(&out, "ca '/etc/ovpn/ca.pem'");
        assert_contains(&out, "cert '/etc/ovpn/client.crt'");
        assert_contains(&out, "key '/etc/ovpn/client.key'");
        assert_contains(&out, "dev tun");
        assert_contains(&out, "proto udp");
        for t in tail() {
            assert_contains(&out, t);
        }
    }

    #[test]
    fn password_tls_emits_auth_user_pass() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "password-tls"),
            ("remote", "vpn.example.com"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("cert", "/etc/ovpn/client.crt"),
            ("key", "/etc/ovpn/client.key"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "auth-user-pass");
    }

    #[test]
    fn password_only_skips_user_cert_and_key() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "password"),
            ("remote", "vpn.example.com"),
            ("ca", "/etc/ovpn/ca.pem"),
            ("cert", "/etc/ovpn/client.crt"),
            ("key", "/etc/ovpn/client.key"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "ca '/etc/ovpn/ca.pem'");
        assert!(
            !out.lines().any(|l| l.starts_with("cert ")),
            "password mode should not emit a user `cert` line"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("key ")),
            "password mode should not emit a user `key` line"
        );
        assert_contains(&out, "auth-user-pass");
    }

    #[test]
    fn tcp_proto_when_proto_tcp_yes() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "vpn.example.com"),
            ("proto-tcp", "yes"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "proto tcp");
    }

    #[test]
    fn remote_random_and_pull_fqdn_flags() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "a.example.com b.example.com,c.example.com"),
            ("remote-random", "yes"),
            ("allow-pull-fqdn", "yes"),
            ("push-peer-info", "yes"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "remote 'a.example.com'");
        assert_contains(&out, "remote 'b.example.com'");
        assert_contains(&out, "remote 'c.example.com'");
        assert_contains(&out, "remote-random");
        assert_contains(&out, "allow-pull-fqdn");
        assert_contains(&out, "push-peer-info");
    }

    #[test]
    fn remote_with_port_and_proto() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "vpn.example.com:1195:tcp"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "remote 'vpn.example.com' 1195 tcp");
    }

    #[test]
    fn remote_with_proto_no_port_uses_1194() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "vpn.example.com::tcp"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "remote 'vpn.example.com' 1194 tcp");
    }

    #[test]
    fn missing_remote_errors() {
        let secrets = SecretsMap::new();
        let data = dict(&[("connection-type", "tls")]);
        let err = build_profile_string(&data, &secrets).expect_err("must error without remote");
        let msg = format!("{err}");
        assert!(
            msg.contains("remote"),
            "error should mention `remote`: {msg}"
        );
    }

    #[test]
    fn int_options_skipped_when_non_numeric() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("port", "not-a-port"),
            ("tunnel-mtu", "1400"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "tun-mtu 1400");
        assert!(
            !out.lines().any(|l| l.starts_with("port ")),
            "non-numeric port must be skipped: {out}"
        );
    }

    #[test]
    fn escape_arg_quotes_paths_with_spaces() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("ca", "/home/me/My Certs/ca.pem"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "ca '/home/me/My Certs/ca.pem'");
    }

    #[test]
    fn escape_arg_double_quotes_when_containing_single_quote() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("ca", "/tmp/it's-mine.pem"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "ca \"/tmp/it's-mine.pem\"");
    }

    #[test]
    fn comp_lzo_no_by_default_maps_to_no() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("comp-lzo", "no-by-default"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "comp-lzo no");
    }

    #[test]
    fn allow_compression_no_suppresses_lzo_and_compress() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("allow-compression", "no"),
            ("comp-lzo", "yes"),
            ("compress", "lz4"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "allow-compression no");
        assert!(
            !out.lines().any(|l| l.starts_with("comp-lzo ")),
            "allow-compression=no must suppress comp-lzo: {out}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("compress")),
            "allow-compression=no must suppress compress: {out}"
        );
    }

    #[test]
    fn verify_x509_name_with_type_prefix() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("verify-x509-name", "name-prefix:server"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "verify-x509-name server name-prefix");
    }

    #[test]
    fn pkcs12_collapsed_when_cert_equals_key_p12() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("ca", "/tmp/ignored.crt"),
            ("cert", "/tmp/bundle.p12"),
            ("key", "/tmp/bundle.p12"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "pkcs12 '/tmp/bundle.p12'");
        assert!(
            !out.lines().any(|l| l.starts_with("ca ")),
            "ca line must be suppressed by pkcs12 collapse: {out}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("cert ")),
            "cert line must be suppressed by pkcs12 collapse: {out}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("key ")),
            "key line must be suppressed by pkcs12 collapse: {out}"
        );
    }

    #[test]
    fn pkcs12_not_collapsed_when_cert_differs_from_key() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("cert", "/tmp/c.p12"),
            ("key", "/tmp/k.p12"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert!(
            !out.lines().any(|l| l.starts_with("pkcs12 ")),
            "different cert/key paths must NOT collapse: {out}"
        );
        assert_contains(&out, "cert '/tmp/c.p12'");
        assert_contains(&out, "key '/tmp/k.p12'");
    }

    #[test]
    fn tls_version_min_or_highest() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            ("tls-version-min", "1.2"),
            ("tls-version-min-or-highest", "yes"),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        // 1.2 contains '.', not in benign set, so it gets single-quoted.
        assert_contains(&out, "tls-version-min '1.2' or-highest");
    }

    /// Bracketed IPv6 remote splits into host + port + proto without
    /// colons leaking into the host slot.
    #[test]
    fn remote_bracketed_ipv6_splits_correctly() {
        let (host, port, proto) = parse_remote("[2001:db8::1]:1194:tcp");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, Some("1194"));
        assert_eq!(proto, Some("tcp"));
    }

    #[test]
    fn remote_bracketed_ipv6_no_port() {
        let (host, port, proto) = parse_remote("[fe80::1]");
        assert_eq!(host, "fe80::1");
        assert_eq!(port, None);
        assert_eq!(proto, None);
    }

    /// Extra `route` directives stashed in vpn.data round-trip into the
    /// emitted profile verbatim.
    #[test]
    fn extra_routes_emit_verbatim() {
        let secrets = SecretsMap::new();
        let data = dict(&[
            ("connection-type", "tls"),
            ("remote", "v"),
            (
                "nm-openvpn3-extra-routes",
                "route 10.0.0.0 255.0.0.0\nroute 192.168.1.0 255.255.255.0 10.0.0.1",
            ),
        ]);
        let out = build_profile_string(&data, &secrets).expect("build");
        assert_contains(&out, "route 10.0.0.0 255.0.0.0");
        assert_contains(&out, "route 192.168.1.0 255.255.255.0 10.0.0.1");
    }
}
