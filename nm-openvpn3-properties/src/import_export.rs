//! `.ovpn` parser + emitter.
//!
//! Mirrors the option set covered by the C tree's
//! `properties/import-export.c` (do_import + do_export) closely enough
//! to round-trip the fixtures under `properties/tests/conf/`.  See
//! `docs/UI-PORT.md` for the design intent.
//!
//! Parser strategy
//! ---------------
//! We model an `.ovpn` config as a sequence of [`Directive`]s — one
//! per non-comment line, preserving original order.  Each directive
//! holds the option name plus its tokenised arguments (or, for inline
//! blobs, the raw block body).  This is one step less "abstract" than
//! the C exporter's NM-key dictionary, but it gives us two wins:
//!
//! * Round-trip emission can preserve the file's original shape — no
//!   surprise reordering of options the user typed in by hand.
//! * Options the editor doesn't recognise survive an import → save
//!   cycle (the dreaded "lost my custom directive" footgun).
//!
//! [`OvpnConfig::as_nm_data`] is the bridge to NM's vpn.data dict; it
//! is intentionally lossy (only round-trips the option set the editor
//! UI exposes).  Round-trip identity is provided by the
//! [`Directive`] form, not the NM-data form.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};

/// Set of inline-blob option names we recognise.  Matches the
/// `INLINE_BLOB_*` defines in the C tree.
const INLINE_BLOB_NAMES: &[&str] = &[
    "ca",
    "cert",
    "extra-certs",
    "crl-verify",
    "key",
    "pkcs12",
    "secret",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
];

/// One non-empty line from an `.ovpn` file.  Either a regular option
/// (`name args…`) or an inline blob (`<name>…</name>`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Directive {
    /// `name arg1 arg2 …`
    Option { name: String, args: Vec<String> },
    /// `<name>\nbody\n</name>` — the `body` is verbatim (newlines
    /// preserved, leading whitespace per-line stripped to match C).
    Blob { name: String, body: String },
}

/// In-memory representation of an `.ovpn` config.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OvpnConfig {
    /// Directives in source order — emission walks this back to text.
    pub directives: Vec<Directive>,
}

impl OvpnConfig {
    /// Parse `.ovpn` text into a structured config.  Strips UTF-8 BOM
    /// and comments (`;` or `#`) the same way openvpn does.  Returns
    /// the line number on failure so editor UIs can highlight the
    /// offending row.
    pub fn parse(input: &str) -> Result<Self> {
        let mut directives = Vec::new();
        // Strip BOM if present.
        let input = input.strip_prefix("\u{feff}").unwrap_or(input);
        let mut lines = input.lines().enumerate().peekable();
        while let Some((lineno, line)) = lines.next() {
            let lineno = lineno + 1;
            let trimmed = line.trim_start();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with(';') || trimmed.starts_with('#') {
                continue;
            }
            let tokens = tokenize(trimmed).map_err(|e| anyhow!("line {lineno}: {e}"))?;
            if tokens.is_empty() {
                continue;
            }
            // openvpn lets users prefix any option with `--`.
            let first = tokens[0].strip_prefix("--").unwrap_or(&tokens[0]);

            // Inline blob: <name>…</name>
            if first.starts_with('<') && first.ends_with('>') {
                let inner = &first[1..first.len() - 1];
                let close = format!("</{inner}>");
                let mut body = String::new();
                let mut closed = false;
                for (_, blob_line) in lines.by_ref() {
                    if blob_line.trim_start().starts_with(&close) {
                        closed = true;
                        break;
                    }
                    body.push_str(blob_line);
                    body.push('\n');
                }
                if !closed {
                    return Err(anyhow!("line {lineno}: unterminated inline blob <{inner}>"));
                }
                if !INLINE_BLOB_NAMES.contains(&inner) {
                    return Err(anyhow!("line {lineno}: unsupported inline blob <{inner}>"));
                }
                directives.push(Directive::Blob {
                    name: inner.to_string(),
                    body,
                });
                continue;
            }

            let name = first.to_string();
            let args = tokens.into_iter().skip(1).collect();
            directives.push(Directive::Option { name, args });
        }
        Ok(OvpnConfig { directives })
    }

    /// Emit the config back to `.ovpn` text.  Regular options are
    /// shell-quoted per [`escape_arg`]; inline blobs are wrapped with
    /// their `<name>` … `</name>` tags and the body is preserved
    /// verbatim (trailing newline added if missing so the close tag
    /// always lands on its own line — what openvpn's parser expects).
    pub fn emit(&self) -> String {
        let mut out = String::with_capacity(512);
        for d in &self.directives {
            match d {
                Directive::Option { name, args } => {
                    out.push_str(name);
                    for a in args {
                        out.push(' ');
                        push_escaped(&mut out, a);
                    }
                    out.push('\n');
                }
                Directive::Blob { name, body } => {
                    out.push('<');
                    out.push_str(name);
                    out.push('>');
                    out.push('\n');
                    out.push_str(body);
                    if !body.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str("</");
                    out.push_str(name);
                    out.push('>');
                    out.push('\n');
                }
            }
        }
        out
    }

    /// Convenience: look up the first directive with a given option
    /// name.  Returns its argument list (empty if it's a flag).  Inline
    /// blobs are *not* matched — use [`Self::blob`] for those.
    pub fn option(&self, name: &str) -> Option<&[String]> {
        self.directives.iter().find_map(|d| match d {
            Directive::Option { name: n, args } if n == name => Some(args.as_slice()),
            _ => None,
        })
    }

    /// Convenience: look up an inline blob body by name.
    pub fn blob(&self, name: &str) -> Option<&str> {
        self.directives.iter().find_map(|d| match d {
            Directive::Blob { name: n, body } if n == name => Some(body.as_str()),
            _ => None,
        })
    }

    /// Synthesise an `.ovpn` directive stream from an NM-style
    /// `vpn.data` dict.  Inverse of [`Self::as_nm_data`] — emission
    /// order mirrors the C tree's `do_export_create` (client, remote,
    /// flags, certs, ciphers, MTU, …) so a Save-As followed by a fresh
    /// import lands at the same NMConnection.  Unknown keys are
    /// dropped (the caller is the editor, which already constrains
    /// the key set it persists).
    pub fn from_nm_data(data: &BTreeMap<String, String>) -> Self {
        let mut directives = Vec::new();
        let get = |k: &str| data.get(k).map(String::as_str).filter(|s| !s.is_empty());

        let connection_type = get("connection-type");
        let is_tls_like = matches!(
            connection_type,
            Some("tls") | Some("password") | Some("password-tls")
        );
        let is_password_like = matches!(connection_type, Some("password") | Some("password-tls"));
        let needs_user_cert = matches!(connection_type, Some("tls") | Some("password-tls"));

        fn push_opt(directives: &mut Vec<Directive>, name: &str, args: Vec<String>) {
            directives.push(Directive::Option {
                name: name.to_string(),
                args,
            });
        }
        fn push_flag(directives: &mut Vec<Directive>, name: &str) {
            directives.push(Directive::Option {
                name: name.to_string(),
                args: vec![],
            });
        }

        if is_tls_like {
            push_flag(&mut directives, "client");
        }

        if let Some(remotes) = get("remote") {
            for gw in remotes.split([' ', '\t', ',']) {
                let gw = gw.trim();
                if gw.is_empty() {
                    continue;
                }
                let mut it = gw.splitn(3, ':');
                let host = it.next().unwrap_or("").to_string();
                let port = it.next().filter(|s| !s.is_empty()).map(String::from);
                let proto = it.next().filter(|s| !s.is_empty()).map(String::from);
                let mut args = vec![host];
                if let Some(p) = port {
                    args.push(p);
                } else if proto.is_some() {
                    args.push("1194".to_string());
                }
                if let Some(p) = proto {
                    args.push(p);
                }
                push_opt(&mut directives, "remote", args);
            }
        }

        if get("remote-random") == Some("yes") {
            push_flag(&mut directives, "remote-random");
        }
        if get("remote-random-hostname") == Some("yes") {
            push_flag(&mut directives, "remote-random-hostname");
        }
        if get("allow-pull-fqdn") == Some("yes") {
            push_flag(&mut directives, "allow-pull-fqdn");
        }
        if get("tun-ipv6") == Some("yes") {
            push_flag(&mut directives, "tun-ipv6");
        }
        if get("push-peer-info") == Some("yes") {
            push_flag(&mut directives, "push-peer-info");
        }

        if is_tls_like {
            if let Some(ca) = get("ca") {
                push_opt(&mut directives, "ca", vec![ca.into()]);
            }
        }
        if needs_user_cert {
            if let Some(cert) = get("cert") {
                push_opt(&mut directives, "cert", vec![cert.into()]);
            }
            if let Some(key) = get("key") {
                push_opt(&mut directives, "key", vec![key.into()]);
            }
        }
        if is_password_like {
            push_flag(&mut directives, "auth-user-pass");
        }

        if connection_type == Some("static-key") {
            if let Some(secret) = get("static-key") {
                let mut args = vec![secret.into()];
                if let Some(dir) = get("static-key-direction") {
                    args.push(dir.into());
                }
                push_opt(&mut directives, "secret", args);
            }
        }

        let pairs_str: &[(&str, &str)] = &[
            ("reneg-seconds", "reneg-sec"),
            ("max-routes", "max-routes"),
            ("cipher", "cipher"),
            ("data-ciphers", "data-ciphers"),
            ("data-ciphers-fallback", "data-ciphers-fallback"),
            ("tls-cipher", "tls-cipher"),
            ("keysize", "keysize"),
            ("allow-compression", "allow-compression"),
            ("auth", "auth"),
            ("mtu-disc", "mtu-disc"),
            ("tunnel-mtu", "tun-mtu"),
            ("connect-timeout", "connect-timeout"),
            ("fragment-size", "fragment"),
            ("port", "port"),
            ("ping", "ping"),
            ("ping-exit", "ping-exit"),
            ("ping-restart", "ping-restart"),
            ("remote-cert-tls", "remote-cert-tls"),
            ("ns-cert-type", "ns-cert-type"),
            ("tls-remote", "tls-remote"),
            ("tls-version-max", "tls-version-max"),
            ("extra-certs", "extra-certs"),
        ];
        for (nm_key, ovpn_key) in pairs_str {
            if let Some(v) = get(nm_key) {
                push_opt(&mut directives, ovpn_key, vec![v.into()]);
            }
        }

        // comp-lzo / compress gated by allow-compression=no
        if get("allow-compression") != Some("no") {
            if let Some(lzo) = get("comp-lzo") {
                let lzo = if lzo == "no-by-default" { "no" } else { lzo };
                push_opt(&mut directives, "comp-lzo", vec![lzo.into()]);
            }
            if let Some(v) = get("compress") {
                if v == "yes" {
                    push_flag(&mut directives, "compress");
                } else {
                    push_opt(&mut directives, "compress", vec![v.into()]);
                }
            }
        }

        if get("float") == Some("yes") {
            push_flag(&mut directives, "float");
        }

        match get("mssfix") {
            Some("yes") => push_flag(&mut directives, "mssfix"),
            Some(v) => push_opt(&mut directives, "mssfix", vec![v.into()]),
            None => {}
        }

        if let (Some(local), Some(remote)) = (get("local-ip"), get("remote-ip")) {
            push_opt(
                &mut directives,
                "ifconfig",
                vec![local.into(), remote.into()],
            );
        }

        if is_tls_like {
            if let Some(x509) = get("verify-x509-name") {
                let args = if let Some((ty, name)) = x509.split_once(':') {
                    vec![name.into(), ty.into()]
                } else {
                    vec![x509.into()]
                };
                push_opt(&mut directives, "verify-x509-name", args);
            }
            if let Some(ta) = get("ta") {
                let mut args = vec![ta.into()];
                if let Some(dir) = get("ta-dir") {
                    args.push(dir.into());
                }
                push_opt(&mut directives, "tls-auth", args);
            }
            if let Some(k) = get("tls-crypt") {
                push_opt(&mut directives, "tls-crypt", vec![k.into()]);
            }
            if let Some(k) = get("tls-crypt-v2") {
                push_opt(&mut directives, "tls-crypt-v2", vec![k.into()]);
            }
            if let Some(v) = get("tls-version-min") {
                let mut args = vec![v.into()];
                if get("tls-version-min-or-highest") == Some("yes") {
                    args.push("or-highest".into());
                }
                push_opt(&mut directives, "tls-version-min", args);
            }
        }

        if let Some(file) = get("crl-verify-file") {
            push_opt(&mut directives, "crl-verify", vec![file.into()]);
        } else if let Some(dir) = get("crl-verify-dir") {
            push_opt(
                &mut directives,
                "crl-verify",
                vec![dir.into(), "dir".into()],
            );
        }

        // dev / dev-type / tap fall-back chain matches build_profile.
        let chosen_dev =
            get("dev")
                .or_else(|| get("dev-type"))
                .unwrap_or(if get("tap-dev") == Some("yes") {
                    "tap"
                } else {
                    "tun"
                });
        push_opt(&mut directives, "dev", vec![chosen_dev.into()]);
        if let Some(dt) = get("dev-type") {
            push_opt(&mut directives, "dev-type", vec![dt.into()]);
        }

        push_opt(
            &mut directives,
            "proto",
            vec![if get("proto-tcp") == Some("yes") {
                "tcp"
            } else {
                "udp"
            }
            .into()],
        );

        // Proxy emission.
        if let Some(pt) = get("proxy-type") {
            if let Some(server) = get("proxy-server") {
                match pt {
                    "http" => {
                        let port = get("proxy-port").unwrap_or("8080");
                        push_opt(
                            &mut directives,
                            "http-proxy",
                            vec![server.into(), port.into()],
                        );
                        if get("proxy-retry") == Some("yes") {
                            push_flag(&mut directives, "http-proxy-retry");
                        }
                    }
                    "socks" => {
                        let port = get("proxy-port").unwrap_or("1080");
                        push_opt(
                            &mut directives,
                            "socks-proxy",
                            vec![server.into(), port.into()],
                        );
                        if get("proxy-retry") == Some("yes") {
                            push_flag(&mut directives, "socks-proxy-retry");
                        }
                    }
                    _ => {}
                }
            }
        }

        // Hard-coded tail matching the C exporter.
        push_flag(&mut directives, "nobind");
        push_flag(&mut directives, "auth-nocache");
        push_opt(&mut directives, "script-security", vec!["2".into()]);
        push_flag(&mut directives, "persist-key");
        push_flag(&mut directives, "persist-tun");
        push_opt(&mut directives, "user", vec!["nm-openvpn3".into()]);
        push_opt(&mut directives, "group", vec!["nm-openvpn3".into()]);

        OvpnConfig { directives }
    }

    /// Project the config onto an NM-style `vpn.data` dict.  Lossy by
    /// design — only the option subset the editor exposes is mapped.
    /// Unknown options are *not* surfaced here; they survive via the
    /// [`Directive`] vector and are emitted unchanged on a Save-As.
    pub fn as_nm_data(&self) -> BTreeMap<String, String> {
        let mut data = BTreeMap::new();

        let mut have_client = false;
        let mut have_auth_user_pass = false;
        let mut have_cert = false;
        let mut have_key = false;
        let mut have_secret = false;
        let mut have_ca = false;

        for d in &self.directives {
            match d {
                Directive::Option { name, args } => {
                    let n = name.as_str();
                    let a0 = args.first().map(String::as_str);
                    match n {
                        "client" | "tls-client" => have_client = true,
                        "auth-user-pass" => have_auth_user_pass = true,
                        "dev" => {
                            if let Some(v) = a0 {
                                data.insert("dev".into(), v.into());
                            }
                        }
                        "dev-type" => {
                            if let Some(v) = a0 {
                                data.insert("dev-type".into(), v.into());
                            }
                        }
                        "proto" => match a0 {
                            Some(p) if !matches!(p, "udp" | "udp4" | "udp6") => {
                                data.insert("proto-tcp".into(), "yes".into());
                            }
                            _ => {}
                        },
                        "remote" => {
                            // Concatenate multiple `remote` lines into
                            // a single comma-joined NM key — the C
                            // exporter does the inverse on emit.
                            let entry: &mut String = data.entry("remote".to_string()).or_default();
                            if !entry.is_empty() {
                                entry.push(',');
                            }
                            let host = a0.unwrap_or("");
                            let port = args.get(1).map(String::as_str);
                            let proto = args.get(2).map(String::as_str);
                            entry.push_str(host);
                            if port.is_some() || proto.is_some() {
                                entry.push(':');
                                entry.push_str(port.unwrap_or(""));
                            }
                            if let Some(p) = proto {
                                entry.push(':');
                                entry.push_str(p);
                            }
                        }
                        "port" => {
                            if let Some(v) = a0 {
                                data.insert("port".into(), v.into());
                            }
                        }
                        "cipher" => {
                            if let Some(v) = a0 {
                                data.insert("cipher".into(), v.into());
                            }
                        }
                        "data-ciphers" => {
                            if let Some(v) = a0 {
                                data.insert("data-ciphers".into(), v.into());
                            }
                        }
                        "data-ciphers-fallback" => {
                            if let Some(v) = a0 {
                                data.insert("data-ciphers-fallback".into(), v.into());
                            }
                        }
                        "auth" => {
                            if let Some(v) = a0 {
                                data.insert("auth".into(), v.into());
                            }
                        }
                        "tls-cipher" => {
                            if let Some(v) = a0 {
                                data.insert("tls-cipher".into(), v.into());
                            }
                        }
                        "tun-mtu" => {
                            if let Some(v) = a0 {
                                data.insert("tunnel-mtu".into(), v.into());
                            }
                        }
                        "fragment" => {
                            if let Some(v) = a0 {
                                data.insert("fragment-size".into(), v.into());
                            }
                        }
                        "mssfix" => match a0 {
                            Some(v) => {
                                data.insert("mssfix".into(), v.into());
                            }
                            None => {
                                data.insert("mssfix".into(), "yes".into());
                            }
                        },
                        "ping" => {
                            if let Some(v) = a0 {
                                data.insert("ping".into(), v.into());
                            }
                        }
                        "ping-exit" => {
                            if let Some(v) = a0 {
                                data.insert("ping-exit".into(), v.into());
                            }
                        }
                        "ping-restart" => {
                            if let Some(v) = a0 {
                                data.insert("ping-restart".into(), v.into());
                            }
                        }
                        "reneg-sec" => {
                            if let Some(v) = a0 {
                                data.insert("reneg-seconds".into(), v.into());
                            }
                        }
                        "connect-timeout" | "server-poll-timeout" => {
                            if let Some(v) = a0 {
                                data.insert("connect-timeout".into(), v.into());
                            }
                        }
                        "comp-lzo" => {
                            data.insert("comp-lzo".into(), a0.unwrap_or("yes").into());
                        }
                        "compress" => {
                            data.insert("compress".into(), a0.unwrap_or("yes").into());
                        }
                        "allow-compression" => {
                            if let Some(v) = a0 {
                                data.insert("allow-compression".into(), v.into());
                            }
                        }
                        "float" => {
                            data.insert("float".into(), "yes".into());
                        }
                        "remote-random" => {
                            data.insert("remote-random".into(), "yes".into());
                        }
                        "remote-random-hostname" => {
                            data.insert("remote-random-hostname".into(), "yes".into());
                        }
                        "push-peer-info" => {
                            data.insert("push-peer-info".into(), "yes".into());
                        }
                        "tun-ipv6" => {
                            data.insert("tun-ipv6".into(), "yes".into());
                        }
                        "allow-pull-fqdn" => {
                            data.insert("allow-pull-fqdn".into(), "yes".into());
                        }
                        "ns-cert-type" => {
                            if let Some(v) = a0 {
                                data.insert("ns-cert-type".into(), v.into());
                            }
                        }
                        "remote-cert-tls" => {
                            if let Some(v) = a0 {
                                data.insert("remote-cert-tls".into(), v.into());
                            }
                        }
                        "tls-remote" => {
                            if let Some(v) = a0 {
                                data.insert("tls-remote".into(), v.into());
                            }
                        }
                        "verify-x509-name" => {
                            // Args are (name, [type]); NM stores as
                            // `type:name` (or just `name` when no type).
                            let name = a0.unwrap_or("");
                            let ty = args.get(1).map(String::as_str);
                            let value = match ty {
                                Some(t) => format!("{t}:{name}"),
                                None => name.to_string(),
                            };
                            data.insert("verify-x509-name".into(), value);
                        }
                        "tls-version-min" => {
                            if let Some(v) = a0 {
                                data.insert("tls-version-min".into(), v.into());
                            }
                            if args.get(1).map(String::as_str) == Some("or-highest") {
                                data.insert("tls-version-min-or-highest".into(), "yes".into());
                            }
                        }
                        "tls-version-max" => {
                            if let Some(v) = a0 {
                                data.insert("tls-version-max".into(), v.into());
                            }
                        }
                        "ca" => {
                            if let Some(v) = a0 {
                                data.insert("ca".into(), v.into());
                                have_ca = true;
                            }
                        }
                        "cert" => {
                            if let Some(v) = a0 {
                                data.insert("cert".into(), v.into());
                                have_cert = true;
                            }
                        }
                        "key" => {
                            if let Some(v) = a0 {
                                data.insert("key".into(), v.into());
                                have_key = true;
                            }
                        }
                        "pkcs12" => {
                            if let Some(v) = a0 {
                                // openvpn's pkcs12 contains CA + cert
                                // + key in a single file; NM stores it
                                // as cert == key == ca.
                                data.insert("ca".into(), v.into());
                                data.insert("cert".into(), v.into());
                                data.insert("key".into(), v.into());
                                have_ca = true;
                                have_cert = true;
                                have_key = true;
                            }
                        }
                        "secret" => {
                            if let Some(v) = a0 {
                                data.insert("static-key".into(), v.into());
                                have_secret = true;
                            }
                            if let Some(dir) = args.get(1) {
                                data.insert("static-key-direction".into(), dir.clone());
                            }
                        }
                        "tls-auth" => {
                            if let Some(v) = a0 {
                                data.insert("ta".into(), v.into());
                            }
                            if let Some(dir) = args.get(1) {
                                data.insert("ta-dir".into(), dir.clone());
                            }
                        }
                        "tls-crypt" => {
                            if let Some(v) = a0 {
                                data.insert("tls-crypt".into(), v.into());
                            }
                        }
                        "tls-crypt-v2" => {
                            if let Some(v) = a0 {
                                data.insert("tls-crypt-v2".into(), v.into());
                            }
                        }
                        "extra-certs" => {
                            if let Some(v) = a0 {
                                data.insert("extra-certs".into(), v.into());
                            }
                        }
                        "crl-verify" => {
                            if let Some(v) = a0 {
                                let key = if args.get(1).map(String::as_str) == Some("dir") {
                                    "crl-verify-dir"
                                } else {
                                    "crl-verify-file"
                                };
                                data.insert(key.into(), v.into());
                            }
                        }
                        "http-proxy" => {
                            if let Some(server) = a0 {
                                data.insert("proxy-type".into(), "http".into());
                                data.insert("proxy-server".into(), server.into());
                                if let Some(port) = args.get(1) {
                                    data.insert("proxy-port".into(), port.clone());
                                }
                            }
                        }
                        "socks-proxy" => {
                            if let Some(server) = a0 {
                                data.insert("proxy-type".into(), "socks".into());
                                data.insert("proxy-server".into(), server.into());
                                if let Some(port) = args.get(1) {
                                    data.insert("proxy-port".into(), port.clone());
                                }
                            }
                        }
                        // Hard-coded options the exporter emits but
                        // doesn't need to round-trip into vpn.data.
                        "nobind" | "auth-nocache" | "persist-key" | "persist-tun"
                        | "script-security" | "user" | "group" | "keepalive" => {}
                        _ => {} // Unknown — survives via Directive only.
                    }
                }
                Directive::Blob { name, body } => {
                    // For inline blobs we just record an indicator
                    // that the slot is filled; the actual content
                    // belongs in NM secrets / out-of-band file storage
                    // (the C editor writes the body to disk and stores
                    // a path here).  Round-trip identity uses the
                    // Directive vector instead.
                    let _ = body;
                    match name.as_str() {
                        "ca" => have_ca = true,
                        "cert" => have_cert = true,
                        "key" => have_key = true,
                        "secret" => have_secret = true,
                        _ => {}
                    }
                }
            }
        }

        // connection-type inference — same triage as the C importer.
        let contype = if have_secret {
            "static-key"
        } else if have_cert && have_key && have_auth_user_pass {
            "password-tls"
        } else if have_cert && have_key {
            "tls"
        } else if have_auth_user_pass {
            "password"
        } else if have_ca {
            "tls"
        } else {
            // Best-effort fall-back; matches the C importer's "tls" default.
            "tls"
        };
        data.insert("connection-type".into(), contype.into());

        // The C importer sets connection.id to the .ovpn basename; we
        // don't have a path here — leave it to the caller.

        let _ = have_client;
        data
    }
}

// ---------------------------------------------------------------------------
// Tokenizer + escape — porting C `args_parse_line` and `escape_arg`.
// ---------------------------------------------------------------------------

/// Tokenize a single non-empty input line into shell-style words,
/// honouring `'…'`, `"…"`, and `\<ch>` escapes as openvpn does.
fn tokenize(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace between tokens.
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Comment terminates the line per openvpn parsing rules.
        if bytes[i] == b';' || bytes[i] == b'#' {
            break;
        }
        let mut token = String::new();
        let first = bytes[i] as char;
        if first == '"' || first == '\'' {
            // Quoted token.  Double-quotes honour backslash escapes;
            // single quotes are literal.  After the closing quote
            // openvpn stops parsing for the current word — concatenated
            // `'a'b` yields `a`, `b` (matches the C `args_parse_line`
            // comment).
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if quote == b'"' && bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                    let escaped = bytes[i] as char;
                    let mapped = match escaped {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    };
                    token.push(mapped);
                    i += 1;
                    continue;
                }
                token.push(bytes[i] as char);
                i += 1;
            }
            if i >= bytes.len() {
                return Err(anyhow!(
                    "unterminated {} quote",
                    if quote == b'"' { "double" } else { "single" }
                ));
            }
            i += 1; // consume closing quote
        } else {
            // Unquoted token.  Backslash escapes the next character;
            // whitespace ends the token.
            loop {
                if i >= bytes.len() {
                    break;
                }
                let c = bytes[i];
                if (c as char).is_ascii_whitespace() {
                    break;
                }
                if c == b'\\' {
                    if i + 1 >= bytes.len() {
                        return Err(anyhow!("trailing escape backslash"));
                    }
                    i += 1;
                    token.push(bytes[i] as char);
                    i += 1;
                    continue;
                }
                token.push(c as char);
                i += 1;
            }
        }
        tokens.push(token);
    }
    Ok(tokens)
}

/// Port of C `escape_arg()`.  Keeps benign chars verbatim, otherwise
/// single-quotes (no inner `'`/newline) or double-quotes (escaped).
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

    #[test]
    fn tokenize_simple() {
        assert_eq!(
            tokenize("remote vpn.example.com 1194").unwrap(),
            vec!["remote", "vpn.example.com", "1194"]
        );
    }

    #[test]
    fn tokenize_strips_inline_comment() {
        assert_eq!(
            tokenize("dev tun ; the device").unwrap(),
            vec!["dev", "tun"]
        );
        assert_eq!(
            tokenize("dev tun # the device").unwrap(),
            vec!["dev", "tun"]
        );
    }

    #[test]
    fn tokenize_single_quoted() {
        assert_eq!(
            tokenize("ca '/etc/ovpn/ca.pem'").unwrap(),
            vec!["ca", "/etc/ovpn/ca.pem"]
        );
    }

    #[test]
    fn tokenize_double_quoted_with_escape() {
        assert_eq!(
            tokenize(r#"verify-x509-name "C=US, O=foo, CN=server" name"#).unwrap(),
            vec!["verify-x509-name", "C=US, O=foo, CN=server", "name"]
        );
    }

    #[test]
    fn tokenize_backslash_in_unquoted() {
        assert_eq!(
            tokenize(r"path C:\\foo\\bar").unwrap(),
            vec!["path", r"C:\foo\bar"]
        );
    }

    #[test]
    fn tokenize_unterminated_quote_errors() {
        let err = tokenize("remote 'vpn.example.com").unwrap_err();
        assert!(format!("{err}").contains("unterminated"));
    }

    #[test]
    fn parse_minimal_tls() {
        let input = "\
client
remote vpn.example.com 1194
proto udp
dev tun
ca /etc/ovpn/ca.pem
cert /etc/ovpn/c.crt
key /etc/ovpn/c.key
";
        let cfg = OvpnConfig::parse(input).unwrap();
        assert_eq!(cfg.option("client"), Some(&[] as &[String]));
        assert_eq!(cfg.option("remote").unwrap()[0], "vpn.example.com");
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("connection-type").map(String::as_str), Some("tls"));
        assert_eq!(
            nm.get("remote").map(String::as_str),
            Some("vpn.example.com:1194")
        );
        assert_eq!(nm.get("ca").map(String::as_str), Some("/etc/ovpn/ca.pem"));
    }

    #[test]
    fn parse_proto_tcp_sets_proto_tcp_yes() {
        let cfg = OvpnConfig::parse("remote v\nproto tcp\n").unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("proto-tcp").map(String::as_str), Some("yes"));
    }

    #[test]
    fn parse_comments_and_blanks_skipped() {
        let cfg = OvpnConfig::parse("; head\n\n# more\nremote v\n").unwrap();
        assert_eq!(cfg.directives.len(), 1);
    }

    #[test]
    fn parse_inline_blob_ca() {
        let input =
            "remote v\n<ca>\n-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n</ca>\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let body = cfg.blob("ca").expect("ca blob");
        assert!(body.contains("BEGIN CERTIFICATE"));
        assert!(body.contains("XX"));
    }

    #[test]
    fn parse_unterminated_blob_errors() {
        let err = OvpnConfig::parse("remote v\n<ca>\nXX\n").unwrap_err();
        assert!(format!("{err}").contains("unterminated"));
    }

    #[test]
    fn parse_unsupported_blob_errors() {
        let err = OvpnConfig::parse("<bogus>\nXX\n</bogus>\n").unwrap_err();
        assert!(format!("{err}").contains("unsupported"));
    }

    #[test]
    fn parse_skips_utf8_bom() {
        let cfg = OvpnConfig::parse("\u{feff}remote v\n").unwrap();
        assert_eq!(cfg.directives.len(), 1);
    }

    #[test]
    fn parse_dash_dash_prefix_stripped() {
        let cfg = OvpnConfig::parse("--remote v\n").unwrap();
        match &cfg.directives[0] {
            Directive::Option { name, .. } => assert_eq!(name, "remote"),
            _ => panic!("expected option"),
        }
    }

    #[test]
    fn emit_round_trip_minimal() {
        let input = "client\nremote vpn.example.com 1194\ndev tun\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let out = cfg.emit();
        assert!(out.contains("client"));
        // vpn.example.com has dots → escape_arg quotes it.
        assert!(out.contains("remote 'vpn.example.com' 1194"));
        assert!(out.contains("dev tun"));
    }

    #[test]
    fn emit_inline_blob_round_trip() {
        let input = "<ca>\nBLOB\n</ca>\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let out = cfg.emit();
        assert!(out.contains("<ca>"));
        assert!(out.contains("BLOB"));
        assert!(out.contains("</ca>"));
    }

    #[test]
    fn nm_data_inferred_connection_type_password_tls() {
        let input = "remote v\ncert c\nkey k\nauth-user-pass\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("connection-type").map(String::as_str),
            Some("password-tls")
        );
    }

    #[test]
    fn nm_data_inferred_connection_type_password_only() {
        let input = "remote v\nauth-user-pass\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("connection-type").map(String::as_str),
            Some("password")
        );
    }

    #[test]
    fn nm_data_inferred_connection_type_static_key() {
        let input = "remote v\nsecret /tmp/k 1\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("connection-type").map(String::as_str),
            Some("static-key")
        );
        assert_eq!(nm.get("static-key").map(String::as_str), Some("/tmp/k"));
        assert_eq!(
            nm.get("static-key-direction").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn nm_data_verify_x509_name_with_type_split() {
        let input = "remote v\nverify-x509-name server name-prefix\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("verify-x509-name").map(String::as_str),
            Some("name-prefix:server")
        );
    }

    #[test]
    fn nm_data_tls_version_min_or_highest() {
        let input = "remote v\ntls-version-min 1.2 or-highest\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("tls-version-min").map(String::as_str), Some("1.2"));
        assert_eq!(
            nm.get("tls-version-min-or-highest").map(String::as_str),
            Some("yes")
        );
    }

    #[test]
    fn nm_data_pkcs12_fills_ca_cert_key() {
        let input = "remote v\npkcs12 /tmp/foo.p12\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("ca").map(String::as_str), Some("/tmp/foo.p12"));
        assert_eq!(nm.get("cert").map(String::as_str), Some("/tmp/foo.p12"));
        assert_eq!(nm.get("key").map(String::as_str), Some("/tmp/foo.p12"));
    }

    #[test]
    fn nm_data_http_proxy() {
        let input = "remote v\nhttp-proxy proxy.example.com 8080\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("proxy-type").map(String::as_str), Some("http"));
        assert_eq!(
            nm.get("proxy-server").map(String::as_str),
            Some("proxy.example.com")
        );
        assert_eq!(nm.get("proxy-port").map(String::as_str), Some("8080"));
    }

    #[test]
    fn nm_data_multi_remote_joined() {
        let input = "remote a.example.com\nremote b.example.com 1195 tcp\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("remote").map(String::as_str),
            Some("a.example.com,b.example.com:1195:tcp")
        );
    }

    #[test]
    fn emit_preserves_unknown_directive() {
        // Editor save/load round-trip: an unknown option survives.
        let input = "remote v\nmy-custom-option foo\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let out = cfg.emit();
        assert!(out.contains("my-custom-option foo"));
    }
}
