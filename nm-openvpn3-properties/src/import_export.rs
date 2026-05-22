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

/// Heuristic match of the C tree's `is_pkcs12()` — file extension
/// only.  Matches `nm-openvpn3-service/src/build_profile.rs`.
pub fn is_pkcs12_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".p12") || lower.ends_with(".pfx")
}

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
        let cfg = OvpnConfig { directives };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Per-option validation to match C `do_import`'s sanity gates.
    /// Errors here surface to the caller (the libnm import hook) and
    /// reach the user as a clear "configuration error in <file>" dialog
    /// instead of an opaque openvpn3 Import failure at activation time.
    fn validate(&self) -> Result<()> {
        for d in &self.directives {
            let Directive::Option { name, args } = d else {
                continue;
            };
            match name.as_str() {
                "port" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("port requires a value"))?;
                    let n: u32 = v
                        .parse()
                        .map_err(|_| anyhow!("port '{v}' is not numeric"))?;
                    if !(1..=65535).contains(&n) {
                        return Err(anyhow!("port {n} out of range 1-65535"));
                    }
                }
                "proxy-port" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("proxy-port requires a value"))?;
                    let n: u32 = v
                        .parse()
                        .map_err(|_| anyhow!("proxy-port '{v}' is not numeric"))?;
                    if !(1..=65535).contains(&n) {
                        return Err(anyhow!("proxy-port {n} out of range 1-65535"));
                    }
                }
                "key-direction" | "static-key-direction" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("{name} requires a value"))?;
                    if !matches!(v.as_str(), "0" | "1") {
                        return Err(anyhow!("{name} must be 0 or 1, got '{v}'"));
                    }
                }
                "remote-cert-tls" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("remote-cert-tls requires a value"))?;
                    if !matches!(v.as_str(), "client" | "server") {
                        return Err(anyhow!("remote-cert-tls must be client|server, got '{v}'"));
                    }
                }
                "ns-cert-type" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("ns-cert-type requires a value"))?;
                    if !matches!(v.as_str(), "client" | "server") {
                        return Err(anyhow!("ns-cert-type must be client|server, got '{v}'"));
                    }
                }
                "mtu-disc" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("mtu-disc requires a value"))?;
                    if !matches!(v.as_str(), "no" | "maybe" | "yes") {
                        return Err(anyhow!("mtu-disc must be no|maybe|yes, got '{v}'"));
                    }
                }
                "comp-lzo" => {
                    if let Some(v) = args.first() {
                        if !matches!(v.as_str(), "yes" | "no" | "adaptive") {
                            return Err(anyhow!("comp-lzo must be yes|no|adaptive, got '{v}'"));
                        }
                    }
                }
                "proto" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("proto requires a value"))?;
                    if !matches!(
                        v.as_str(),
                        "udp"
                            | "tcp"
                            | "udp4"
                            | "udp6"
                            | "tcp4"
                            | "tcp6"
                            | "tcp-client"
                            | "tcp-server"
                            | "udp-client"
                            | "udp-server"
                            | "tcp4-client"
                            | "tcp6-client"
                            | "udp4-client"
                            | "udp6-client"
                    ) {
                        return Err(anyhow!("proto '{v}' is not recognised"));
                    }
                }
                "tls-version-min" | "tls-version-max" => {
                    let v = args
                        .first()
                        .ok_or_else(|| anyhow!("{name} requires a value"))?;
                    let base = v.strip_suffix(" or-highest").unwrap_or(v);
                    if !matches!(base, "1.0" | "1.1" | "1.2" | "1.3") {
                        return Err(anyhow!("{name} '{v}' is not a recognised TLS version"));
                    }
                }
                "keepalive" => {
                    if args.len() < 2 {
                        return Err(anyhow!("keepalive requires two integers"));
                    }
                    for (i, arg) in args.iter().take(2).enumerate() {
                        if arg.parse::<u32>().is_err() {
                            return Err(anyhow!(
                                "keepalive arg {} must be a non-negative integer, got '{arg}'",
                                i + 1
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
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

        // PKCS#12 collapse — when ca == cert == key and the path ends
        // in .p12 / .pfx, emit a single `pkcs12 <path>` directive (the
        // bundle carries all three).  Mirrors `build_profile.rs` and
        // the C exporter; without this, an editor save of an imported
        // PKCS#12 profile emits three separate ca/cert/key lines that
        // openvpn3 refuses to parse against a binary bundle.
        let cert = if needs_user_cert { get("cert") } else { None };
        let key = if needs_user_cert { get("key") } else { None };
        let ca = if is_tls_like { get("ca") } else { None };
        let pkcs12_collapse = matches!(
            (ca, cert, key),
            (Some(a), Some(c), Some(k)) if a == c && c == k && is_pkcs12_path(c)
        );
        if pkcs12_collapse {
            // unwrap_or_default is unreachable — pkcs12_collapse implies
            // cert is Some — but keep it defensive.
            push_opt(
                &mut directives,
                "pkcs12",
                vec![cert.unwrap_or_default().into()],
            );
        } else {
            if let Some(ca) = ca {
                push_opt(&mut directives, "ca", vec![ca.into()]);
            }
            if let Some(cert) = cert {
                push_opt(&mut directives, "cert", vec![cert.into()]);
            }
            if let Some(key) = key {
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

        // Extra static routes preserved from the imported .ovpn.  Each
        // line is `route <args…>`; tokenise and push as Directive::Option
        // so the emitter re-applies `push_escaped` per arg.  Failure to
        // tokenise (a malformed line we shouldn't have stored) is
        // skipped silently rather than failing the whole emit.
        if let Some(routes) = get("nm-openvpn3-extra-routes") {
            for line in routes.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let toks = match tokenize(line) {
                    Ok(t) if !t.is_empty() => t,
                    _ => continue,
                };
                let (name, rest) = toks.split_first().expect("non-empty per filter above");
                push_opt(&mut directives, name, rest.to_vec());
            }
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
                            // Legacy `comp-lzo no` arrives as "no";
                            // remap to the internal "no-by-default"
                            // sentinel the build_profile emitter knows
                            // to translate back to plain "no" (bgo
                            // #769177 workaround — plasma-nm wrote
                            // "no" for the unset state).
                            let v = a0.unwrap_or("yes");
                            let normalised = if v == "no" { "no-by-default" } else { v };
                            data.insert("comp-lzo".into(), normalised.into());
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
                                // params[3] = path to auth file
                                // (user/password, two lines).  Captured
                                // verbatim here; the path is resolved
                                // against the .ovpn dir and read into
                                // vpn.data['http-proxy-username'] +
                                // vpn.secrets['http-proxy-password'] in
                                // `bridge.rs` (which is the only call
                                // site with the source path).
                                // params (after stripping the option
                                // name) are: host, port, authfile,
                                // [retry|auth-method].  Capture the
                                // authfile for bridge.rs to resolve.
                                if let Some(authfile) = args.get(2) {
                                    data.insert("http-proxy-auth-file".into(), authfile.clone());
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
                        "ifconfig" => {
                            // Static-key mode requires `ifconfig <local>
                            // <remote>`.  Splitting into the two NM keys
                            // matches the C importer.
                            if let (Some(local), Some(remote)) = (a0, args.get(1)) {
                                data.insert("local-ip".into(), local.into());
                                data.insert("remote-ip".into(), remote.clone());
                            }
                        }
                        "route" => {
                            // Routes have no NM-vocabulary key on this
                            // plugin (C tree pushed them into
                            // NMSettingIPConfig directly, which would
                            // require additional libnm FFI we haven't
                            // bound here).  Preserve them in a
                            // newline-joined extras key so the editor
                            // round-trips them via the out-of-vocab
                            // replay path and `build_profile` re-emits
                            // them at activation.
                            let line = std::iter::once("route")
                                .chain(args.iter().map(String::as_str))
                                .collect::<Vec<&str>>()
                                .join(" ");
                            let entry: &mut String = data
                                .entry("nm-openvpn3-extra-routes".to_string())
                                .or_default();
                            if !entry.is_empty() {
                                entry.push('\n');
                            }
                            entry.push_str(&line);
                        }
                        "keepalive" => {
                            // `keepalive A B` → ping=A, ping-restart=B
                            // (matches C `do_import` ~L1395-1406).
                            if let (Some(a), Some(b)) = (a0, args.get(1)) {
                                data.insert("ping".into(), a.into());
                                data.insert("ping-restart".into(), b.clone());
                            }
                        }
                        // Hard-coded options the exporter emits but
                        // doesn't need to round-trip into vpn.data.
                        "nobind" | "auth-nocache" | "persist-key" | "persist-tun"
                        | "script-security" | "user" | "group" => {}
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
/// Iterates over `chars`, not raw bytes, so multi-byte UTF-8 codepoints
/// land in the token as a single `char` rather than being split into
/// Latin-1 fragments (the regression that mangled `verify-x509-name
/// "CN=Müller"` into `CN=MÃ¼ller`).
fn tokenize(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut it = line.chars().peekable();
    while let Some(&c) = it.peek() {
        if c.is_ascii_whitespace() {
            it.next();
            continue;
        }
        if c == ';' || c == '#' {
            // Comments terminate the line per openvpn parsing rules.
            break;
        }
        let mut token = String::new();
        if c == '"' || c == '\'' {
            // Quoted token.  Double-quotes honour backslash escapes;
            // single quotes are literal.  After the closing quote
            // openvpn stops parsing for the current word — concatenated
            // `'a'b` yields `a`, `b` (matches C `args_parse_line`).
            let quote = c;
            it.next(); // consume opening quote
            loop {
                let ch = it.next().ok_or_else(|| {
                    anyhow!(
                        "unterminated {} quote",
                        if quote == '"' { "double" } else { "single" }
                    )
                })?;
                if ch == quote {
                    break;
                }
                if quote == '"' && ch == '\\' {
                    let esc = it.next().ok_or_else(|| {
                        anyhow!("trailing escape backslash inside double-quoted token")
                    })?;
                    let mapped = match esc {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    };
                    token.push(mapped);
                    continue;
                }
                token.push(ch);
            }
        } else {
            // Unquoted token.  Backslash escapes the next character;
            // whitespace ends the token.
            while let Some(&ch) = it.peek() {
                if ch.is_ascii_whitespace() {
                    break;
                }
                it.next();
                if ch == '\\' {
                    let esc = it
                        .next()
                        .ok_or_else(|| anyhow!("trailing escape backslash"))?;
                    token.push(esc);
                    continue;
                }
                token.push(ch);
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

    /// Regression for the bytes-as-char tokenizer that mangled multi-
    /// byte UTF-8 sequences into Latin-1 mojibake.  An x509 name
    /// containing `ü` (UTF-8 `0xC3 0xBC`) must round-trip as a single
    /// codepoint.
    #[test]
    fn tokenize_preserves_utf8_codepoints() {
        let input = "verify-x509-name \"CN=Müller\"\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("verify-x509-name").map(String::as_str),
            Some("CN=Müller")
        );
    }

    /// Regression: from_nm_data must collapse ca == cert == key == .p12
    /// back into a single `pkcs12` directive.  Without this, the editor
    /// emit path produced three separate ca/cert/key lines openvpn3
    /// refuses to parse against a binary PKCS#12 bundle.
    #[test]
    fn from_nm_data_collapses_pkcs12() {
        let mut data = BTreeMap::new();
        data.insert("connection-type".into(), "tls".into());
        data.insert("remote".into(), "vpn.example".into());
        data.insert("ca".into(), "/etc/vpn/bundle.p12".into());
        data.insert("cert".into(), "/etc/vpn/bundle.p12".into());
        data.insert("key".into(), "/etc/vpn/bundle.p12".into());
        let out = OvpnConfig::from_nm_data(&data).emit();
        // push_escaped single-quotes paths that contain non-benign
        // characters (here `/` and `.`), so accept either form.
        let pkcs12_present = out
            .lines()
            .any(|l| l.starts_with("pkcs12 ") && l.contains("/etc/vpn/bundle.p12"));
        assert!(pkcs12_present, "no pkcs12 line in emit");
        // Confirm we did NOT emit the split form alongside it.
        for line in out.lines() {
            assert!(
                !(line.starts_with("ca ") && line.contains(".p12")),
                "unexpected separate ca line: {line}"
            );
            assert!(
                !(line.starts_with("cert ") && line.contains(".p12")),
                "unexpected separate cert line: {line}"
            );
        }
    }

    /// Regression: bare `ifconfig <local> <remote>` lands as the NM
    /// keys the static-key build_profile path expects.
    #[test]
    fn import_ifconfig_populates_local_remote_ip() {
        let input = "ifconfig 10.0.0.2 10.0.0.1\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("local-ip").map(String::as_str), Some("10.0.0.2"));
        assert_eq!(nm.get("remote-ip").map(String::as_str), Some("10.0.0.1"));
    }

    /// Regression: `keepalive A B` splits into ping=A, ping-restart=B
    /// instead of silently being dropped.
    #[test]
    fn import_keepalive_populates_ping_keys() {
        let input = "remote v\nkeepalive 10 60\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(nm.get("ping").map(String::as_str), Some("10"));
        assert_eq!(nm.get("ping-restart").map(String::as_str), Some("60"));
    }

    /// Regression: validation rejects out-of-range port.
    #[test]
    fn validate_rejects_port_overflow() {
        let input = "remote v\nport 99999\n";
        let err = OvpnConfig::parse(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("port"), "expected port error, got: {msg}");
    }

    /// Regression: validation rejects bogus key-direction.
    #[test]
    fn validate_rejects_bad_key_direction() {
        let input = "remote v\nkey-direction 2\n";
        let err = OvpnConfig::parse(input).unwrap_err();
        assert!(err.to_string().contains("key-direction"));
    }

    /// Regression: validation rejects unknown remote-cert-tls value.
    #[test]
    fn validate_rejects_bad_remote_cert_tls() {
        let input = "remote v\nremote-cert-tls maybe\n";
        let err = OvpnConfig::parse(input).unwrap_err();
        assert!(err.to_string().contains("remote-cert-tls"));
    }

    /// Regression: `route` directives that don't have a first-class
    /// NM key are preserved verbatim under `nm-openvpn3-extra-routes`
    /// so a Save-Save round-trip doesn't drop split-tunnel routes.
    #[test]
    fn import_route_preserves_extras() {
        let input =
            "remote v\nroute 10.0.0.0 255.0.0.0\nroute 192.168.1.0 255.255.255.0 10.0.0.1\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        let extras = nm
            .get("nm-openvpn3-extra-routes")
            .expect("routes preserved");
        assert!(extras.contains("route 10.0.0.0 255.0.0.0"));
        assert!(extras.contains("route 192.168.1.0 255.255.255.0 10.0.0.1"));
    }

    /// Regression: extra routes round-trip through from_nm_data as
    /// `route …` directives.
    #[test]
    fn from_nm_data_emits_extra_routes() {
        let mut data = BTreeMap::new();
        data.insert("connection-type".into(), "tls".into());
        data.insert("remote".into(), "v".into());
        data.insert(
            "nm-openvpn3-extra-routes".into(),
            "route 10.0.0.0 255.0.0.0".into(),
        );
        let out = OvpnConfig::from_nm_data(&data).emit();
        assert!(out
            .lines()
            .any(|l| l.starts_with("route ") && l.contains("10.0.0.0") && l.contains("255.0.0.0")));
    }

    /// Regression: http-proxy with authfile preserves the path as
    /// `http-proxy-auth-file` so bridge.rs can read it.
    #[test]
    fn import_http_proxy_preserves_authfile() {
        let input = "remote v\nhttp-proxy 10.1.1.1 8080 auth.txt\n";
        let cfg = OvpnConfig::parse(input).unwrap();
        let nm = cfg.as_nm_data();
        assert_eq!(
            nm.get("http-proxy-auth-file").map(String::as_str),
            Some("auth.txt")
        );
    }
}
