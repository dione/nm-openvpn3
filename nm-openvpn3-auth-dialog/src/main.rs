//! nm-openvpn3-auth-dialog (Rust, external-UI-only).
//!
//! NM spawns this helper when it needs the user to supply VPN
//! credentials.  We implement only the external-UI mode (the GKeyFile
//! protocol over stdout) — the standard GTK NMAVpnPasswordDialog flow
//! is left to a future port if it turns out a working desktop NM
//! agent isn't reachable.  GNOME Shell, plasma-nm, nm-applet and
//! other front-ends all drive external-UI mode natively so this
//! covers the realistic deployment matrix without dragging gtk4 +
//! libsecret bindings into the build.
//!
//! Protocol contract:
//!
//! Stdin — libnm `nm_vpn_service_plugin_read_vpn_details()` format:
//!   ```
//!   DATA_KEY=key1\n DATA_VAL=v1\n DATA_KEY=key2\n DATA_VAL=v2\n
//!   \n
//!   SECRET_KEY=k\n SECRET_VAL=v\n
//!   \n
//!   DONE\n
//!   ```
//!
//! Stdout — GKeyFile-style entries NM consumes back as
//! NMSettingVpn::secrets:
//!   ```
//!   [VPN Plugin UI]
//!   Version=2
//!   Description=...
//!   Title=...
//!
//!   [password]
//!   Value=
//!   Label=Password
//!   IsSecret=true
//!   ShouldAsk=true
//!   ForceEcho=false
//!   ```

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::Parser;
use zeroize::Zeroizing;

// Must match shared/nm-service-defines.h.
const NM_VPN_SERVICE_TYPE_OPENVPN3: &str = "org.freedesktop.NetworkManager.openvpn3";

const KEY_PASSWORD: &str = "password";
const KEY_CERTPASS: &str = "cert-pass";
const KEY_HTTP_PROXY_PASSWORD: &str = "http-proxy-password";
const KEY_CHALLENGE_RESPONSE: &str = "challenge-response";
const KEY_NOSECRET: &str = "no-secret";

const KEY_CONNECTION_TYPE: &str = "connection-type";
const KEY_KEY: &str = "key";
const KEY_PROXY_SERVER: &str = "proxy-server";

const CONTYPE_TLS: &str = "tls";
const CONTYPE_PASSWORD: &str = "password";
const CONTYPE_PASSWORD_TLS: &str = "password-tls";

const HINT_CHALLENGE_RESPONSE_ECHO: &str = "x-dynamic-challenge-echo:challenge-response";
const HINT_CHALLENGE_RESPONSE_NOECHO: &str = "x-dynamic-challenge:challenge-response";
const VPN_MSG_TAG: &str = "x-vpn-message:";

#[derive(Parser, Debug)]
#[command(version, about = "NetworkManager openvpn3 auth dialog (Rust)")]
struct Args {
    /// Reprompt for passwords (NM sets this on retry).
    #[arg(short = 'r', long = "reprompt")]
    _reprompt: bool,

    /// UUID of the VPN connection.
    #[arg(short = 'u', long = "uuid")]
    uuid: Option<String>,

    /// Display name of the VPN connection.
    #[arg(short = 'n', long = "name")]
    name: Option<String>,

    /// Service type — must equal NM_VPN_SERVICE_TYPE_OPENVPN3.
    #[arg(short = 's', long = "service")]
    service: Option<String>,

    /// Whether NM allows interactive prompting (vs. only returning
    /// cached creds).
    #[arg(short = 'i', long = "allow-interaction")]
    allow_interaction: bool,

    /// External-UI mode — REQUIRED.  Standard GTK flow not ported.
    #[arg(long = "external-ui-mode")]
    external_ui_mode: bool,

    /// Hints from the VPN service plugin (vpn-secrets keys + optional
    /// x-vpn-message prompt).  May be repeated.
    #[arg(short = 't', long = "hint")]
    hints: Vec<String>,
}

#[derive(Default, Debug)]
struct Needed {
    password: bool,
    certpass: bool,
    proxypass: bool,
    challenge_response: bool,
    challenge_response_echo: bool,
    prompt: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nm-openvpn3-auth-dialog: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// This dialog is a standalone binary (not dlopened into a host), so
/// unlike the editor it may own the process-wide text domain.
fn gettext_init() {
    gettextrs::setlocale(gettextrs::LocaleCategory::LcAll, "");
    let localedir =
        std::env::var("NM_OPENVPN3_LOCALEDIR").unwrap_or_else(|_| "/usr/share/locale".to_string());
    let _ = gettextrs::bindtextdomain("nm-openvpn3", localedir);
    let _ = gettextrs::textdomain("nm-openvpn3");
}

fn tr(s: &str) -> String {
    gettextrs::gettext(s)
}

fn run() -> Result<()> {
    let args = Args::parse();
    gettext_init();

    if args.uuid.is_none() || args.name.is_none() || args.service.is_none() {
        bail!("--uuid, --name and --service are all required");
    }
    if args.service.as_deref() != Some(NM_VPN_SERVICE_TYPE_OPENVPN3) {
        bail!(
            "this dialog only works with service '{}'; got '{}'",
            NM_VPN_SERVICE_TYPE_OPENVPN3,
            args.service.as_deref().unwrap_or("")
        );
    }
    if !args.external_ui_mode {
        // Standard GTK flow not ported — bail loudly so NM falls
        // through to whatever fallback it has, instead of returning
        // an empty payload that the user would mistake for "no
        // secrets needed".
        bail!("only --external-ui-mode is supported");
    }

    // `_secrets` is parsed off stdin so we honour libnm's protocol, but
    // the dialog never echoes credentials back; the `Zeroizing` wrapper
    // scrubs the bytes from process memory at end of scope, before the
    // process exits.
    let (data, _secrets) =
        read_vpn_details(io::stdin().lock()).context("reading vpn details from stdin")?;

    let needed = needs(&data, &args.hints);

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if !needed.password && !needed.certpass && !needed.proxypass && !needed.challenge_response {
        write_no_secret(&mut out)?;
        return Ok(());
    }

    let prompt = needed.prompt.clone().unwrap_or_else(|| {
        // `needed.prompt` (when set) is the server's x-vpn-message — left
        // verbatim.  Only our fallback string is translated; keep the
        // `{name}` placeholder in the msgid so translators control word
        // order around it.
        tr("You need to authenticate to access the Virtual Private Network \u{201C}{name}\u{201D}.")
            .replace("{name}", args.name.as_deref().unwrap_or(""))
    });

    write_eui_keyfile(&mut out, &prompt, &needed, args.allow_interaction)?;
    Ok(())
}

type DataMap = HashMap<String, String>;
type SecretsMap = HashMap<String, Zeroizing<String>>;

/// Parse stdin per libnm's `nm_vpn_service_plugin_read_vpn_details`
/// format.  Returns (data, secrets).  Either may be empty.  Secret
/// values are wrapped in `Zeroizing` so their bytes are scrubbed when
/// the returned map is dropped.
fn read_vpn_details<R: BufRead>(reader: R) -> Result<(DataMap, SecretsMap)> {
    let mut data: DataMap = HashMap::new();
    let mut secrets: SecretsMap = HashMap::new();

    let mut current_key: Option<(String, bool)> = None; // (key, is_secret)
    let mut data_mode = true;

    for line in reader.lines() {
        // Wrap the raw line in Zeroizing: a `SECRET_VAL=<password>` line
        // holds plaintext credentials in this buffer; without scrubbing,
        // the bytes linger on the heap after the String drops (only the
        // post-split value was previously zeroized).
        let line = Zeroizing::new(line.context("reading stdin line")?);
        let line = line.as_str();
        if line == "DONE" {
            break;
        }
        if line.is_empty() {
            // Empty line separates data from secrets, and terminates
            // the secrets block too (the next line is "DONE").
            data_mode = false;
            current_key = None;
            continue;
        }
        if let Some((prefix, value)) = line.split_once('=') {
            match (prefix, &current_key) {
                ("DATA_KEY", _) => current_key = Some((value.to_string(), false)),
                ("DATA_VAL", Some((k, false))) => {
                    data.insert(k.clone(), value.to_string());
                    current_key = None;
                }
                ("SECRET_KEY", _) => current_key = Some((value.to_string(), true)),
                ("SECRET_VAL", Some((k, true))) => {
                    secrets.insert(k.clone(), Zeroizing::new(value.to_string()));
                    current_key = None;
                }
                _ => {
                    // Unknown / out-of-order — silently ignore so a
                    // libnm format bump doesn't crash us.
                }
            }
        } else if !data_mode {
            // Defensive: secret values may legitimately contain '=';
            // libnm always re-prefixes them, but allow tolerant skip.
        }
    }
    Ok((data, secrets))
}

fn secret_required_flag(data: &HashMap<String, String>, key: &str) -> bool {
    // NMSettingSecretFlags is encoded in vpn.data under "<key>-flags".
    // NOT_REQUIRED = 0x4 — only this bit lets activation proceed without
    // the secret.  NOT_SAVED (0x2) means "don't store it, but DO ask
    // every time", so it must still prompt.  Treat missing/unparseable
    // as required.
    let flag_key = format!("{key}-flags");
    let raw = match data.get(&flag_key) {
        Some(v) => v.as_str(),
        None => return true,
    };
    let bits: u32 = raw.parse().unwrap_or(0);
    (bits & 0x4) == 0
}

fn is_encrypted_keyfile_path(path: &str) -> bool {
    // Port of utils.c `is_encrypted()`.  We open the file and look for
    // markers that mean the key is password-protected:
    //   * legacy PEM: `Proc-Type: 4,ENCRYPTED`
    //   * PKCS#8:    `BEGIN ENCRYPTED PRIVATE KEY`
    //   * PKCS#12:   binary `.p12` / `.pfx` containers always carry a
    //                MAC password, so prompt unconditionally.
    // On any I/O error we fall back to "yes" — over-prompting is
    // harmless (the user dismisses), under-prompting hangs the
    // activation.
    // Cap to a sane PEM upper bound.  NM hands us the path verbatim
    // from `vpn.data['key']`; a hostile or misconfigured profile that
    // points at `/dev/urandom` or a 10 GiB blob must not stall the
    // dialog (NM gives up on us and leaves activation broken).  Any
    // real PEM/PKCS#12 keyfile fits comfortably in 256 KiB.
    const MAX_KEYFILE_BYTES: u64 = 256 * 1024;
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".p12") || lower.ends_with(".pfx") {
        return true;
    }
    // Open once with O_NONBLOCK, then fstat the fd and read through a
    // cap.  O_NONBLOCK keeps a FIFO / special-file path from blocking
    // the open (the fstat below then rejects non-regular files);
    // operating on the fd (not the path) also removes the metadata→read
    // TOCTOU window the previous two-syscall form had.
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return true,
    };
    let md = match file.metadata() {
        Ok(m) => m,
        Err(_) => return true,
    };
    if !md.is_file() || md.len() > MAX_KEYFILE_BYTES {
        // Non-regular or pathologically large — over-prompt, don't read.
        return true;
    }
    let mut bytes = Vec::new();
    if (&file)
        .take(MAX_KEYFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return true;
    }
    if bytes.len() as u64 > MAX_KEYFILE_BYTES {
        // File grew past the cap during the read: play safe.
        return true;
    }
    // PEM markers are 7-bit ASCII; binary PKCS#12 was handled by the
    // extension check above, so anything not-quite-UTF-8 here is
    // garbage we don't want to scan.
    let text = std::str::from_utf8(&bytes).unwrap_or("");
    text.contains("Proc-Type: 4,ENCRYPTED") || text.contains("BEGIN ENCRYPTED PRIVATE KEY")
}

fn needs(data: &HashMap<String, String>, hints: &[String]) -> Needed {
    let mut out = Needed::default();

    // Hints take precedence — when NM passes them we ask only for
    // what was requested (mirrors C `get_passwords_required`).
    if !hints.is_empty() {
        for h in hints {
            if let Some(msg) = h.strip_prefix(VPN_MSG_TAG) {
                if out.prompt.is_none() {
                    out.prompt = Some(msg.to_string());
                }
                continue;
            }
            match h.as_str() {
                KEY_PASSWORD => out.password = true,
                KEY_CERTPASS => out.certpass = true,
                KEY_HTTP_PROXY_PASSWORD => out.proxypass = true,
                // Bare challenge-response is what the Rust service
                // emits (slot_to_vpn_key); the dynamic-challenge
                // prefixed variants are kept for compatibility with
                // anything that follows the openvpn3 raw slot naming.
                KEY_CHALLENGE_RESPONSE | HINT_CHALLENGE_RESPONSE_NOECHO => {
                    out.challenge_response = true;
                }
                HINT_CHALLENGE_RESPONSE_ECHO => {
                    out.challenge_response = true;
                    out.challenge_response_echo = true;
                }
                _ => {}
            }
        }
        return out;
    }

    // No hints — infer from vpn.data.
    let Some(ctype) = data.get(KEY_CONNECTION_TYPE) else {
        return out;
    };
    match ctype.as_str() {
        CONTYPE_TLS | CONTYPE_PASSWORD_TLS => {
            if ctype == CONTYPE_PASSWORD_TLS && secret_required_flag(data, KEY_PASSWORD) {
                out.password = true;
            }
            if let Some(key_path) = data.get(KEY_KEY) {
                if is_encrypted_keyfile_path(key_path) {
                    out.certpass = true;
                }
            }
        }
        CONTYPE_PASSWORD if secret_required_flag(data, KEY_PASSWORD) => {
            out.password = true;
        }
        _ => {}
    }
    if let Some(proxy) = data.get(KEY_PROXY_SERVER) {
        if !proxy.is_empty() && secret_required_flag(data, KEY_HTTP_PROXY_PASSWORD) {
            out.proxypass = true;
        }
    }
    out
}

fn write_no_secret(out: &mut impl Write) -> Result<()> {
    writeln!(out, "[VPN Plugin UI]")?;
    writeln!(out, "Version=2")?;
    writeln!(out)?;
    writeln!(out, "[{KEY_NOSECRET}]")?;
    writeln!(out, "Value=true")?;
    writeln!(out, "Label=")?;
    writeln!(out, "IsSecret=true")?;
    writeln!(out, "ShouldAsk=false")?;
    writeln!(out, "ForceEcho=false")?;
    out.flush()?;
    Ok(())
}

fn write_eui_keyfile(
    out: &mut impl Write,
    prompt: &str,
    needed: &Needed,
    allow_interaction: bool,
) -> Result<()> {
    writeln!(out, "[VPN Plugin UI]")?;
    writeln!(out, "Version=2")?;
    writeln!(out, "Description={}", escape(prompt))?;
    writeln!(out, "Title={}", escape(&tr("Authentication required")))?;

    write_entry(
        out,
        KEY_PASSWORD,
        "",
        &tr("Password"),
        false,
        needed.password && allow_interaction,
    )?;
    write_entry(
        out,
        KEY_CERTPASS,
        "",
        &tr("Certificate password"),
        false,
        needed.certpass && allow_interaction,
    )?;
    write_entry(
        out,
        KEY_HTTP_PROXY_PASSWORD,
        "",
        &tr("HTTP proxy password"),
        false,
        needed.proxypass && allow_interaction,
    )?;
    // Always emit the bare vpn-secrets key NM uses in its dict — the
    // service's `new_secrets` looks up `challenge-response` here, not
    // the dynamic-challenge prefix.  The ForceEcho flag carries the
    // echo/noecho distinction the prefix used to encode.
    write_entry(
        out,
        KEY_CHALLENGE_RESPONSE,
        "",
        &tr("Challenge response"),
        needed.challenge_response_echo,
        needed.challenge_response && allow_interaction,
    )?;
    out.flush()?;
    Ok(())
}

fn write_entry(
    out: &mut impl Write,
    key: &str,
    value: &str,
    label: &str,
    force_echo: bool,
    should_ask: bool,
) -> Result<()> {
    writeln!(out)?;
    writeln!(out, "[{key}]")?;
    writeln!(out, "Value={}", escape(value))?;
    writeln!(out, "Label={}", escape(label))?;
    writeln!(out, "IsSecret=true")?;
    writeln!(out, "ShouldAsk={should_ask}")?;
    writeln!(out, "ForceEcho={force_echo}")?;
    Ok(())
}

/// Match GKeyFile string escaping rules (only the chars libnm cares
/// about: backslash + newline + tab + carriage-return).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_data_and_secrets_blocks() {
        let stdin = b"DATA_KEY=connection-type\nDATA_VAL=password\n\nSECRET_KEY=password\nSECRET_VAL=p\n\nDONE\n";
        let (d, s) = read_vpn_details(&stdin[..]).unwrap();
        assert_eq!(
            d.get("connection-type").map(String::as_str),
            Some("password")
        );
        assert_eq!(s.get("password").map(|v| v.as_str()), Some("p"));
    }

    #[test]
    fn hints_override_inference() {
        let data = HashMap::new();
        let hints = vec!["password".into(), "x-vpn-message:hi".into()];
        let n = needs(&data, &hints);
        assert!(n.password);
        assert_eq!(n.prompt.as_deref(), Some("hi"));
    }

    #[test]
    fn password_tls_requires_password() {
        let mut data = HashMap::new();
        data.insert("connection-type".into(), "password-tls".into());
        let n = needs(&data, &[]);
        assert!(n.password);
    }

    #[test]
    fn flag_not_required_suppresses_password() {
        // NOT_REQUIRED = 0x4 lets activation proceed without the secret.
        let mut data = HashMap::new();
        data.insert("connection-type".into(), "password".into());
        data.insert("password-flags".into(), "4".into());
        let n = needs(&data, &[]);
        assert!(!n.password);
    }

    /// Regression for B3: NOT_SAVED (0x2) means "don't store, ask every
    /// time" — it MUST still prompt.  The pre-fix code masked 0x2 and
    /// silently suppressed the prompt for this (security-conscious) setup.
    #[test]
    fn flag_not_saved_still_prompts() {
        let mut data = HashMap::new();
        data.insert("connection-type".into(), "password".into());
        data.insert("password-flags".into(), "2".into());
        assert!(needs(&data, &[]).password);
        // AGENT_OWNED (0x1) alone also requires a prompt path.
        data.insert("password-flags".into(), "1".into());
        assert!(needs(&data, &[]).password);
    }

    #[test]
    fn proxy_server_present_needs_proxypass() {
        let mut d = HashMap::new();
        d.insert("connection-type".into(), "tls".into());
        d.insert("proxy-server".into(), "proxy.example:8080".into());
        assert!(needs(&d, &[]).proxypass);
        d.insert("proxy-server".into(), "".into());
        assert!(!needs(&d, &[]).proxypass);
    }

    #[test]
    fn challenge_echo_hint_sets_force_echo_flag() {
        let n = needs(&HashMap::new(), &[HINT_CHALLENGE_RESPONSE_ECHO.into()]);
        assert!(n.challenge_response && n.challenge_response_echo);
        let n2 = needs(&HashMap::new(), &[HINT_CHALLENGE_RESPONSE_NOECHO.into()]);
        assert!(n2.challenge_response && !n2.challenge_response_echo);
    }

    #[test]
    fn escape_neutralises_keyfile_metacharacters() {
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("line1\nline2"), "line1\\nline2");
        assert_eq!(escape("a\tb\rc"), "a\\tb\\rc");
        assert_eq!(escape("plain text"), "plain text");
    }

    /// An untrusted x-vpn-message must not break out of the Description
    /// line and forge extra KeyFile entries.
    #[test]
    fn description_line_cannot_be_broken_by_vpn_message() {
        let needed = Needed {
            password: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_eui_keyfile(&mut buf, "evil\nShouldAsk=true", &needed, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Description=evil\\nShouldAsk=true"));
    }

    /// allow_interaction=false (non-interactive activation) must emit
    /// ShouldAsk=false for every entry even when the secret is needed.
    #[test]
    fn non_interactive_emits_no_should_ask() {
        let needed = Needed {
            password: true,
            certpass: true,
            proxypass: true,
            challenge_response: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_eui_keyfile(&mut buf, "prompt", &needed, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("ShouldAsk=true"), "{s}");
    }

    #[test]
    fn interactive_asks_only_needed() {
        let needed = Needed {
            password: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_eui_keyfile(&mut buf, "p", &needed, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.matches("ShouldAsk=true").count(), 1);
    }

    /// A secret value containing '=' (base64/JWT tokens) must survive
    /// intact (split on the FIRST '='), and out-of-order lines must be
    /// dropped, not mis-filed across the data/secret boundary.
    #[test]
    fn read_vpn_details_edge_cases() {
        let stdin = b"DATA_KEY=connection-type\nDATA_VAL=password\n\nSECRET_KEY=password\nSECRET_VAL=a=b==c\n\nDONE\n";
        let (_d, s) = read_vpn_details(&stdin[..]).unwrap();
        assert_eq!(s.get("password").map(|v| v.as_str()), Some("a=b==c"));

        let bad = b"DATA_KEY=k\nSECRET_VAL=leak\nDATA_VAL=v\n\nDONE\n";
        let (d, s2) = read_vpn_details(&bad[..]).unwrap();
        assert!(s2.is_empty(), "out-of-order SECRET_VAL must not be filed");
        assert_eq!(d.get("k").map(String::as_str), Some("v"));
    }

    #[test]
    fn write_no_secret_emits_marker_block() {
        let mut buf = Vec::new();
        write_no_secret(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("[no-secret]"));
        assert!(s.contains("Value=true"));
        assert!(s.contains("ShouldAsk=false"));
    }
}
