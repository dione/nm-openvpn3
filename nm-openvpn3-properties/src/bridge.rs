//! Two-way bridge between [`OvpnConfig`] and libnm's `NMConnection`.
//!
//! Used by the `NMVpnEditorPlugin` import / export hooks and (via
//! callable Rust API) by the editor crate when wiring the widget state
//! back to the connection on Save.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::c_char;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use glib_sys::{gboolean, gpointer, GFALSE, GTRUE};
use gobject_sys::{g_object_set, GObject};
use zeroize::{Zeroize, Zeroizing};

use crate::import_export::{Directive, OvpnConfig};
use crate::libnm::*;

/// Locate (creating if absent) the per-user cert directory under
/// `$HOME/.cert/nm-openvpn3` and force its mode to 0700.  Mirrors the
/// C tree's `nm_vpn_plugin_utils_get_cert_path("nm-openvpn3")`.
fn secure_cert_dir() -> std::io::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable unset",
        )
    })?;
    let dir = PathBuf::from(home).join(".cert").join("nm-openvpn3");
    std::fs::create_dir_all(&dir)?;
    // Best-effort tighten — if the dir already existed with looser
    // perms, this brings it back to user-only.  set_permissions follows
    // symlinks; a malicious actor who can sit on $HOME/.cert/nm-openvpn3
    // already has access to the parent dir, so we accept that.
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    Ok(dir)
}

/// Write `body` to `path` with `O_NOFOLLOW | O_CREAT | O_EXCL`, mode
/// 0600.  Existing target is removed first so a re-import overwrites
/// stale state, but the O_EXCL after that point fails closed if a
/// concurrent process raced us to plant a symlink between the unlink
/// and the open.  Returns the path on success.
fn write_blob_securely(path: &Path, body: &[u8]) -> std::io::Result<()> {
    // Tolerate "not present" — we want create-new on the open below.
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

/// Read a pinned `.ovpn` profile path defensively for export: open
/// `O_NOFOLLOW | O_CLOEXEC` so a symlink can't redirect the read,
/// fstat the fd to confirm a regular file (rejects FIFOs / devices),
/// and cap the read at 1 MiB.  Returns `None` (caller falls back to a
/// structured emit) on any rejection or I/O error.
fn read_profile_securely(path: &Path) -> Option<String> {
    use std::io::Read;
    const MAX_PROFILE_BYTES: u64 = 1 << 20;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let md = file.metadata().ok()?;
    if !md.is_file() || md.len() > MAX_PROFILE_BYTES {
        return None;
    }
    let mut buf = String::with_capacity((md.len() as usize).saturating_add(1));
    let mut limited = (&file).take(MAX_PROFILE_BYTES + 1);
    limited.read_to_string(&mut buf).ok()?;
    if buf.len() as u64 > MAX_PROFILE_BYTES {
        return None;
    }
    Some(buf)
}

/// Defensive open + bounded read for a small user-supplied credentials
/// file: `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` (no symlink redirect, no
/// blocking on a FIFO), fstat confirms a regular file (rejects FIFOs /
/// devices), and the read is capped at `max_bytes`.  Returns the body
/// in a `Zeroizing` so credential text is scrubbed on drop.
fn read_small_regular_file(
    path: &Path,
    max_bytes: u64,
) -> std::io::Result<Zeroizing<String>> {
    use std::io::Read;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let md = file.metadata()?;
    if !md.is_file() || md.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "not a regular file within the {max_bytes}-byte cap (len={}, regular={})",
                md.len(),
                md.is_file()
            ),
        ));
    }
    let mut buf = Zeroizing::new(String::with_capacity(
        (md.len() as usize).saturating_add(1),
    ));
    let mut limited = (&file).take(max_bytes + 1);
    limited.read_to_string(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file grew past the size cap during read",
        ));
    }
    Ok(buf)
}

/// Build a fresh `NMConnection` from an `.ovpn` text + the connection
/// id derived from the file's basename.  Returns NULL + populated
/// GError on failure, mirroring the C tree's `do_import` contract.
///
/// # Safety
/// Caller passes ownership of the returned pointer.  libnm refcounts
/// `NMConnection` via GObject; we hand back a `floating` reference
/// per `nm_simple_connection_new`, NM sinks it.
pub unsafe fn ovpn_text_to_connection(
    path: &Path,
    text: &str,
) -> Result<*mut NMConnection, String> {
    let cfg = OvpnConfig::parse(text).map_err(|e| format!("parse: {e}"))?;
    let mut data = cfg.as_nm_data();

    let connection = nm_simple_connection_new();
    if connection.is_null() {
        return Err("nm_simple_connection_new returned NULL".into());
    }

    // Connection setting — `id` from basename (sans extension), `type`
    // = "vpn", which selects NMSettingVpn as the per-type settings
    // surface.
    let s_con = nm_setting_connection_new();
    nm_connection_add_setting(connection, s_con);
    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("openvpn3");
    let id_c = CString::new(id).unwrap_or_else(|_| CString::new("openvpn3").unwrap());
    let type_c = CString::new("vpn").expect("static string");
    g_object_set(
        s_con.cast::<GObject>(),
        NM_SETTING_CONNECTION_ID.as_ptr().cast(),
        id_c.as_ptr(),
        ptr::null::<u8>(),
    );
    g_object_set(
        s_con.cast::<GObject>(),
        NM_SETTING_CONNECTION_TYPE.as_ptr().cast(),
        type_c.as_ptr(),
        ptr::null::<u8>(),
    );

    // IP4 — auto, matches the C importer.
    let s_ip4 = nm_setting_ip4_config_new();
    nm_connection_add_setting(connection, s_ip4);
    let auto_c = CString::new("auto").expect("static string");
    g_object_set(
        s_ip4.cast::<GObject>(),
        NM_SETTING_IP_CONFIG_METHOD.as_ptr().cast(),
        auto_c.as_ptr(),
        ptr::null::<u8>(),
    );

    // VPN setting — service-type = our openvpn3 well-known name, then
    // all vpn.data items the .ovpn parse projected.
    let s_vpn = nm_setting_vpn_new();
    nm_connection_add_setting(connection, s_vpn);
    let svc_c = CStr::from_bytes_with_nul(NM_VPN_SERVICE_TYPE_OPENVPN3).expect("static c-string");
    g_object_set(
        s_vpn.cast::<GObject>(),
        NM_SETTING_VPN_SERVICE_TYPE.as_ptr().cast(),
        svc_c.as_ptr(),
        ptr::null::<u8>(),
    );
    let s_vpn_cast = s_vpn.cast::<NMSettingVpn>();

    // HTTP-proxy authfile resolution — the .ovpn import preserved the
    // path verbatim under "http-proxy-auth-file".  Resolve against
    // this .ovpn's parent dir, read the first two lines, populate
    // vpn.data['http-proxy-username'] + vpn.secrets['http-proxy-
    // password'] (AGENT_OWNED).  Mirrors C `parse_http_proxy_auth`.
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    if let Some(authfile) = data.remove("http-proxy-auth-file") {
        // Resolve the authfile strictly within the .ovpn's own
        // directory.  A crafted profile could otherwise name an
        // absolute path or climb out with `..` to slurp the first two
        // lines of an arbitrary readable file into the connection's
        // proxy credentials.  Honour ONLY a bare filename (a single
        // Normal component) beside the .ovpn: O_NOFOLLOW on the open
        // below guards just the final component, so a relative name
        // with a separator (`subdir/creds`) could still traverse a
        // symlinked intermediate dir (`subdir -> /etc`).  Rejecting any
        // path component closes that off entirely.
        let af = Path::new(&authfile);
        let safe_name = matches!(
            af.components().collect::<Vec<_>>().as_slice(),
            [std::path::Component::Normal(_)]
        );
        if !safe_name {
            // Surface the rejection — a silent drop looks like a
            // mis-parse to a user who legitimately pointed at a creds
            // path with a directory component.
            eprintln!("nm-openvpn3: refusing http-proxy-auth-file that is not a bare filename: {authfile}");
        } else {
            let af_path = parent_dir.join(af);
            // The bare-filename guard above means there is no
            // intermediate directory to traverse; the hardened open
            // (O_NOFOLLOW | O_NONBLOCK + regular-file check + size cap)
            // blocks a symlink AT the final component (creds ->
            // /etc/shadow, yielding ELOOP), a FIFO planted to hang the
            // GUI thread, and an oversized file.  The body lives in a
            // Zeroizing so the plaintext credential is scrubbed from
            // the heap on drop.
            const MAX_AUTHFILE_BYTES: u64 = 16 * 1024;
            match read_small_regular_file(&af_path, MAX_AUTHFILE_BYTES) {
                Ok(contents) => {
                    let mut iter = contents.lines();
                    let user = iter.next().unwrap_or("").trim().to_string();
                    let pass = Zeroizing::new(iter.next().unwrap_or("").trim().to_string());
                    if !user.is_empty() {
                        data.insert("http-proxy-username".into(), user);
                    }
                    if !pass.is_empty() {
                        if let (Ok(k), Ok(v)) = (
                            CString::new("http-proxy-password"),
                            CString::new(pass.as_str()),
                        ) {
                            nm_setting_vpn_add_secret(s_vpn_cast, k.as_ptr(), v.as_ptr());
                            let _ = nm_setting_set_secret_flags(
                                s_vpn.cast::<NMSetting>(),
                                k.as_ptr(),
                                NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                ptr::null_mut(),
                            );
                            // libnm copied the value into its own store;
                            // scrub our plaintext CString before it drops.
                            let mut vb = v.into_bytes_with_nul();
                            vb.zeroize();
                        }
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    eprintln!("nm-openvpn3: refusing symlinked http-proxy-auth-file: {authfile}");
                }
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    eprintln!(
                        "nm-openvpn3: refusing http-proxy-auth-file '{authfile}': {e}"
                    );
                }
                // Missing or unreadable — skip silently, as before.
                Err(_) => {}
            }
        }
        // The key was removed from `data` above; either way it shouldn't
        // survive in vpn.data as a key NM doesn't recognise.
    }

    for (k, v) in &data {
        let Ok(k_c) = CString::new(k.as_str()) else {
            // NUL in a key name is a programmer error in our parsers;
            // skip rather than corrupt vpn.data.
            continue;
        };
        let Ok(v_c) = CString::new(v.as_str()) else {
            // NUL in a value means the .ovpn produced a malformed
            // token (or the field is a binary blob misclassified).
            // Skip the value entirely — better than silently
            // truncating to empty, which would let blank passwords
            // through.
            continue;
        };
        nm_setting_vpn_add_data_item(s_vpn_cast, k_c.as_ptr(), v_c.as_ptr());
    }

    // Inline blobs (<ca>, <cert>, <key>, <pkcs12>, …) — write to a
    // per-user cert dir (`~/.cert/nm-openvpn3/`) with mode 0600 and
    // `O_NOFOLLOW | O_EXCL`, so the resulting file is never world-
    // readable and a symlink-race cannot redirect the write into an
    // attacker-controlled target.  Files in the parent of the source
    // .ovpn used to be the destination; that was unsafe on /tmp, USB
    // mounts, and Flatpak host-files mounts.
    //
    // Inline `<pkcs12>` bodies are base64-encoded DER per openvpn —
    // decode before writing or openvpn3 will refuse the bundle.  Any
    // other blob is written raw.
    let id_safe: String = id
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    // The alnum-collapse above maps distinct ids onto the same stem
    // ("vpn-prod" and "vpn_prod" both become "vpn_prod"), so a second
    // import would silently overwrite the first connection's blob files
    // (write_blob_securely unlinks before create_new).  Append a short
    // hash of the *full* id to keep distinct connections in distinct
    // files.  FNV-1a, not DefaultHasher: the latter's output changes
    // across Rust releases, so a toolchain bump would re-hash the same
    // id to a new filename and orphan the previous 0600 blob.
    let id_disc: String = {
        let mut h: u32 = 0x811c_9dc5;
        for b in id.as_bytes() {
            h ^= u32::from(*b);
            h = h.wrapping_mul(0x0100_0193);
        }
        format!("{h:08x}")
    };
    let blob_dir_result = secure_cert_dir();
    for d in &cfg.directives {
        let Directive::Blob { name, body } = d else {
            continue;
        };
        let filename = format!("{id_safe}-{id_disc}-{name}.pem");
        let blob_path = match &blob_dir_result {
            Ok(dir) => dir.join(&filename),
            // Cert dir unavailable — fail closed.  The old fallback wrote
            // next to the source .ovpn, but that directory is often a
            // USB stick / Flatpak host mount on vfat/exfat where the
            // 0600 mode bits are silently ignored, leaving private-key
            // material world-readable.  Skip the blob (and its data-item)
            // instead; the editor's path-validity indicator flags the
            // now-empty key on next edit.
            Err(e) => {
                eprintln!(
                    "nm-openvpn3: no secure cert dir ({e}); skipping inline blob '{name}' rather than risk a world-readable write"
                );
                continue;
            }
        };
        let bytes: Vec<u8> = if name == "pkcs12" {
            // openvpn wraps inline pkcs12 in line-broken base64
            // ("-----BEGIN PKCS12-----"-style wrapping, ~64 cols).
            // base64::engine::general_purpose::STANDARD is strict and
            // rejects embedded whitespace, so strip every whitespace
            // char before decoding.  This matches what C g_base64_decode
            // does on the same body.
            let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            match BASE64.decode(cleaned.as_bytes()) {
                Ok(b) => b,
                // Base64 garbage — fall through to writing the raw text
                // so the user still sees *something* and the editor
                // flags the file; matches C's "import succeeds, fails
                // at activation" failure mode rather than dropping the
                // blob silently.
                Err(_) => body.as_bytes().to_vec(),
            }
        } else {
            body.as_bytes().to_vec()
        };
        // A failed write must NOT leave a data item pointing at a
        // missing file — that imports "successfully" and then fails at
        // activation with an opaque missing-cert error.  Skip the item
        // and tell the user why.
        if let Err(e) = write_blob_securely(&blob_path, &bytes) {
            eprintln!(
                "nm-openvpn3: failed to write inline blob '{name}' to {}: {e}; dropping it from the connection",
                blob_path.display()
            );
            continue;
        }
        let Ok(key_c) = CString::new(name.as_str()) else {
            continue;
        };
        let Ok(path_c) = CString::new(blob_path.to_string_lossy().as_ref()) else {
            continue;
        };
        nm_setting_vpn_add_data_item(s_vpn_cast, key_c.as_ptr(), path_c.as_ptr());
        // PKCS#12 collapse — C tree stores the bundle path under all
        // three of ca/cert/key.  Mirror that so the inferred
        // connection-type ("password-tls"/"tls"/etc.) lines up with
        // the file the editor will surface.
        if name == "pkcs12" {
            for triple in ["ca", "cert", "key"] {
                if let Ok(k) = CString::new(triple) {
                    nm_setting_vpn_add_data_item(s_vpn_cast, k.as_ptr(), path_c.as_ptr());
                }
            }
        }
    }

    // Pin `nm-openvpn3-profile` to the original .ovpn path the user
    // imported from.  At activation time the service prefers this
    // path over `build_profile_string` synthesis, so the file is fed
    // verbatim to openvpn3 Import — preserving modern syntax
    // (tls-crypt-v2 inline blob, peer-fingerprint, data-ciphers
    // ordering) that our synthesizer can lose.  The per-key vpn.data
    // values written above remain so the editor still has structured
    // state to render.
    if let Some(p) = path.to_str() {
        if let (Ok(k), Ok(v)) = (CString::new("nm-openvpn3-profile"), CString::new(p)) {
            nm_setting_vpn_add_data_item(s_vpn_cast, k.as_ptr(), v.as_ptr());
        }
    }

    Ok(connection)
}

/// Walk an `NMConnection`'s vpn.data dict into a `BTreeMap`.  Calls
/// `nm_setting_vpn_foreach_data_item` so we don't depend on libnm's
/// internal hash-table representation.
///
/// # Safety
/// `connection` must point at a live `NMConnection` produced by libnm.
pub unsafe fn connection_to_nm_data(connection: *mut NMConnection) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    let s_vpn = nm_connection_get_setting_vpn(connection);
    if s_vpn.is_null() {
        return out;
    }

    unsafe extern "C" fn collect(key: *const c_char, value: *const c_char, user_data: gpointer) {
        if key.is_null() || value.is_null() || user_data.is_null() {
            return;
        }
        let map = &mut *user_data.cast::<BTreeMap<String, String>>();
        if let (Ok(k), Ok(v)) = (CStr::from_ptr(key).to_str(), CStr::from_ptr(value).to_str()) {
            map.insert(k.to_string(), v.to_string());
        }
    }

    nm_setting_vpn_foreach_data_item(
        s_vpn,
        collect,
        (&mut out as *mut BTreeMap<String, String>).cast(),
    );
    out
}

/// Serialise an `NMConnection` to `.ovpn` text.  Prefers the verbatim
/// content of the file pinned in `vpn.data['nm-openvpn3-profile']`
/// (matches what the service feeds openvpn3 at activation, so the
/// re-exported file describes the *real* connection — including any
/// tls-crypt-v2 / peer-fingerprint / inline-blob syntax the structured
/// projection cannot reconstruct).  Falls back to a structured emit
/// from vpn.data when the profile path is unset or unreadable; in the
/// fallback case a one-line warning is prepended so the recipient is
/// aware the export is lossy.
///
/// # Safety
/// `connection` must be a live libnm `NMConnection`.
pub unsafe fn connection_to_ovpn_text(connection: *mut NMConnection) -> String {
    let data = connection_to_nm_data(connection);

    if let Some(profile_path) = data.get("nm-openvpn3-profile") {
        if !profile_path.is_empty() {
            // SECURITY: the pinned profile path is stored connection
            // state that can be influenced by an attacker who can write
            // the system-connection / settings; a plain read_to_string
            // would follow a symlink swap on this path and stream an
            // arbitrary file (e.g. /etc/shadow) into the user-chosen
            // export destination.  Open O_NOFOLLOW, fstat the fd to
            // confirm a regular file, and cap the read — the same
            // hardening the import side (iface_import_from_file) uses.
            if let Some(text) = read_profile_securely(Path::new(profile_path)) {
                return text;
            }
        }
    }

    let body = OvpnConfig::from_nm_data(&data).emit();
    format!(
        "# Exported by NetworkManager-openvpn3 from vpn.data — modern\n\
         # openvpn3 options stored only in the original .ovpn (tls-crypt-v2,\n\
         # peer-fingerprint, inline blobs) cannot be reconstructed and are\n\
         # NOT included in this file.\n\
         {body}"
    )
}

/// Write `.ovpn` text to `path` atomically (temp + rename) so an ENOSPC
/// or signal cannot leave the caller's previous file half-written.
/// Returns `GTRUE` / `GFALSE` for the NM `export_to_file` interface
/// hook.  Errors are reported through `err_out`.
///
/// # Safety
/// `err_out` follows the standard GError contract — NULL or a pointer
/// to a NULL GError pointer.
pub unsafe fn export_connection_to_path(
    connection: *mut NMConnection,
    path: &Path,
    err_out: *mut *mut glib_sys::GError,
) -> gboolean {
    let text = connection_to_ovpn_text(connection);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_name = match path.file_name() {
        Some(n) => format!(".{}.tmp", n.to_string_lossy()),
        None => ".export.tmp".to_string(),
    };
    let tmp_path = parent.join(&tmp_name);
    // The exported profile may carry inline <key> / <tls-crypt> /
    // <tls-crypt-v2> blobs (connection_to_ovpn_text re-emits the pinned
    // profile verbatim).  A plain std::fs::write creates the temp at
    // 0666 & ~umask (typically 0644), leaving private-key material
    // world-readable.  Write it 0600 with O_NOFOLLOW | O_EXCL — the
    // same hardening write_blob_securely applies on import — then
    // rename onto the target (which inherits the temp's mode).
    // Reuse the import-side hardened write (unlink-first, create_new +
    // O_NOFOLLOW, mode 0600, fsync) so the two secret-write paths can't
    // drift, then rename onto the target.
    let write_secure = || -> std::io::Result<()> {
        write_blob_securely(&tmp_path, text.as_bytes())?;
        std::fs::rename(&tmp_path, path)
    };
    match write_secure() {
        Ok(()) => GTRUE,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            set_error(
                err_out,
                NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                &format!("write {}: {e}", path.display()),
            );
            GFALSE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nmovpn3_{}_{}_{}",
            tag,
            std::process::id(),
            line!()
        ))
    }

    #[test]
    fn blob_written_0600_and_overwrites() {
        let p = tmp("blob");
        let _ = std::fs::remove_file(&p);
        write_blob_securely(&p, b"first").unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Re-import overwrites (unlink-first) rather than erroring on O_EXCL.
        write_blob_securely(&p, b"second").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"second");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn read_profile_rejects_symlink_accepts_regular() {
        let real = tmp("real");
        std::fs::write(&real, b"client\nremote x 1194\n").unwrap();
        assert!(read_profile_securely(&real).is_some());

        let link = tmp("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // O_NOFOLLOW → symlink open fails → None.
        assert!(read_profile_securely(&link).is_none());

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&real);
    }

    #[test]
    fn small_file_read_accepts_regular_file() {
        let p = tmp("auth_ok");
        std::fs::write(&p, b"user\npass\n").unwrap();
        let body = read_small_regular_file(&p, 16 * 1024).unwrap();
        assert_eq!(body.as_str(), "user\npass\n");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn small_file_read_rejects_fifo_without_blocking() {
        let p = tmp("auth_fifo");
        let _ = std::fs::remove_file(&p);
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // A FIFO with no writer: a plain open(O_RDONLY) would block the
        // GUI thread forever.  Must error out instead.
        assert!(read_small_regular_file(&p, 16 * 1024).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn small_file_read_rejects_oversized() {
        let p = tmp("auth_big");
        std::fs::write(&p, vec![b'x'; 1025]).unwrap();
        assert!(read_small_regular_file(&p, 1024).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn read_profile_rejects_oversized() {
        let big = tmp("big");
        // 1 MiB + 1 byte exceeds the cap.
        let data = vec![b'x'; (1usize << 20) + 1];
        std::fs::write(&big, &data).unwrap();
        assert!(read_profile_securely(&big).is_none());
        let _ = std::fs::remove_file(&big);
    }
}
