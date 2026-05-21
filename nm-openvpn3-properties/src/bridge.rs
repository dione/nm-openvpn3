//! Two-way bridge between [`OvpnConfig`] and libnm's `NMConnection`.
//!
//! Used by the `NMVpnEditorPlugin` import / export hooks and (via
//! callable Rust API) by the editor crate when wiring the widget state
//! back to the connection on Save.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

use glib_sys::{gboolean, gpointer, GFALSE, GTRUE};
use gobject_sys::{g_object_set, GObject};

use crate::import_export::{Directive, OvpnConfig};
use crate::libnm::*;

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
    let data = cfg.as_nm_data();

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
    let type_c = CString::new("vpn").unwrap();
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
    let auto_c = CString::new("auto").unwrap();
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
    for (k, v) in &data {
        let k_c = CString::new(k.as_str()).unwrap();
        let v_c = CString::new(v.as_str()).unwrap_or_default();
        nm_setting_vpn_add_data_item(s_vpn_cast, k_c.as_ptr(), v_c.as_ptr());
    }

    // Inline blobs (<ca>, <cert>, etc.) — write to disk in a sibling
    // directory of the .ovpn file and store the path in vpn.data.
    // openvpn3's import is happy to consume `ca /path/to/ca.pem` so
    // long as the file exists at activation time.
    //
    // We keep doing this even though `nm-openvpn3-profile` below pins
    // the service to the verbatim .ovpn file — the editor reads these
    // path keys to pre-fill its widgets, so without them the user
    // would see empty CA / cert / key fields on an imported
    // connection and might think the import lost the cert chain.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for d in &cfg.directives {
        if let Directive::Blob { name, body } = d {
            let id_safe: String = id
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect();
            let filename = format!("{id_safe}-{name}.pem");
            let blob_path = parent.join(&filename);
            // Best-effort write; if the directory isn't writable, we
            // still emit the key (pointing at a non-existent file) so
            // the editor surfaces the issue clearly rather than
            // dropping the inline data on the floor.
            let _ = std::fs::write(&blob_path, body);
            let key_c = CString::new(name.as_str()).unwrap();
            let path_c = CString::new(blob_path.to_string_lossy().as_ref()).unwrap();
            nm_setting_vpn_add_data_item(s_vpn_cast, key_c.as_ptr(), path_c.as_ptr());
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
    //
    // Caveat: if the user later deletes the original .ovpn, activation
    // will fail at the file-read step in plugin.rs::do_connect.  The
    // editor's file-existence indicator (red `error` CSS class)
    // surfaces the missing path on next edit — see editor.rs's
    // `refresh_path_validity`.
    if let Some(p) = path.to_str() {
        let key_c = CString::new("nm-openvpn3-profile").unwrap();
        let path_c = CString::new(p).unwrap();
        nm_setting_vpn_add_data_item(s_vpn_cast, key_c.as_ptr(), path_c.as_ptr());
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

/// Serialise an `NMConnection` to `.ovpn` text via [`OvpnConfig::from_nm_data`].
///
/// # Safety
/// `connection` must be a live libnm `NMConnection`.
pub unsafe fn connection_to_ovpn_text(connection: *mut NMConnection) -> String {
    let data = connection_to_nm_data(connection);
    OvpnConfig::from_nm_data(&data).emit()
}

/// Write `.ovpn` text to `path`.  Returns `GTRUE` / `GFALSE` for the
/// NM `export_to_file` interface hook.  Errors are reported through
/// `err_out` (typed as glib_sys::GError).
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
    match std::fs::write(path, text.as_bytes()) {
        Ok(()) => GTRUE,
        Err(e) => {
            set_error(
                err_out,
                NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                &format!("write {}: {e}", path.display()),
            );
            GFALSE
        }
    }
}
