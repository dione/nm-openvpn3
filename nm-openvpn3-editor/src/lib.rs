//! NetworkManager openvpn3 GTK editor — round 3 scaffold.
//!
//! Produces `libnm-vpn-plugin-openvpn3-editor.so`.  NM's libnm
//! cdylib (`libnm-vpn-plugin-openvpn3.so`) dlopens this and calls
//! `nm_vpn_editor_factory_openvpn3` to instantiate an `NMVpnEditor`
//! GObject wrapping the editor widget tree.
//!
//! Round-3 deliverable: a working AdwPreferencesPage with **one** real
//! page (General — connection-type, gateway, CA/cert/key, user/pass)
//! plus the GObject + interface plumbing.  Round-4 builds out
//! Advanced/Security/TLS/Proxies/Misc tabs and validation.
//!
//! Honest limitations:
//!
//! * Compile-clean and structurally complete, but the libnm GType +
//!   GInterface registration has not been runtime-tested against an
//!   actual NM/gnome-control-center session.  Treat first runtime
//!   activation as a smoke-test gate — see `docs/UI-PORT.md` round-3
//!   notes.
//! * The widget set is intentionally narrow; saving a connection
//!   touches the keys this UI exposes and leaves everything else
//!   alone (no destructive clear-and-rewrite).

#![allow(clippy::missing_safety_doc)]

mod editor;

use std::ptr;

use glib_sys::GError;
use gobject_sys::GObject;

use nm_vpn_plugin_openvpn3::libnm::{set_error, NMConnection, NMVpnEditor};

/// `nm_vpn_editor_factory_openvpn3` — the symbol the libnm plugin
/// cdylib `g_module_symbol`s.  Constructs a fresh editor GObject
/// (which implements the `NMVpnEditor` interface) pre-filled with
/// state from `connection`.
///
/// # Safety
/// libnm-defined C ABI.  `connection` and `error` follow the standard
/// libnm contracts.
#[no_mangle]
pub unsafe extern "C" fn nm_vpn_editor_factory_openvpn3(
    _plugin: *mut std::ffi::c_void,
    connection: *mut NMConnection,
    error: *mut *mut GError,
) -> *mut NMVpnEditor {
    editor::ffi_guard(ptr::null_mut(), || unsafe {
        if connection.is_null() {
            set_error(
                error,
                nm_vpn_plugin_openvpn3::libnm::NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                "editor factory called with NULL connection",
            );
            return ptr::null_mut();
        }
        editor::new_editor(connection, error) as *mut NMVpnEditor
    })
}

/// Editor crate entrypoint usable from in-process Rust tests (the
/// runtime path always enters via the `extern "C"` factory).  Returns
/// a raw `GObject*` that the caller must `g_object_unref` once the
/// dialog closes.
///
/// # Safety
/// `connection` must be a live libnm `NMConnection`.
pub unsafe fn new_editor_object(
    connection: *mut NMConnection,
    error: *mut *mut GError,
) -> *mut GObject {
    editor::new_editor(connection, error)
}
