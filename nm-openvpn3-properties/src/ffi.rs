//! `libnm-vpn-plugin-openvpn3.so` factory entrypoint.
//!
//! NM dlopens our `.so` and resolves the `nm_vpn_editor_plugin_factory`
//! symbol declared here, then calls it to obtain an `NMVpnEditorPlugin`
//! GObject.  We construct one from [`crate::plugin`].

use std::ptr;

use glib_sys::GError;
use gobject_sys::GObject;

use crate::libnm::set_error;
use crate::plugin::plugin_new;

/// `NMVpnEditorPlugin *nm_vpn_editor_plugin_factory (GError **error)`.
///
/// # Safety
/// libnm-defined C ABI.  `error` is either NULL or a pointer to a
/// NULL GError pointer (the GError contract).
#[no_mangle]
pub unsafe extern "C" fn nm_vpn_editor_plugin_factory(error: *mut *mut GError) -> *mut GObject {
    crate::plugin::ffi_guard(ptr::null_mut(), || unsafe {
    // ABI guard.  Our vtable layout for NMVpnEditorPluginInterface
    // assumes the `get_vt` field that landed in libnm 1.4 and the
    // `notify_plugin_info_set` slot that's stable since 1.30.  An
    // older libnm has a shorter struct and writing the trailing
    // function pointers would scribble past the allocation.  Refuse
    // to load cleanly rather than corrupt memory.
    let version = crate::libnm::nm_utils_version();
    if version < crate::libnm::NM_LIBNM_VERSION_MIN {
        set_error(
            error,
            crate::libnm::NM_OPENVPN3_PLUGIN_ERROR_FAILED,
            &format!(
                "libnm {}.{}.{} is too old; need 1.30+",
                (version >> 16) & 0xff,
                (version >> 8) & 0xff,
                version & 0xff
            ),
        );
        return ptr::null_mut();
    }

    let obj = plugin_new();
    if obj.is_null() {
        set_error(
            error,
            crate::libnm::NM_OPENVPN3_PLUGIN_ERROR_FAILED,
            "plugin_new returned NULL",
        );
        return ptr::null_mut();
    }
    obj
    })
}
