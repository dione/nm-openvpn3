//! `NMOpenvpn3EditorPlugin` — Rust port of the C tree's
//! `Openvpn3EditorPlugin` GObject.
//!
//! Implements the `NMVpnEditorPlugin` GInterface so NM (and tooling
//! like `nmcli connection import`) can discover the plugin, read its
//! metadata, import/export `.ovpn` files, and (in round 3, when the
//! editor cdylib lands) load the GTK editor.
//!
//! Type registration is hand-written against `gobject-sys` because we
//! cannot use the high-level `glib` Rust subclassing macros — those
//! require the parent type to be expressible in Rust, and
//! `NMVpnEditorPlugin` is a libnm-defined GInterface.

use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use glib_sys::{gboolean, gpointer, GError, GFALSE};
use gobject_sys::{
    g_object_class_override_property, g_object_new, GObject, GObjectClass, GParamSpec,
    GTypeInstance, GValue, G_TYPE_FLAG_NONE, G_TYPE_OBJECT,
};

use crate::bridge::{connection_to_nm_data, export_connection_to_path, ovpn_text_to_connection};
use crate::libnm::*;

// Property IDs for our get_property dispatcher.
const PROP_NAME: u32 = 1;
const PROP_DESC: u32 = 2;
const PROP_SERVICE: u32 = 3;

// Human-readable plugin metadata — exposed via the GObject properties
// NM advertises in nm-applet / gnome-control-center.  Strings match
// the C tree's OPENVPN3_PLUGIN_NAME / _DESC defines.
const PLUGIN_NAME: &[u8] = b"OpenVPN 3\0";
const PLUGIN_DESC: &[u8] = b"Compatible with the OpenVPN 3 Linux client (net.openvpn.v3.*).\0";

/// Filename of the GTK editor cdylib `get_editor` should `g_module_open`.
const EDITOR_MODULE: &[u8] = b"libnm-vpn-plugin-openvpn3-editor.so\0";
const EDITOR_FACTORY: &[u8] = b"nm_vpn_editor_factory_openvpn3\0";

/// Singleton `GType` for our plugin class.  Registered lazily on the
/// first call to [`plugin_get_type`] — matches how the C tree's
/// `G_DEFINE_TYPE_EXTENDED` macro lays things out.
static PLUGIN_TYPE: OnceLock<glib_sys::GType> = OnceLock::new();

/// Per-instance struct.  We carry no state — the editor plugin is
/// stateless; metadata is delivered via property overrides.  Struct
/// must still exist so libnm knows the per-instance allocation size.
#[repr(C)]
struct Openvpn3EditorPlugin {
    parent: GObject,
}

#[repr(C)]
struct Openvpn3EditorPluginClass {
    parent_class: GObjectClass,
}

/// `class_init` — install GObject property overrides for the three
/// interface-declared properties (name/description/service-type).
unsafe extern "C" fn class_init(class_ptr: gpointer, _class_data: gpointer) {
    let object_class = class_ptr.cast::<GObjectClass>();
    (*object_class).get_property = Some(get_property);

    let prop_name = CStr::from_bytes_with_nul(NM_VPN_EDITOR_PLUGIN_NAME).unwrap();
    let prop_desc = CStr::from_bytes_with_nul(NM_VPN_EDITOR_PLUGIN_DESCRIPTION).unwrap();
    let prop_svc = CStr::from_bytes_with_nul(NM_VPN_EDITOR_PLUGIN_SERVICE).unwrap();
    g_object_class_override_property(object_class, PROP_NAME, prop_name.as_ptr());
    g_object_class_override_property(object_class, PROP_DESC, prop_desc.as_ptr());
    g_object_class_override_property(object_class, PROP_SERVICE, prop_svc.as_ptr());
}

/// `instance_init` — no-op, the struct only holds the GObject parent.
unsafe extern "C" fn instance_init(_instance: *mut GTypeInstance, _class: gpointer) {}

/// Property getter — returns name / description / service-type as
/// G_TYPE_STRING values.  Matches the C tree's `get_property` switch.
unsafe extern "C" fn get_property(
    _object: *mut GObject,
    prop_id: u32,
    value: *mut GValue,
    _pspec: *mut GParamSpec,
) {
    let bytes: &[u8] = match prop_id {
        PROP_NAME => PLUGIN_NAME,
        PROP_DESC => PLUGIN_DESC,
        PROP_SERVICE => NM_VPN_SERVICE_TYPE_OPENVPN3,
        _ => return,
    };
    let cstr = CStr::from_bytes_with_nul(bytes).expect("static c-string");
    gobject_sys::g_value_set_string(value, cstr.as_ptr());
}

/// Run an FFI entrypoint body, converting any Rust panic into a clean
/// `default` return instead of unwinding across the C ABI (which aborts
/// the host process — nm-applet / gnome-control-center).
pub(crate) fn ffi_guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("nm-openvpn3: caught panic at FFI boundary; returning failure to libnm");
            default
        }
    }
}

// --- NMVpnEditorPlugin interface implementation ---------------------------

unsafe extern "C" fn iface_get_capabilities(_plugin: *mut NMVpnEditorPlugin) -> u32 {
    // IPV6 capability is intentionally NOT advertised — the service
    // currently emits only Ip4Config (has_ip6=false, no SetIp6Config
    // path).  Advertising IPV6 here would let NM accept v6-only
    // profiles whose tunnel then has no routable v6 address.  Add the
    // flag back when the service grows an Ip6Config emitter.
    NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT | NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT
}

unsafe extern "C" fn iface_import_from_file(
    _plugin: *mut NMVpnEditorPlugin,
    path: *const c_char,
    error: *mut *mut GError,
) -> *mut NMConnection {
    ffi_guard(ptr::null_mut(), || unsafe {
        if path.is_null() {
            set_error(error, NM_OPENVPN3_PLUGIN_ERROR_FAILED, "import: NULL path");
            return ptr::null_mut();
        }
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                    "import: non-UTF8 path",
                );
                return ptr::null_mut();
            }
        };
        let p = Path::new(path_str);
        // Hard cap on the .ovpn we'll read.  NM hands us an attacker-
        // controllable path; an oversized or special file (/dev/zero, a
        // FUSE-backed pipe, a 2 GiB log) would otherwise freeze the host
        // GUI.  1 MiB matches the service-side MAX_PROFILE_BYTES.  Open
        // first (O_NOFOLLOW + O_CLOEXEC + O_NONBLOCK), fstat the fd (so
        // the size check operates on the same inode the read will consume
        // — no TOCTOU between stat and open), then read through a `take()`
        // cap so a mid-read growth still aborts at the same byte budget.
        const MAX_IMPORT_BYTES: u64 = 1 << 20;
        let text = {
            use std::io::Read;
            use std::os::unix::fs::OpenOptionsExt;
            // O_NONBLOCK so opening a FIFO / named pipe at the (attacker-
            // controllable) import path returns immediately instead of
            // blocking the GUI thread forever waiting for a writer; the
            // is_file() check below then rejects it.  No effect on
            // regular-file reads, so the legitimate path is unchanged.
            // Matches the service-side profile open in do_connect.
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(p)
            {
                Ok(f) => f,
                Err(e) => {
                    set_error(
                        error,
                        NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                        &format!("open {path_str}: {e}"),
                    );
                    return ptr::null_mut();
                }
            };
            let md = match file.metadata() {
                Ok(m) => m,
                Err(e) => {
                    set_error(
                        error,
                        NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                        &format!("fstat {path_str}: {e}"),
                    );
                    return ptr::null_mut();
                }
            };
            if !md.is_file() {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                    &format!("import {path_str}: not a regular file"),
                );
                return ptr::null_mut();
            }
            if md.len() > MAX_IMPORT_BYTES {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                    &format!(
                        "import {path_str}: {} bytes exceeds {MAX_IMPORT_BYTES}-byte cap",
                        md.len()
                    ),
                );
                return ptr::null_mut();
            }
            let cap = (md.len() as usize).saturating_add(1);
            let mut buf = String::with_capacity(cap);
            let mut limited = (&file).take(MAX_IMPORT_BYTES + 1);
            if let Err(e) = limited.read_to_string(&mut buf) {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                    &format!("read {path_str}: {e}"),
                );
                return ptr::null_mut();
            }
            if buf.len() as u64 > MAX_IMPORT_BYTES {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                    &format!("import {path_str}: grew past {MAX_IMPORT_BYTES} bytes during read"),
                );
                return ptr::null_mut();
            }
            buf
        };
        match ovpn_text_to_connection(p, &text) {
            Ok(c) => c,
            Err(e) => {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FILE_NOT_OPENVPN,
                    &format!("import {path_str}: {e}"),
                );
                ptr::null_mut()
            }
        }
    })
}

unsafe extern "C" fn iface_export_to_file(
    _plugin: *mut NMVpnEditorPlugin,
    path: *const c_char,
    connection: *mut NMConnection,
    error: *mut *mut GError,
) -> gboolean {
    ffi_guard(GFALSE, || unsafe {
        if path.is_null() || connection.is_null() {
            set_error(
                error,
                NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                "export: NULL path or connection",
            );
            return GFALSE;
        }
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    error,
                    NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                    "export: non-UTF8 path",
                );
                return GFALSE;
            }
        };
        export_connection_to_path(connection, Path::new(path_str), error)
    })
}

unsafe extern "C" fn iface_get_suggested_filename(
    _plugin: *mut NMVpnEditorPlugin,
    connection: *mut NMConnection,
) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || unsafe {
        let s_con = nm_connection_get_setting_connection(connection);
        if s_con.is_null() {
            return ptr::null_mut();
        }
        let id_ptr = nm_setting_connection_get_id(s_con);
        if id_ptr.is_null() {
            return ptr::null_mut();
        }
        let id = match CStr::from_ptr(id_ptr).to_str() {
            Ok(s) if !s.is_empty() => s,
            _ => return ptr::null_mut(),
        };
        let suggested = format!("{id} (openvpn).conf");
        // libnm frees this with g_free, so allocate with glib's
        // g_malloc-equivalent (g_strdup) to keep allocators paired.
        let c = match CString::new(suggested) {
            Ok(c) => c,
            Err(_) => return ptr::null_mut(),
        };
        glib_sys::g_strdup(c.as_ptr())
    })
}

/// Resolve the editor cdylib's absolute path by asking the loader for
/// where this very .so was loaded from (via `dladdr`) and substituting
/// the basename.  Avoids depending on PLUGINDIR / LD_LIBRARY_PATH being
/// set during a gnome-control-center / nm-applet activation.
unsafe fn locate_editor_module() -> Option<CString> {
    let mut info: crate::libnm::Dl_info = std::mem::zeroed();
    // Any code address inside our `.so` works for dladdr.  `plugin_new`
    // is exported by us so it satisfies that requirement.
    if crate::libnm::dladdr(plugin_new as *const c_void, &mut info as *mut _) == 0 {
        return None;
    }
    // POSIX does not guarantee `dli_fname` is non-NULL (anonymous
    // mappings, the vDSO); guard before constructing a CStr from it.
    if info.dli_fname.is_null() {
        return None;
    }
    let fname = CStr::from_ptr(info.dli_fname)
        .to_string_lossy()
        .into_owned();
    // Path::parent() returns Some("") for a bare basename (no slash),
    // which would silently produce a CWD-relative editor path and let
    // g_module_open resolve against whatever the process happens to be
    // sitting in.  Reject that case explicitly so we fall through to
    // the loader-search basename form.
    let parent = Path::new(&fname)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())?;
    let editor = parent.join("libnm-vpn-plugin-openvpn3-editor.so");
    CString::new(editor.to_string_lossy().as_ref()).ok()
}

/// `g_module_error()` wraps `dlerror(3)`, which returns NULL when no
/// error is pending (e.g. the module is simply missing).  Dereferencing
/// that NULL via `CStr::from_ptr` is UB — guard it.
unsafe fn module_error_string() -> String {
    let p = crate::libnm::g_module_error();
    if p.is_null() {
        "no GModule error detail available".to_string()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

unsafe extern "C" fn iface_get_editor(
    plugin: *mut NMVpnEditorPlugin,
    connection: *mut NMConnection,
    error: *mut *mut GError,
) -> *mut NMVpnEditor {
    ffi_guard(ptr::null_mut(), || unsafe {
        let factory_name = CStr::from_bytes_with_nul(EDITOR_FACTORY).unwrap();
        let module_name_default = CStr::from_bytes_with_nul(EDITOR_MODULE).unwrap();

        // Try the absolute-sibling path first (the way gnome-control-center
        // / nm-applet typically encounters the install) and fall back to
        // the bare basename (handles dev installs where LD_LIBRARY_PATH is
        // set).  g_module_open with a path component only searches that
        // path; with bare basename it consults the loader search list.
        // BIND_LOCAL keeps the editor cdylib's gtk4-rs / libadwaita-rs
        // symbol duplicates out of the host process's global namespace —
        // matters when the host (gnome-control-center, nm-applet) is
        // upgraded to a slightly different GTK4 ABI while our compiled .so
        // still references the older one.
        let abs_path = locate_editor_module();
        let module = match &abs_path {
            Some(p) => {
                crate::libnm::g_module_open(p.as_ptr(), crate::libnm::G_MODULE_BIND_LAZY_LOCAL)
            }
            None => ptr::null_mut(),
        };
        let module = if module.is_null() {
            crate::libnm::g_module_open(
                module_name_default.as_ptr(),
                crate::libnm::G_MODULE_BIND_LAZY_LOCAL,
            )
        } else {
            module
        };
        if module.is_null() {
            let detail = module_error_string();
            let tried = abs_path
                .as_ref()
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_else(|| module_name_default.to_string_lossy().into_owned());
            set_error(
                error,
                NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                &format!("g_module_open({tried}) failed: {detail}"),
            );
            return ptr::null_mut();
        }
        let mut sym: gpointer = ptr::null_mut();
        let ok = crate::libnm::g_module_symbol(module, factory_name.as_ptr(), &mut sym);
        if ok == GFALSE || sym.is_null() {
            let detail = module_error_string();
            set_error(
                error,
                NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                &format!("g_module_symbol(nm_vpn_editor_factory_openvpn3): {detail}"),
            );
            let _ = crate::libnm::g_module_close(module);
            return ptr::null_mut();
        }
        // Don't close the module — its symbols remain referenced by the
        // returned NMVpnEditor for the lifetime of the editor dialog.
        type EditorFactory = unsafe extern "C" fn(
            plugin: *mut NMVpnEditorPlugin,
            connection: *mut NMConnection,
            error: *mut *mut GError,
        ) -> *mut NMVpnEditor;
        let factory: EditorFactory = std::mem::transmute(sym);
        // Forward the caller's NMVpnEditorPlugin pointer instead of NULL —
        // matches the libnm contract and lets the editor read plugin-info
        // metadata if a future version of the editor needs it.
        factory(plugin, connection, error)
    })
}

/// Fill the libnm-supplied interface vtable with our methods.  Called
/// once during type registration.
unsafe extern "C" fn iface_init(iface_data: gpointer, _user_data: gpointer) {
    let iface = iface_data.cast::<NMVpnEditorPluginInterface>();
    (*iface).get_editor = Some(iface_get_editor);
    (*iface).get_capabilities = Some(iface_get_capabilities);
    (*iface).import_from_file = Some(iface_import_from_file);
    (*iface).export_to_file = Some(iface_export_to_file);
    (*iface).get_suggested_filename = Some(iface_get_suggested_filename);
    (*iface).notify_plugin_info_set = None;
    (*iface).get_vt = None;
}

/// Register the GType + interface on first use.  Idempotent.
pub fn plugin_get_type() -> glib_sys::GType {
    *PLUGIN_TYPE.get_or_init(|| unsafe {
        let type_name = c"NMOpenvpn3EditorPlugin";
        let class_size = std::mem::size_of::<Openvpn3EditorPluginClass>();
        let inst_size = std::mem::size_of::<Openvpn3EditorPlugin>();
        let g_type = g_type_register_static_simple(
            G_TYPE_OBJECT,
            type_name.as_ptr().cast(),
            class_size as u32,
            Some(class_init),
            inst_size as u32,
            Some(instance_init),
            G_TYPE_FLAG_NONE,
        );
        let iface_info = gobject_sys::GInterfaceInfo {
            interface_init: Some(iface_init),
            interface_finalize: None,
            interface_data: ptr::null_mut(),
        };
        g_type_add_interface_static(
            g_type,
            nm_vpn_editor_plugin_get_type(),
            &iface_info as *const _,
        );
        g_type
    })
}

/// Construct a fresh instance via `g_object_new`.  Used by the
/// `nm_vpn_editor_plugin_factory` entrypoint.
///
/// # Safety
/// Caller takes ownership of the returned floating reference.
pub unsafe fn plugin_new() -> *mut GObject {
    let g_type = plugin_get_type();
    g_object_new(g_type, ptr::null()).cast()
}

/// Used by the editor crate when it wants to round-trip a connection
/// before persisting widget state.  Wrapper to keep the cross-crate
/// surface narrow.
///
/// # Safety
/// `connection` must be a live libnm `NMConnection*`.
#[allow(dead_code)]
pub unsafe fn debug_connection_data(
    connection: *mut NMConnection,
) -> std::collections::BTreeMap<String, String> {
    connection_to_nm_data(connection)
}

// silence unused-import lint for the GValue type when building
// without the gtk4-editor feature in the editor crate's tree
const _: () = {
    let _ = std::mem::size_of::<*mut c_void>();
};
