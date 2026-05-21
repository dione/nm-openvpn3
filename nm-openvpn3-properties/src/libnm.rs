//! Minimal libnm FFI — only the symbols the editor plugin touches.
//!
//! libnm has no Rust binding on crates.io.  Generating one via `gir`
//! is a project of its own; this module declares the handful of types
//! and functions the openvpn3 plugin needs and is small enough to
//! audit against the libnm headers (`/usr/include/libnm/`).  Verified
//! against libnm 1.30 + 1.54.
//!
//! All struct layouts are *opaque* — we never poke fields directly,
//! only pass pointers to libnm and read GValues back via the gobject
//! accessor functions.  The two exceptions are
//! [`NMVpnEditorPluginInterface`] and [`NMVpnEditorInterface`] vtables
//! which we install during interface registration; those layouts must
//! match the libnm header byte-for-byte.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_char;
use std::os::raw::c_int;

use glib_sys::{gboolean, gpointer, GError, GQuark, GType};
use gobject_sys::{GObject, GTypeInterface};

// glib-sys 0.21 dropped the `gchar` type alias; libnm headers still
// declare `gchar *` returns, but mapping it onto `c_char` (which is
// what `gchar` always was) keeps the bindings stable.
type gchar = c_char;

// Opaque libnm types — we never construct or dereference these directly,
// we just shuttle the pointers to libnm.
pub enum NMConnection {}
pub enum NMSetting {}
pub enum NMSettingConnection {}
pub enum NMSettingVpn {}
pub enum NMSettingIPConfig {}
pub enum NMVpnEditorPlugin {}
pub enum NMVpnEditor {}
pub enum NMVpnPluginInfo {}

// NMVpnEditorPluginCapability (bitflags from libnm/nm-vpn-editor-plugin.h).
pub const NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE: u32 = 0x00;
pub const NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT: u32 = 0x01;
pub const NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT: u32 = 0x02;
pub const NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6: u32 = 0x04;

// NMVpnEditorPlugin property names — `g_object_class_override_property`
// expects the same strings the interface declared.
pub const NM_VPN_EDITOR_PLUGIN_NAME: &[u8] = b"name\0";
pub const NM_VPN_EDITOR_PLUGIN_DESCRIPTION: &[u8] = b"description\0";
pub const NM_VPN_EDITOR_PLUGIN_SERVICE: &[u8] = b"service\0";

// NMVpnEditorPluginVT — used by libnm's `get_vt` hook to extend the
// plugin without breaking ABI.  We don't expose any VT functions, so
// we always return NULL from `get_vt`.
#[repr(C)]
pub struct NMVpnEditorPluginVT {
    pub _opaque: u8,
}

// NMVpnEditorPluginInterface — vtable layout matches libnm 1.30+.
// The trailing get_vt was added in 1.4 and is still there in 1.54.
//
// IMPORTANT: the field *order* and signatures must match libnm exactly.
// Verified against /usr/include/libnm/nm-vpn-editor-plugin.h.
#[repr(C)]
pub struct NMVpnEditorPluginInterface {
    pub g_iface: GTypeInterface,
    pub get_editor: Option<
        unsafe extern "C" fn(
            plugin: *mut NMVpnEditorPlugin,
            connection: *mut NMConnection,
            error: *mut *mut GError,
        ) -> *mut NMVpnEditor,
    >,
    pub get_capabilities: Option<unsafe extern "C" fn(plugin: *mut NMVpnEditorPlugin) -> u32>,
    pub import_from_file: Option<
        unsafe extern "C" fn(
            plugin: *mut NMVpnEditorPlugin,
            path: *const c_char,
            error: *mut *mut GError,
        ) -> *mut NMConnection,
    >,
    pub export_to_file: Option<
        unsafe extern "C" fn(
            plugin: *mut NMVpnEditorPlugin,
            path: *const c_char,
            connection: *mut NMConnection,
            error: *mut *mut GError,
        ) -> gboolean,
    >,
    pub get_suggested_filename: Option<
        unsafe extern "C" fn(
            plugin: *mut NMVpnEditorPlugin,
            connection: *mut NMConnection,
        ) -> *mut gchar,
    >,
    pub notify_plugin_info_set: Option<
        unsafe extern "C" fn(plugin: *mut NMVpnEditorPlugin, plugin_info: *mut NMVpnPluginInfo),
    >,
    pub get_vt: Option<
        unsafe extern "C" fn(
            plugin: *mut NMVpnEditorPlugin,
            out_vt_size: *mut usize,
        ) -> *const NMVpnEditorPluginVT,
    >,
}

// NMVpnEditorInterface — same source: /usr/include/libnm/nm-vpn-editor.h.
#[repr(C)]
pub struct NMVpnEditorInterface {
    pub g_iface: GTypeInterface,
    pub get_widget: Option<unsafe extern "C" fn(editor: *mut NMVpnEditor) -> *mut GObject>,
    pub placeholder: Option<unsafe extern "C" fn()>,
    pub update_connection: Option<
        unsafe extern "C" fn(
            editor: *mut NMVpnEditor,
            connection: *mut NMConnection,
            error: *mut *mut GError,
        ) -> gboolean,
    >,
    pub changed: Option<unsafe extern "C" fn(editor: *mut NMVpnEditor)>,
}

// VPN service type for openvpn3.  Matches the C tree's
// `NM_VPN_SERVICE_TYPE_OPENVPN3` define in shared/nm-service-defines.h.
pub const NM_VPN_SERVICE_TYPE_OPENVPN3: &[u8] = b"org.freedesktop.NetworkManager.openvpn3\0";

// NMSettingConnection / NMSettingVpn property names — string keys
// libnm uses for g_object_set / nm_setting_vpn_add_data_item etc.
pub const NM_SETTING_CONNECTION_ID: &[u8] = b"id\0";
pub const NM_SETTING_CONNECTION_TYPE: &[u8] = b"type\0";
pub const NM_SETTING_VPN_SERVICE_TYPE: &[u8] = b"service-type\0";
pub const NM_SETTING_VPN_SETTING_NAME: &[u8] = b"vpn\0";
pub const NM_SETTING_IP_CONFIG_METHOD: &[u8] = b"method\0";
pub const NM_SETTING_IP4_CONFIG_METHOD_AUTO: &[u8] = b"auto\0";

// NMVpnEditorPluginError quark (NMV_EDITOR_PLUGIN_ERROR in the C tree).
// We declare our own subdomain so callers can filter our errors.
pub const NM_OPENVPN3_PLUGIN_ERROR_FAILED: i32 = 0;
pub const NM_OPENVPN3_PLUGIN_ERROR_FILE_NOT_OPENVPN: i32 = 1;

// gmodule (g_module_open etc.) — shipped in libgmodule-2.0, not in
// glib-sys.  Declared inline here since we use a small handful.
#[allow(non_camel_case_types)]
pub type GModule = std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GModuleFlags(pub u32);
pub const G_MODULE_BIND_LAZY: GModuleFlags = GModuleFlags(1);
pub const G_MODULE_BIND_LOCAL: GModuleFlags = GModuleFlags(2);

extern "C" {
    pub fn g_module_open(file_name: *const c_char, flags: GModuleFlags) -> *mut GModule;
    pub fn g_module_symbol(
        module: *mut GModule,
        symbol_name: *const c_char,
        symbol: *mut gpointer,
    ) -> gboolean;
    pub fn g_module_close(module: *mut GModule) -> gboolean;
    pub fn g_module_error() -> *const c_char;
}

// Variadic signal emission — gobject-sys does not re-export this in
// 0.22.  We use it to fire the `NMVpnEditor::changed` signal each
// time a widget's state moves, so libnma enables the Apply button.
extern "C" {
    pub fn g_signal_emit_by_name(instance: gpointer, detailed_signal: *const c_char, ...);
}

// dladdr — used to find our own `.so` path at runtime so we can locate
// sibling .so files (the editor cdylib lives next to us under
// $PLUGINDIR/NetworkManager/).
#[repr(C)]
pub struct Dl_info {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut std::ffi::c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut std::ffi::c_void,
}

extern "C" {
    pub fn dladdr(addr: *const std::ffi::c_void, info: *mut Dl_info) -> c_int;
}

// Runtime libnm version, packed `major << 16 | minor << 8 | micro`.
// We declare the constant ourselves rather than relying on a libnm
// helper that may not exist on every release.  `MIN` is the lowest
// libnm whose `NMVpnEditorPluginInterface` vtable layout matches the
// one we install — 1.30 added `notify_plugin_info_set` past which
// `get_vt` (1.4) is the trailing slot.  Patch releases of the same
// minor (1.30.1, 1.30.2 …) satisfy the check.
pub const NM_LIBNM_VERSION_MIN: u32 = (1 << 16) | (30 << 8);

extern "C" {
    /// Runtime libnm version.  Available since libnm 1.6, so safe to
    /// call from a plugin that targets any sensible NM.
    pub fn nm_utils_version() -> u32;

    // libnm core
    pub fn nm_simple_connection_new() -> *mut NMConnection;
    pub fn nm_connection_add_setting(connection: *mut NMConnection, setting: *mut NMSetting);
    pub fn nm_connection_get_setting_connection(
        connection: *mut NMConnection,
    ) -> *mut NMSettingConnection;
    pub fn nm_connection_get_setting_vpn(connection: *mut NMConnection) -> *mut NMSettingVpn;

    pub fn nm_setting_connection_new() -> *mut NMSetting;
    pub fn nm_setting_connection_get_id(s: *mut NMSettingConnection) -> *const c_char;

    pub fn nm_setting_vpn_new() -> *mut NMSetting;
    pub fn nm_setting_vpn_add_data_item(
        s: *mut NMSettingVpn,
        key: *const c_char,
        value: *const c_char,
    );
    pub fn nm_setting_vpn_get_data_item(s: *mut NMSettingVpn, key: *const c_char) -> *const c_char;
    pub fn nm_setting_vpn_add_secret(
        s: *mut NMSettingVpn,
        key: *const c_char,
        value: *const c_char,
    );
    pub fn nm_setting_vpn_get_secret(s: *mut NMSettingVpn, key: *const c_char) -> *const c_char;
    pub fn nm_setting_vpn_foreach_data_item(
        s: *mut NMSettingVpn,
        func: unsafe extern "C" fn(key: *const c_char, value: *const c_char, user_data: gpointer),
        user_data: gpointer,
    );

    pub fn nm_setting_ip4_config_new() -> *mut NMSetting;

    pub fn nm_vpn_editor_plugin_get_type() -> GType;
    pub fn nm_vpn_editor_get_type() -> GType;
}

// glib-sys re-exports we use enough to import locally
pub use glib_sys::g_error_new;
pub use glib_sys::g_quark_from_static_string;
pub use gobject_sys::g_type_add_interface_static;
pub use gobject_sys::g_type_interface_peek_parent;
pub use gobject_sys::g_type_register_static_simple;

/// Build the GError domain quark unique to this plugin.
pub fn error_domain() -> GQuark {
    unsafe { g_quark_from_static_string(c"nm-vpn-plugin-openvpn3-rust".as_ptr()) }
}

/// Set `*err_out` to a fresh GError carrying `msg`.  Caller must hold
/// the GError contract — `err_out` is either NULL or points to a NULL
/// GError pointer.
///
/// # Safety
/// `err_out` must satisfy the GError contract above.  The function is
/// a no-op when `err_out` is NULL or `*err_out` is non-NULL.
pub unsafe fn set_error(err_out: *mut *mut GError, code: c_int, msg: &str) {
    if err_out.is_null() || !(*err_out).is_null() {
        return;
    }
    let cmsg = std::ffi::CString::new(msg).unwrap_or_else(|_| {
        std::ffi::CString::new("unspecified error").expect("static string is valid")
    });
    *err_out = g_error_new(error_domain(), code, c"%s".as_ptr(), cmsg.as_ptr());
}
