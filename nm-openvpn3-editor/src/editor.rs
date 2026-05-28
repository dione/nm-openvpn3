//! `Openvpn3Editor` — Rust GObject implementing the `NMVpnEditor`
//! interface from libnm.
//!
//! Round-5 HIG sweep — every row is now a purpose-built libadwaita
//! widget (AdwComboRow / AdwSpinRow / AdwSwitchRow / AdwEntryRow /
//! AdwPasswordEntryRow), titles are short, hints land in subtitles or
//! tooltips, and connection-type drives row visibility so static-key
//! / password-only / TLS connections never see fields they cannot
//! use.  File pickers replace bare path entries for ca / cert / key /
//! ta / tls-crypt / tls-crypt-v2 / inline profile.
//!
//! Save remains additive — the initial vpn.data snapshot is replayed
//! first and the widget state overlays only the keys this UI exposes.
//! Anything the user typed via `nmcli` outside the editor's vocabulary
//! survives the round-trip.

use std::cell::RefCell;
use std::ffi::CString;
use std::path::Path;
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};

use gettextrs::dgettext;
use zeroize::{Zeroize, Zeroizing};
use glib::ffi::{gboolean, gpointer, GError, GFALSE, GTRUE};
use gobject_sys::{
    g_object_new, g_type_add_interface_static, g_type_register_static_simple, GInterfaceInfo,
    GObject, GTypeInstance, G_TYPE_FLAG_NONE, G_TYPE_OBJECT,
};
use gtk4::prelude::*;
use gtk4::{gio, glib, StringList};
use libadwaita::prelude::*;
use libadwaita::{
    ComboRow, EntryRow, ExpanderRow, PasswordEntryRow, PreferencesGroup, PreferencesPage, SpinRow,
    SwitchRow,
};

use nm_vpn_plugin_openvpn3::bridge::connection_to_nm_data;
use nm_vpn_plugin_openvpn3::libnm::{
    nm_connection_get_setting_vpn, nm_setting_set_secret_flags, nm_setting_vpn_add_data_item,
    nm_setting_vpn_add_secret, nm_setting_vpn_remove_data_item, nm_setting_vpn_remove_secret,
    nm_vpn_editor_get_type, set_error, NMConnection, NMVpnEditorInterface,
    NM_OPENVPN3_PLUGIN_ERROR_FAILED, NM_SETTING_SECRET_FLAG_AGENT_OWNED,
};

// ---------------------------------------------------------------------------
// Static option vocabularies — kept as `(id, display_key)`.  Display
// strings are wrapped in `gettext()` when consumed so locales pick up
// translated labels; pure acronyms / numerals route through
// `passthrough_label` so translators are not asked to "translate" tokens
// like "TLS" or "tun".
// ---------------------------------------------------------------------------

const CONTYPE_TLS: &str = "tls";
const CONTYPE_PASSWORD: &str = "password";
const CONTYPE_PASSWORD_TLS: &str = "password-tls";
const CONTYPE_STATIC_KEY: &str = "static-key";

const CONTYPES: &[(&str, &str)] = &[
    (CONTYPE_TLS, "TLS"),
    (CONTYPE_PASSWORD, "Password"),
    (CONTYPE_PASSWORD_TLS, "Password + TLS"),
    (CONTYPE_STATIC_KEY, "Static key"),
];

const ALLOW_COMPRESSION: &[(&str, &str)] = &[
    ("", "Default"),
    ("no", "Disabled"),
    ("asym", "Asymmetric"),
    ("yes", "Enabled"),
];

const REMOTE_CERT_TLS: &[(&str, &str)] = &[
    ("", "Not enforced"),
    ("client", "Server must present a client certificate"),
    ("server", "Server must present a server certificate"),
];

const NS_CERT_TYPE: &[(&str, &str)] = &[
    ("", "Not enforced"),
    ("client", "client"),
    ("server", "server"),
];

const TLS_VERSIONS: &[(&str, &str)] = &[
    ("", "Default"),
    ("1.0", "TLS 1.0"),
    ("1.1", "TLS 1.1"),
    ("1.2", "TLS 1.2"),
    ("1.3", "TLS 1.3"),
];

const PROXY_TYPES: &[(&str, &str)] = &[("", "None"), ("http", "HTTP"), ("socks", "SOCKS")];

const COMP_LZO: &[(&str, &str)] = &[
    ("", "Off"),
    ("yes", "Enabled"),
    ("no", "Disabled"),
    ("adaptive", "Adaptive"),
];

const DEV_TYPES: &[(&str, &str)] = &[("", "Auto"), ("tun", "tun"), ("tap", "tap")];

/// `compress` (modern openvpn) accepts a finite enum of algorithm
/// names; the ID is the literal token openvpn3 expects on the wire.
/// "lzo" matches the legacy `compress yes` shorthand.
const COMPRESS: &[(&str, &str)] = &[
    ("", "Default"),
    ("lzo", "LZO"),
    ("lz4", "LZ4"),
    ("lz4-v2", "LZ4 v2"),
];

/// Legacy `cipher` and modern `data-ciphers-fallback` share the same
/// single-cipher vocabulary.  IDs are the literal cipher names openvpn3
/// hands to OpenSSL.  Empty leaves openvpn3's negotiated default in
/// place.  GCM modes ordered first because that is what every modern
/// peer prefers.  `cipher=none` and DES-EDE3-CBC are intentionally
/// omitted — anyone who needs the no-encryption mode or 3DES for a
/// test rig can set them via nmcli; surfacing them at parity with
/// AES-256-GCM invites a misclick that ships traffic in cleartext.
const CIPHERS: &[(&str, &str)] = &[
    ("", "Default"),
    ("AES-256-GCM", "AES-256-GCM"),
    ("AES-192-GCM", "AES-192-GCM"),
    ("AES-128-GCM", "AES-128-GCM"),
    ("CHACHA20-POLY1305", "CHACHA20-POLY1305"),
    ("AES-256-CBC", "AES-256-CBC"),
    ("AES-192-CBC", "AES-192-CBC"),
    ("AES-128-CBC", "AES-128-CBC"),
    ("BF-CBC", "BF-CBC"),
];

/// HMAC algorithms for the openvpn `auth` directive.  IDs match the
/// OpenSSL digest names openvpn3 forwards verbatim.  `auth=none` is
/// intentionally omitted (see CIPHERS); MD5 stays because some legacy
/// tunnels still rely on it as the HMAC even when the data cipher is
/// modern.
const AUTH_ALGS: &[(&str, &str)] = &[
    ("", "Default"),
    ("SHA1", "SHA1"),
    ("SHA224", "SHA224"),
    ("SHA256", "SHA256"),
    ("SHA384", "SHA384"),
    ("SHA512", "SHA512"),
    ("RIPEMD160", "RIPEMD160"),
    ("MD5", "MD5"),
];

/// Tri-state key-direction vocabulary used by both `static-key-direction`
/// and `ta-dir`.  IDs are the literal `--key-direction` values openvpn
/// expects ("" for unset, "0", "1"); labels expose the OpenVPN convention
/// (server uses 0, client uses 1) so users don't have to memorise the
/// numbering.
const KEY_DIR: &[(&str, &str)] = &[("", "None"), ("0", "Server"), ("1", "Client")];

/// Labels that must not be sent through `gettext()` — openvpn protocol
/// tokens and TLS version strings.  Translators get an easier life and
/// shipping `tun` as `msgid "tun"` in a fresh locale won't accidentally
/// render as something different.
fn passthrough_label(s: &str) -> bool {
    matches!(
        s,
        "TLS"
            | "HTTP"
            | "SOCKS"
            | "TLS 1.0"
            | "TLS 1.1"
            | "TLS 1.2"
            | "TLS 1.3"
            | "tun"
            | "tap"
            | "LZO"
            | "LZ4"
            | "LZ4 v2"
            | "AES-128-CBC"
            | "AES-192-CBC"
            | "AES-256-CBC"
            | "AES-128-GCM"
            | "AES-192-GCM"
            | "AES-256-GCM"
            | "CHACHA20-POLY1305"
            | "BF-CBC"
            | "SHA1"
            | "SHA224"
            | "SHA256"
            | "SHA384"
            | "SHA512"
            | "RIPEMD160"
            | "MD5"
    )
}

/// vpn.data keys this editor owns.  Anything in the imported snapshot
/// that is NOT in this list is replayed verbatim on Save so nmcli-set
/// values outside our vocabulary survive a round-trip; anything that IS
/// in this list is set or removed strictly from widget state.
const WIDGET_DATA_KEYS: &[&str] = &[
    "connection-type",
    "remote",
    "port",
    "ca",
    "cert",
    "key",
    "static-key",
    "static-key-direction",
    "username",
    "nm-openvpn3-profile",
    "dev",
    "dev-type",
    "proto-tcp",
    "tunnel-mtu",
    "mssfix",
    "fragment-size",
    "ping",
    "ping-restart",
    "reneg-seconds",
    "connect-timeout",
    "allow-compression",
    "comp-lzo",
    "compress",
    "cipher",
    "data-ciphers",
    "data-ciphers-fallback",
    "tls-cipher",
    "auth",
    "keysize",
    "tls-version-min",
    "tls-version-min-or-highest",
    "tls-version-max",
    "verify-x509-name",
    "remote-cert-tls",
    "ns-cert-type",
    "ta",
    "ta-dir",
    "tls-crypt",
    "tls-crypt-v2",
    "proxy-type",
    "proxy-server",
    "proxy-port",
    "http-proxy-username",
    "override-route-nopull",
    "override-force-default-gateway",
    "override-block-ipv6",
    "override-dns-setup-disabled",
    "override-dco",
    "override-log-level",
];

// ---------------------------------------------------------------------------
// Translation helper.  Initialises gettext on first call, then
// dispatches every subsequent lookup straight through.  Strings fall
// back to English when no .mo catalog is installed.
// ---------------------------------------------------------------------------

/// Look the string up in OUR catalog only — never touch the process-
/// wide default domain, otherwise the host (gnome-control-center,
/// nm-applet) loses access to its own translations after we load.
fn tr(s: &str) -> String {
    dgettext("nm-openvpn3", s)
}

fn gettext_init_once() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // setlocale honours LANG / LC_ALL from the desktop environment.
        // bindtextdomain registers our catalog; we deliberately do NOT
        // call textdomain() because that would override the host's
        // default domain.  dgettext() in tr() above is domain-scoped.
        gettextrs::setlocale(gettextrs::LocaleCategory::LcAll, "");
        // Honour a build/install-time locale dir override so a non-/usr
        // prefix (/opt, /usr/local, Flatpak) still finds the catalog;
        // fall back to the FHS default otherwise.
        let localedir = std::env::var("NM_OPENVPN3_LOCALEDIR")
            .unwrap_or_else(|_| "/usr/share/locale".to_string());
        let _ = gettextrs::bindtextdomain("nm-openvpn3", localedir);
    });
}

// ---------------------------------------------------------------------------
// GObject layout.
// ---------------------------------------------------------------------------

#[repr(C)]
struct Openvpn3Editor {
    parent: GObject,
    state: *mut EditorState,
}

#[repr(C)]
struct Openvpn3EditorClass {
    parent_class: gobject_sys::GObjectClass,
}

/// Wraps an `AdwComboRow` together with the option-id vector backing
/// its `StringList` model.  `selected_id` translates the row's u32
/// `selected` index back into the NM key the row's been bound to.
struct ComboBinding {
    row: ComboRow,
    ids: Vec<String>,
}

impl ComboBinding {
    fn selected_id(&self) -> &str {
        let idx = self.row.selected() as usize;
        self.ids.get(idx).map(String::as_str).unwrap_or("")
    }
}

struct EditorState {
    page: PreferencesPage,

    // General
    contype: ComboBinding,
    remote: EntryRow,
    port: SpinRow,
    ca: EntryRow,
    cert: EntryRow,
    key: EntryRow,
    cert_pass: PasswordEntryRow,
    username: EntryRow,
    password: PasswordEntryRow,
    profile_path: EntryRow,
    static_key: EntryRow,
    static_key_dir: ComboBinding,

    // Device + Connection (was "Routing")
    dev: EntryRow,
    dev_type: ComboBinding,
    proto_tcp: SwitchRow,
    tun_mtu: SpinRow,
    mssfix_enabled: SwitchRow,
    mssfix_bytes: SpinRow,
    fragment: SpinRow,
    keepalive_ping: SpinRow,
    keepalive_restart: SpinRow,
    reneg_seconds: SpinRow,
    connect_timeout: SpinRow,

    // Compression
    allow_compression: ComboBinding,
    comp_lzo: ComboBinding,
    compress: ComboBinding,

    // Security
    cipher: ComboBinding,
    data_ciphers: EntryRow,
    data_ciphers_fallback: ComboBinding,
    tls_cipher: EntryRow,
    auth: ComboBinding,
    keysize: SpinRow,

    // TLS
    tls_version_min: ComboBinding,
    tls_version_min_or_highest: SwitchRow,
    tls_version_max: ComboBinding,
    verify_x509_name: EntryRow,
    remote_cert_tls: ComboBinding,
    ns_cert_type: ComboBinding,
    ta: EntryRow,
    ta_dir: ComboBinding,
    tls_crypt: EntryRow,
    tls_crypt_v2: EntryRow,

    // Proxy
    proxy_type: ComboBinding,
    proxy_server: EntryRow,
    proxy_port: SpinRow,
    proxy_user: EntryRow,

    // Misc / Overrides
    or_route_nopull: SwitchRow,
    or_force_default_gateway: SwitchRow,
    or_block_ipv6: SwitchRow,
    or_dns_setup_disabled: SwitchRow,
    or_dco: SwitchRow,
    or_log_level: SpinRow,

    initial_data: RefCell<std::collections::BTreeMap<String, String>>,

    /// Lifetime gate for the closures that fire `NMVpnEditor::changed`.
    /// Flipped to `false` at the top of `instance_finalize` so any
    /// signal handler still on the GLib main loop at that point bails
    /// before dereferencing the stale GObject pointer.  In practice
    /// GTK signal emission is synchronous + main-loop-bound and
    /// widget destruction disconnects handlers, so this flag is
    /// belt-and-braces defence against a regression in the
    /// destruction order.
    alive: Arc<AtomicBool>,
}

static EDITOR_TYPE: OnceLock<glib_sys::GType> = OnceLock::new();

/// Pointer to the GObjectClass of our type's *parent* (GObject itself).
/// Captured during `class_init` while the class structure is live and
/// fully realised; safe to read from any thread because we only ever
/// write it once.  Used by `instance_finalize` to chain up — avoids
/// re-querying `g_type_class_peek` during teardown, which can race
/// against module-unload ordering and return NULL.
static PARENT_CLASS: AtomicPtr<gobject_sys::GObjectClass> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" fn class_init(class_ptr: gpointer, _class_data: gpointer) {
    let object_class = class_ptr.cast::<gobject_sys::GObjectClass>();
    (*object_class).finalize = Some(instance_finalize);
    let parent =
        gobject_sys::g_type_class_peek_parent(class_ptr).cast::<gobject_sys::GObjectClass>();
    PARENT_CLASS.store(parent, Ordering::Release);
}

unsafe extern "C" fn instance_init(instance: *mut GTypeInstance, _class: gpointer) {
    let inst = instance.cast::<Openvpn3Editor>();
    (*inst).state = ptr::null_mut();
}

unsafe extern "C" fn instance_finalize(object: *mut GObject) {
    if object.is_null() {
        // GObject contract says this never happens, but bailing is
        // cheap and beats segfaulting on a future libnm regression.
        return;
    }
    let inst = object.cast::<Openvpn3Editor>();
    if !(*inst).state.is_null() {
        // Flip the closure lifetime gate FIRST so any signal handler
        // still scheduled on the main loop sees the editor is going
        // away and skips the emit.  Only then drop the boxed state
        // (which drops the widgets, which disconnect the handlers).
        (*(*inst).state).alive.store(false, Ordering::Release);
        drop(Box::from_raw((*inst).state));
        (*inst).state = ptr::null_mut();
    }
    let parent_class = PARENT_CLASS.load(Ordering::Acquire);
    if !parent_class.is_null() {
        if let Some(parent_finalize) = (*parent_class).finalize {
            parent_finalize(object);
        }
    }
}

/// Run an FFI entrypoint body, converting any Rust panic into a clean
/// `default` return instead of unwinding across the C ABI (which aborts
/// the host process — gnome-control-center / nm-applet).  Widget
/// construction and libnm calls can panic; this keeps that contained.
pub(crate) fn ffi_guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("nm-openvpn3-editor: caught panic at FFI boundary; returning failure");
            default
        }
    }
}

// ---------------------------------------------------------------------------
// NMVpnEditor interface impl.
// ---------------------------------------------------------------------------

unsafe extern "C" fn iface_get_widget(
    editor: *mut nm_vpn_plugin_openvpn3::libnm::NMVpnEditor,
) -> *mut GObject {
    // libnm contract: returns the editor's primary widget as a
    // borrowed GObject* (transfer none).  Lifetime is tied to the
    // NMVpnEditor itself — libnma keeps a strong ref on the editor
    // for as long as it holds the widget pointer, so the page stays
    // alive via our EditorState (which owns a strong gtk4-rs ref) +
    // any container ref libnma adds when packing the page.  When the
    // dialog drops its ref and libnma finally unrefs the editor,
    // instance_finalize runs, the Box<EditorState> drops, and the
    // page's last strong ref disappears — at which point GTK frees
    // the GObject.  Do NOT g_object_ref here: libnma would not unref
    // and the page would leak.
    ffi_guard(ptr::null_mut(), || unsafe {
        let inst = editor.cast::<Openvpn3Editor>();
        let state = (*inst).state;
        if state.is_null() {
            return ptr::null_mut();
        }
        let glib_obj = (*state).page.upcast_ref::<glib::Object>();
        glib_obj.as_ptr().cast::<GObject>()
    })
}

unsafe extern "C" fn iface_update_connection(
    editor: *mut nm_vpn_plugin_openvpn3::libnm::NMVpnEditor,
    connection: *mut NMConnection,
    error: *mut *mut GError,
) -> gboolean {
    ffi_guard(GFALSE, || unsafe {
    let inst = editor.cast::<Openvpn3Editor>();
    let state = (*inst).state;
    if state.is_null() || connection.is_null() {
        return GFALSE;
    }
    let s_vpn = nm_connection_get_setting_vpn(connection);
    if s_vpn.is_null() {
        return GFALSE;
    }

    let st = &*state;

    // check_validity gate — matches C nm-openvpn-editor's update_connection
    // refusing to save until the minimum-viable field set is filled in.
    // Catching this here (instead of letting build_profile error at
    // activation) means the user sees a clear "Apply rejected" hint in
    // libnma's dialog rather than an opaque red banner on Connect.
    let ct = st.contype.selected_id();
    let remote_text = st.remote.text();
    let remote_str = remote_text.as_str();
    let validity_err = if remote_str.is_empty() {
        Some("missing gateway address".to_string())
    } else if matches!(ct, "tls" | "password-tls") && st.ca.text().is_empty() {
        Some("TLS connection requires a CA certificate".to_string())
    } else if ct == "tls" && (st.cert.text().is_empty() || st.key.text().is_empty()) {
        Some("TLS connection requires both client certificate and private key".to_string())
    } else if matches!(ct, "password" | "password-tls") && st.username.text().is_empty() {
        Some("password authentication requires a user name".to_string())
    } else if ct == "static-key" && st.static_key.text().is_empty() {
        Some("static-key connection requires a key file".to_string())
    } else {
        None
    };
    if let Some(msg) = validity_err {
        set_error(error, NM_OPENVPN3_PLUGIN_ERROR_FAILED, &msg);
        return GFALSE;
    }

    // Empty value → remove the key entirely so cleared widgets actually
    // wipe state.  Non-empty value → add (libnm overwrites).  NUL in
    // the value is treated as remove rather than silently truncating —
    // the editor's path-validity indicator already flags the bad input
    // visually.
    let set = |key: &str, value: &str| {
        let k = match CString::new(key) {
            Ok(c) => c,
            Err(_) => return,
        };
        if value.is_empty() {
            let _ = nm_setting_vpn_remove_data_item(s_vpn, k.as_ptr());
            return;
        }
        match CString::new(value) {
            Ok(v) => nm_setting_vpn_add_data_item(s_vpn, k.as_ptr(), v.as_ptr()),
            Err(_) => {
                let _ = nm_setting_vpn_remove_data_item(s_vpn, k.as_ptr());
            }
        }
    };

    // Secrets follow the same pattern; after add we tag the key
    // AGENT_OWNED so libnm routes it through the user keyring instead
    // of the on-disk system-connections file.
    let s_setting = s_vpn.cast::<nm_vpn_plugin_openvpn3::libnm::NMSetting>();
    let set_secret = |key: &str, value: &str| {
        let k = match CString::new(key) {
            Ok(c) => c,
            Err(_) => return,
        };
        if value.is_empty() {
            let _ = nm_setting_vpn_remove_secret(s_vpn, k.as_ptr());
            return;
        }
        match CString::new(value) {
            Ok(v) => {
                nm_setting_vpn_add_secret(s_vpn, k.as_ptr(), v.as_ptr());
                let _ = nm_setting_set_secret_flags(
                    s_setting,
                    k.as_ptr(),
                    NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                    ptr::null_mut(),
                );
                // libnm has copied the value into its own secret store;
                // scrub the CString's heap bytes before they drop so the
                // plaintext doesn't linger in this process's memory.
                let mut vb = v.into_bytes_with_nul();
                vb.zeroize();
            }
            Err(_) => {
                let _ = nm_setting_vpn_remove_secret(s_vpn, k.as_ptr());
            }
        }
    };

    // Replay only the imported keys we do NOT own — preserves nmcli-set
    // entries outside the editor's vocabulary across a round-trip.  In-
    // vocabulary keys land below from widget state, including explicit
    // removal when the user cleared a field.
    for (k, v) in st.initial_data.borrow().iter() {
        if WIDGET_DATA_KEYS.contains(&k.as_str()) {
            continue;
        }
        let kc = match CString::new(k.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let vc = match CString::new(v.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        nm_setting_vpn_add_data_item(s_vpn, kc.as_ptr(), vc.as_ptr());
    }

    let tls_like = matches!(ct, "tls" | "password" | "password-tls");
    let needs_user_cert = matches!(ct, "tls" | "password-tls");
    let needs_password = matches!(ct, "password" | "password-tls");
    let is_static_key = ct == "static-key";

    // Helpers — empty value clears the key, so non-applicable widgets
    // and zeroed spin rows both round-trip as a remove.
    let cond = |b: bool, s: &str| -> String {
        if b {
            s.to_string()
        } else {
            String::new()
        }
    };
    let int_or_empty = |v: i64| -> String {
        if v > 0 {
            v.to_string()
        } else {
            String::new()
        }
    };

    set("connection-type", ct);
    set("remote", st.remote.text().as_ref());
    set("port", &int_or_empty(st.port.value() as i64));

    set("ca", &cond(tls_like, st.ca.text().as_ref()));
    set("cert", &cond(needs_user_cert, st.cert.text().as_ref()));
    set("key", &cond(needs_user_cert, st.key.text().as_ref()));
    // Hold the derived secret in a Zeroizing<String> so our heap copy
    // is scrubbed on drop.  (The GTK entry buffer + the glib::GString it
    // returns remain GTK-owned and unscrubbed — outside our control.)
    let cert_pass = Zeroizing::new(cond(needs_user_cert, st.cert_pass.text().as_ref()));
    set_secret("cert-pass", cert_pass.as_str());

    set(
        "username",
        &cond(needs_password, st.username.text().as_ref()),
    );
    let pw = Zeroizing::new(cond(needs_password, st.password.text().as_ref()));
    set_secret("password", pw.as_str());

    set(
        "static-key",
        &cond(is_static_key, st.static_key.text().as_ref()),
    );
    set(
        "static-key-direction",
        &cond(is_static_key, st.static_key_dir.selected_id()),
    );

    set("nm-openvpn3-profile", st.profile_path.text().as_ref());

    // Device + Connection
    set("dev", st.dev.text().as_ref());
    set("dev-type", st.dev_type.selected_id());
    set(
        "proto-tcp",
        if st.proto_tcp.is_active() { "yes" } else { "" },
    );
    set("tunnel-mtu", &int_or_empty(st.tun_mtu.value() as i64));
    // Switch off → drop the key (empty string clears).  Switch on with
    // byte count 0 → "yes" (openvpn3 picks).  Switch on with explicit
    // byte count → numeric string.
    let mssfix_value = if !st.mssfix_enabled.is_active() {
        String::new()
    } else {
        let bytes = st.mssfix_bytes.value() as i64;
        if bytes > 0 {
            bytes.to_string()
        } else {
            "yes".to_string()
        }
    };
    set("mssfix", &mssfix_value);
    set("fragment-size", &int_or_empty(st.fragment.value() as i64));
    set("ping", &int_or_empty(st.keepalive_ping.value() as i64));
    set(
        "ping-restart",
        &int_or_empty(st.keepalive_restart.value() as i64),
    );
    set(
        "reneg-seconds",
        &int_or_empty(st.reneg_seconds.value() as i64),
    );
    set(
        "connect-timeout",
        &int_or_empty(st.connect_timeout.value() as i64),
    );

    // Compression
    set("allow-compression", st.allow_compression.selected_id());
    set("comp-lzo", st.comp_lzo.selected_id());
    set("compress", st.compress.selected_id());

    // Security
    set("cipher", st.cipher.selected_id());
    set("data-ciphers", st.data_ciphers.text().as_ref());
    set(
        "data-ciphers-fallback",
        st.data_ciphers_fallback.selected_id(),
    );
    set("tls-cipher", st.tls_cipher.text().as_ref());
    set("auth", st.auth.selected_id());
    set("keysize", &int_or_empty(st.keysize.value() as i64));

    // TLS
    set("tls-version-min", st.tls_version_min.selected_id());
    set(
        "tls-version-min-or-highest",
        if st.tls_version_min_or_highest.is_active() {
            "yes"
        } else {
            ""
        },
    );
    set("tls-version-max", st.tls_version_max.selected_id());
    set("verify-x509-name", st.verify_x509_name.text().as_ref());
    set("remote-cert-tls", st.remote_cert_tls.selected_id());
    set("ns-cert-type", st.ns_cert_type.selected_id());
    set("ta", st.ta.text().as_ref());
    set("ta-dir", st.ta_dir.selected_id());
    set("tls-crypt", st.tls_crypt.text().as_ref());
    set("tls-crypt-v2", st.tls_crypt_v2.text().as_ref());

    // Proxy
    set("proxy-type", st.proxy_type.selected_id());
    set("proxy-server", st.proxy_server.text().as_ref());
    set("proxy-port", &int_or_empty(st.proxy_port.value() as i64));
    set("http-proxy-username", st.proxy_user.text().as_ref());

    // Misc
    set(
        "override-route-nopull",
        if st.or_route_nopull.is_active() {
            "yes"
        } else {
            ""
        },
    );
    set(
        "override-force-default-gateway",
        if st.or_force_default_gateway.is_active() {
            "yes"
        } else {
            ""
        },
    );
    set(
        "override-block-ipv6",
        if st.or_block_ipv6.is_active() {
            "yes"
        } else {
            ""
        },
    );
    set(
        "override-dns-setup-disabled",
        if st.or_dns_setup_disabled.is_active() {
            "yes"
        } else {
            ""
        },
    );
    set(
        "override-dco",
        if st.or_dco.is_active() { "yes" } else { "" },
    );
    set(
        "override-log-level",
        &int_or_empty(st.or_log_level.value() as i64),
    );

    GTRUE
    })
}

unsafe extern "C" fn iface_init(iface_data: gpointer, _user_data: gpointer) {
    let iface = iface_data.cast::<NMVpnEditorInterface>();
    (*iface).get_widget = Some(iface_get_widget);
    (*iface).update_connection = Some(iface_update_connection);
    (*iface).changed = None;
    (*iface).placeholder = None;
}

pub fn editor_get_type() -> glib_sys::GType {
    *EDITOR_TYPE.get_or_init(|| unsafe {
        let type_name = c"NMOpenvpn3Editor";
        let g_type = g_type_register_static_simple(
            G_TYPE_OBJECT,
            type_name.as_ptr().cast(),
            std::mem::size_of::<Openvpn3EditorClass>() as u32,
            Some(class_init),
            std::mem::size_of::<Openvpn3Editor>() as u32,
            Some(instance_init),
            G_TYPE_FLAG_NONE,
        );
        let iface_info = GInterfaceInfo {
            interface_init: Some(iface_init),
            interface_finalize: None,
            interface_data: ptr::null_mut(),
        };
        g_type_add_interface_static(g_type, nm_vpn_editor_get_type(), &iface_info as *const _);
        g_type
    })
}

// ---------------------------------------------------------------------------
// Row construction helpers — every one returns a fully styled libadwaita
// row that drops cleanly into a PreferencesGroup.
// ---------------------------------------------------------------------------

fn combo_row(
    title: &str,
    subtitle: Option<&str>,
    choices: &[(&str, &str)],
    initial: Option<&str>,
) -> ComboBinding {
    let row = ComboRow::new();
    row.set_title(&tr(title));
    if let Some(s) = subtitle {
        row.set_subtitle(&tr(s));
    }
    let labels: Vec<String> = choices
        .iter()
        .map(|(_, l)| {
            if passthrough_label(l) {
                (*l).to_string()
            } else {
                tr(l)
            }
        })
        .collect();
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let model = StringList::new(&label_refs);
    let mut ids = Vec::with_capacity(choices.len());
    let mut selected = 0u32;
    for (i, (id, _)) in choices.iter().enumerate() {
        ids.push((*id).to_string());
        if initial == Some(*id) {
            selected = i as u32;
        }
    }
    row.set_model(Some(&model));
    row.set_selected(selected);
    ComboBinding { row, ids }
}

fn spin_row(title: &str, subtitle: Option<&str>, min: f64, max: f64, value: f64) -> SpinRow {
    let row = SpinRow::with_range(min, max, 1.0);
    row.set_title(&tr(title));
    if let Some(s) = subtitle {
        row.set_subtitle(&tr(s));
    }
    row.set_value(value);
    row
}

fn switch_row(title: &str, subtitle: Option<&str>, initial: bool) -> SwitchRow {
    let row = SwitchRow::new();
    row.set_title(&tr(title));
    if let Some(s) = subtitle {
        row.set_subtitle(&tr(s));
    }
    row.set_active(initial);
    row
}

fn entry_row(title: &str, tooltip: Option<&str>, initial: &str) -> EntryRow {
    let r = EntryRow::new();
    r.set_title(&tr(title));
    r.set_text(initial);
    if let Some(t) = tooltip {
        r.set_tooltip_text(Some(&tr(t)));
    }
    r
}

/// File-filter spec for a picker row.  Each entry pairs a translatable
/// human-readable name with a list of glob patterns; the row builder
/// always appends an "All files" wildcard so users can fall through if
/// a peer ships a profile with an unusual extension.
type PickerFilters = &'static [(&'static str, &'static [&'static str])];

const FILTER_CERT: PickerFilters =
    &[("Certificates (PEM, CRT, CER)", &["*.pem", "*.crt", "*.cer"])];
const FILTER_KEY: PickerFilters = &[
    ("Keys (PEM, KEY)", &["*.pem", "*.key"]),
    ("PKCS#12 bundles (P12, PFX)", &["*.p12", "*.pfx"]),
];
const FILTER_PROFILE: PickerFilters = &[("OpenVPN profiles (OVPN, CONF)", &["*.ovpn", "*.conf"])];
const FILTER_KEY_MATERIAL: PickerFilters =
    &[("Key material (KEY, PEM, TXT)", &["*.key", "*.pem", "*.txt"])];

/// Build an `AdwEntryRow` with a `document-open-symbolic` suffix
/// button.  Clicking the button opens a `GtkFileDialog` rooted at the
/// row's nearest window ancestor with the supplied filters applied;
/// selection writes the absolute path back into the entry.
fn path_picker_row(
    title: &str,
    tooltip: Option<&str>,
    initial: &str,
    filters: PickerFilters,
) -> EntryRow {
    let row = entry_row(title, tooltip, initial);
    let button = gtk4::Button::from_icon_name("document-open-symbolic");
    button.set_valign(gtk4::Align::Center);
    button.add_css_class("flat");
    let browse_label = tr("Browse for file…");
    button.set_tooltip_text(Some(&browse_label));
    // Screen readers that ignore tooltips still need an accessible name
    // — the symbolic icon button has no visible text.
    button.update_property(&[gtk4::accessible::Property::Label(&browse_label)]);

    let row_weak = row.downgrade();
    button.connect_clicked(move |btn| {
        let Some(row) = row_weak.upgrade() else {
            return;
        };
        let dialog = gtk4::FileDialog::new();
        dialog.set_title(&tr("Select file"));

        // tr() runs every click so a host that flipped locale mid-
        // session (gnome-control-center → Region & Language) sees fresh
        // filter names without rebuilding the editor.  Filters are
        // re-materialised per click anyway because FileDialog::filters
        // wants a fresh ListStore.
        if !filters.is_empty() {
            let store = gio::ListStore::new::<gtk4::FileFilter>();
            for (name, patterns) in filters {
                let f = gtk4::FileFilter::new();
                f.set_name(Some(&tr(name)));
                for p in *patterns {
                    f.add_pattern(p);
                }
                store.append(&f);
            }
            // Always offer a wildcard fallback — drops out the moment a
            // user hits a profile with `.txt` or no extension at all.
            let all = gtk4::FileFilter::new();
            all.set_name(Some(&tr("All files")));
            all.add_pattern("*");
            store.append(&all);
            dialog.set_filters(Some(&store));
        }

        let parent_window = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
        let row_weak2 = row.downgrade();
        dialog.open(
            parent_window.as_ref(),
            None::<&gio::Cancellable>,
            move |result| {
                if let Ok(file) = result {
                    if let Some(path) = file.path() {
                        if let Some(s) = path.to_str() {
                            if let Some(row) = row_weak2.upgrade() {
                                row.set_text(s);
                            }
                        }
                    }
                }
            },
        );
    });
    row.add_suffix(&button);
    row
}

fn password_row(title: &str) -> PasswordEntryRow {
    let r = PasswordEntryRow::new();
    r.set_title(&tr(title));
    r
}

fn parse_int_default(s: Option<&String>, default: f64) -> f64 {
    s.and_then(|v| v.parse::<f64>().ok()).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Widget tree construction.
// ---------------------------------------------------------------------------

fn build_widget_tree(initial: &std::collections::BTreeMap<String, String>) -> EditorState {
    let page = PreferencesPage::new();
    page.set_title(&tr("OpenVPN 3"));

    // ---- General ----
    let g_general = PreferencesGroup::new();
    g_general.set_title(&tr("General"));
    g_general.set_description(Some(&tr(
        "Server and credentials. Advanced settings collapse below.",
    )));

    let initial_ct = initial
        .get("connection-type")
        .map(String::as_str)
        .unwrap_or(CONTYPE_TLS);
    let contype = combo_row(
        "Connection type",
        Some("Selects which credentials the server expects."),
        CONTYPES,
        Some(initial_ct),
    );
    g_general.add(&contype.row);

    let remote = entry_row(
        "Gateway",
        Some("Server hostname or IP. Comma-separated entries fail over in order."),
        initial.get("remote").map(String::as_str).unwrap_or(""),
    );
    g_general.add(&remote);

    let port = spin_row(
        "Port",
        Some("0 leaves the value at openvpn's default (1194)."),
        0.0,
        65535.0,
        parse_int_default(initial.get("port"), 0.0),
    );
    g_general.add(&port);

    let ca = path_picker_row(
        "CA certificate",
        Some("PEM-encoded certificate authority that signs the server."),
        initial.get("ca").map(String::as_str).unwrap_or(""),
        FILTER_CERT,
    );
    g_general.add(&ca);

    let cert = path_picker_row(
        "User certificate",
        Some("PEM-encoded client certificate."),
        initial.get("cert").map(String::as_str).unwrap_or(""),
        FILTER_CERT,
    );
    g_general.add(&cert);

    let key = path_picker_row(
        "Private key",
        Some("PEM or PKCS#12 file matching the user certificate."),
        initial.get("key").map(String::as_str).unwrap_or(""),
        FILTER_KEY,
    );
    g_general.add(&key);

    let cert_pass = password_row("Private key passphrase");
    g_general.add(&cert_pass);

    let username = entry_row(
        "Username",
        None,
        initial.get("username").map(String::as_str).unwrap_or(""),
    );
    g_general.add(&username);

    let password = password_row("Password");
    g_general.add(&password);

    let static_key = path_picker_row(
        "Static key file",
        Some("Pre-shared key. Only used when Connection type is Static key."),
        initial.get("static-key").map(String::as_str).unwrap_or(""),
        FILTER_KEY_MATERIAL,
    );
    g_general.add(&static_key);

    let static_key_dir = combo_row(
        "Static key direction",
        None,
        KEY_DIR,
        initial.get("static-key-direction").map(String::as_str),
    );
    g_general.add(&static_key_dir.row);

    let profile_path = path_picker_row(
        "Inline .ovpn profile",
        Some("Optional path to a verbatim .ovpn file. When set, the file is fed straight to openvpn3 and the rest of these fields are ignored."),
        initial
            .get("nm-openvpn3-profile")
            .map(String::as_str)
            .unwrap_or(""),
        FILTER_PROFILE,
    );
    g_general.add(&profile_path);
    page.add(&g_general);

    // Everything past General lives under collapsible AdwExpanderRows
    // inside a single "Advanced" group.  HIG: don't nest tabs inside
    // tabs (cc-network-panel already wraps us); use ExpanderRow to
    // keep the page short on first open and expand on demand.
    let g_advanced = PreferencesGroup::new();
    g_advanced.set_title(&tr("Advanced"));
    g_advanced.set_description(Some(&tr(
        "Sections below collapse — open the ones you need. Empty fields keep openvpn3's defaults.",
    )));

    // ---- Device ----
    let exp_device = ExpanderRow::new();
    exp_device.set_title(&tr("Device"));
    exp_device.set_subtitle(&tr("Tun / tap interface, MTU, fragmentation."));
    let dev = entry_row(
        "Custom device name",
        Some("Leave empty for openvpn3's default (tun0, tun1, …)."),
        initial.get("dev").map(String::as_str).unwrap_or(""),
    );
    exp_device.add_row(&dev);
    let dev_type = combo_row(
        "Device type",
        Some("tun (layer 3, default) or tap (layer 2 bridge)."),
        DEV_TYPES,
        initial.get("dev-type").map(String::as_str),
    );
    exp_device.add_row(&dev_type.row);
    let tun_mtu = spin_row(
        "Tunnel MTU",
        Some("0 leaves openvpn3 to negotiate."),
        0.0,
        65535.0,
        parse_int_default(initial.get("tunnel-mtu"), 0.0),
    );
    exp_device.add_row(&tun_mtu);
    let fragment = spin_row(
        "Fragment size",
        Some("0 disables fragmentation. Set when the path MTU is unstable."),
        0.0,
        65535.0,
        parse_int_default(initial.get("fragment-size"), 0.0),
    );
    exp_device.add_row(&fragment);
    // mssfix is "" (default / disabled), "yes" (enabled, auto byte count),
    // "no" (disabled), or a positive integer (enabled, explicit bytes).
    // Surface as a switch + companion spin; the spin only meaningfully
    // applies when the switch is on (0 ≙ "yes", >0 ≙ explicit value).
    let mssfix_raw = initial.get("mssfix").map(String::as_str).unwrap_or("");
    // Clamp at parse so a hostile vpn.data ("mssfix=-1") cannot land a
    // negative spin value that would survive a switch-off / switch-on
    // round-trip if the user never touches the spin.
    let mssfix_bytes_initial: f64 = mssfix_raw.parse::<f64>().unwrap_or(0.0).max(0.0);
    let mssfix_on = matches!(mssfix_raw, "yes") || mssfix_bytes_initial > 0.0;
    let mssfix_enabled = switch_row(
        "MSSfix",
        Some("Cap TCP payload to fit inside the tunnel MTU."),
        mssfix_on,
    );
    exp_device.add_row(&mssfix_enabled);
    let mssfix_bytes = spin_row(
        "MSSfix byte count",
        Some("0 lets openvpn3 pick the value automatically."),
        0.0,
        65535.0,
        mssfix_bytes_initial,
    );
    mssfix_bytes.set_visible(mssfix_on);
    exp_device.add_row(&mssfix_bytes);
    g_advanced.add(&exp_device);

    // ---- Connection / timing ----
    let exp_conn = ExpanderRow::new();
    exp_conn.set_title(&tr("Connection"));
    exp_conn.set_subtitle(&tr("Protocol, keepalive, timeouts."));
    let proto_tcp = switch_row(
        "Use TCP",
        Some("Off uses UDP (recommended). Enable only when UDP is blocked."),
        initial.get("proto-tcp").map(String::as_str) == Some("yes"),
    );
    exp_conn.add_row(&proto_tcp);
    let keepalive_ping = spin_row(
        "Ping interval",
        Some("Seconds between keepalive probes. 0 disables."),
        0.0,
        3600.0,
        parse_int_default(initial.get("ping"), 0.0),
    );
    exp_conn.add_row(&keepalive_ping);
    let keepalive_restart = spin_row(
        "Restart after",
        Some("Seconds without traffic before openvpn3 restarts the session."),
        0.0,
        3600.0,
        parse_int_default(initial.get("ping-restart"), 0.0),
    );
    exp_conn.add_row(&keepalive_restart);
    let reneg_seconds = spin_row(
        "Renegotiate after",
        Some("Re-key seconds. 0 leaves the default (3600)."),
        0.0,
        86400.0,
        parse_int_default(initial.get("reneg-seconds"), 0.0),
    );
    exp_conn.add_row(&reneg_seconds);
    let connect_timeout = spin_row(
        "Connect timeout",
        Some("Seconds to wait for the initial connection. 0 keeps the default."),
        0.0,
        3600.0,
        parse_int_default(initial.get("connect-timeout"), 0.0),
    );
    exp_conn.add_row(&connect_timeout);
    g_advanced.add(&exp_conn);

    // ---- Compression ----
    let exp_comp = ExpanderRow::new();
    exp_comp.set_title(&tr("Compression"));
    exp_comp.set_subtitle(&tr(
        "Disable unless your server enforces it (modern default).",
    ));
    let allow_compression = combo_row(
        "Allow compression",
        Some("Master switch — disabling overrides the two options below."),
        ALLOW_COMPRESSION,
        initial.get("allow-compression").map(String::as_str),
    );
    exp_comp.add_row(&allow_compression.row);
    let comp_lzo = combo_row(
        "LZO compression (legacy)",
        Some("Off is the modern default."),
        COMP_LZO,
        initial.get("comp-lzo").map(String::as_str),
    );
    exp_comp.add_row(&comp_lzo.row);
    let compress = combo_row(
        "Compression algorithm",
        None,
        COMPRESS,
        initial.get("compress").map(String::as_str),
    );
    exp_comp.add_row(&compress.row);
    g_advanced.add(&exp_comp);

    // ---- Security ----
    let exp_sec = ExpanderRow::new();
    exp_sec.set_title(&tr("Security"));
    exp_sec.set_subtitle(&tr("Ciphers and HMAC algorithms."));
    let cipher = combo_row(
        "Legacy cipher",
        Some("Used with older servers. Modern setups use data-ciphers."),
        CIPHERS,
        initial.get("cipher").map(String::as_str),
    );
    exp_sec.add_row(&cipher.row);
    let data_ciphers = entry_row(
        "Data ciphers",
        Some("Colon-separated list, highest preference first."),
        initial
            .get("data-ciphers")
            .map(String::as_str)
            .unwrap_or(""),
    );
    exp_sec.add_row(&data_ciphers);
    let data_ciphers_fallback = combo_row(
        "Data ciphers fallback",
        Some("Cipher to use when negotiation fails."),
        CIPHERS,
        initial.get("data-ciphers-fallback").map(String::as_str),
    );
    exp_sec.add_row(&data_ciphers_fallback.row);
    let tls_cipher = entry_row(
        "TLS cipher",
        Some("OpenSSL cipher string for the control channel."),
        initial.get("tls-cipher").map(String::as_str).unwrap_or(""),
    );
    exp_sec.add_row(&tls_cipher);
    let auth = combo_row(
        "HMAC authentication",
        None,
        AUTH_ALGS,
        initial.get("auth").map(String::as_str),
    );
    exp_sec.add_row(&auth.row);
    let keysize = spin_row(
        "Key size",
        Some("0 leaves the cipher's native key size."),
        0.0,
        65535.0,
        parse_int_default(initial.get("keysize"), 0.0),
    );
    exp_sec.add_row(&keysize);
    g_advanced.add(&exp_sec);

    // ---- TLS ----
    let exp_tls = ExpanderRow::new();
    exp_tls.set_title(&tr("TLS"));
    exp_tls.set_subtitle(&tr(
        "TLS versions, peer verification, control-channel keys.",
    ));
    let tls_version_min = combo_row(
        "Minimum TLS version",
        None,
        TLS_VERSIONS,
        initial.get("tls-version-min").map(String::as_str),
    );
    exp_tls.add_row(&tls_version_min.row);
    let tls_version_min_or_highest = switch_row(
        "Use highest available if unsupported",
        Some("Fall back to the highest TLS version the peer supports rather than refusing the connection."),
        initial
            .get("tls-version-min-or-highest")
            .map(String::as_str)
            == Some("yes"),
    );
    exp_tls.add_row(&tls_version_min_or_highest);
    let tls_version_max = combo_row(
        "Maximum TLS version",
        None,
        TLS_VERSIONS,
        initial.get("tls-version-max").map(String::as_str),
    );
    exp_tls.add_row(&tls_version_max.row);
    let verify_x509_name = entry_row(
        "Verify X.509 name",
        Some("Optional type:name prefix, for example name-prefix:server."),
        initial
            .get("verify-x509-name")
            .map(String::as_str)
            .unwrap_or(""),
    );
    exp_tls.add_row(&verify_x509_name);
    let remote_cert_tls = combo_row(
        "Require remote certificate type",
        None,
        REMOTE_CERT_TLS,
        initial.get("remote-cert-tls").map(String::as_str),
    );
    exp_tls.add_row(&remote_cert_tls.row);
    let ns_cert_type = combo_row(
        "Legacy NS certificate type",
        Some("Pre-X509 v3 server check. Leave at Not enforced unless your server requires it."),
        NS_CERT_TYPE,
        initial.get("ns-cert-type").map(String::as_str),
    );
    exp_tls.add_row(&ns_cert_type.row);
    let ta = path_picker_row(
        "TLS-auth key",
        Some("HMAC key for the control channel."),
        initial.get("ta").map(String::as_str).unwrap_or(""),
        FILTER_KEY_MATERIAL,
    );
    exp_tls.add_row(&ta);
    let ta_dir = combo_row(
        "TLS-auth direction",
        None,
        KEY_DIR,
        initial.get("ta-dir").map(String::as_str),
    );
    exp_tls.add_row(&ta_dir.row);
    let tls_crypt = path_picker_row(
        "TLS-crypt key",
        Some("Encrypted control channel key."),
        initial.get("tls-crypt").map(String::as_str).unwrap_or(""),
        FILTER_KEY_MATERIAL,
    );
    exp_tls.add_row(&tls_crypt);
    let tls_crypt_v2 = path_picker_row(
        "TLS-crypt-v2 key",
        Some("Modern per-client control channel key."),
        initial
            .get("tls-crypt-v2")
            .map(String::as_str)
            .unwrap_or(""),
        FILTER_KEY_MATERIAL,
    );
    exp_tls.add_row(&tls_crypt_v2);
    g_advanced.add(&exp_tls);

    // ---- Proxy ----
    let exp_proxy = ExpanderRow::new();
    exp_proxy.set_title(&tr("Proxy"));
    exp_proxy.set_subtitle(&tr("HTTP or SOCKS proxy in front of the VPN."));
    let proxy_type = combo_row(
        "Proxy type",
        None,
        PROXY_TYPES,
        initial.get("proxy-type").map(String::as_str),
    );
    exp_proxy.add_row(&proxy_type.row);
    let proxy_server = entry_row(
        "Proxy server",
        None,
        initial
            .get("proxy-server")
            .map(String::as_str)
            .unwrap_or(""),
    );
    exp_proxy.add_row(&proxy_server);
    let proxy_port = spin_row(
        "Proxy port",
        Some("0 uses the type's default (HTTP 8080, SOCKS 1080)."),
        0.0,
        65535.0,
        parse_int_default(initial.get("proxy-port"), 0.0),
    );
    exp_proxy.add_row(&proxy_port);
    let proxy_user = entry_row(
        "Proxy username",
        None,
        initial
            .get("http-proxy-username")
            .map(String::as_str)
            .unwrap_or(""),
    );
    exp_proxy.add_row(&proxy_user);
    g_advanced.add(&exp_proxy);

    // ---- Misc / overrides ----
    let exp_misc = ExpanderRow::new();
    exp_misc.set_title(&tr("Misc"));
    exp_misc.set_subtitle(&tr(
        "Override flags forwarded to openvpn3's SetOverride API.",
    ));
    let or_route_nopull = switch_row(
        "Don't pull routes from server",
        Some("Useful when you only want the VPN for traffic you route yourself."),
        initial.get("override-route-nopull").map(String::as_str) == Some("yes"),
    );
    exp_misc.add_row(&or_route_nopull);
    let or_force_default_gateway = switch_row(
        "Force default gateway",
        Some("Forwards all traffic through the tunnel even if the server didn't push it."),
        initial
            .get("override-force-default-gateway")
            .map(String::as_str)
            == Some("yes"),
    );
    exp_misc.add_row(&or_force_default_gateway);
    let or_block_ipv6 = switch_row(
        "Block IPv6",
        Some("Drop IPv6 traffic instead of leaking it outside the tunnel."),
        initial.get("override-block-ipv6").map(String::as_str) == Some("yes"),
    );
    exp_misc.add_row(&or_block_ipv6);
    let or_dns_setup_disabled = switch_row(
        "Don't configure DNS",
        Some("Leaves system resolvers alone — useful with systemd-resolved or a local resolver."),
        initial
            .get("override-dns-setup-disabled")
            .map(String::as_str)
            == Some("yes"),
    );
    exp_misc.add_row(&or_dns_setup_disabled);
    let or_dco = switch_row(
        "Data-channel offload (DCO)",
        Some(
            "Hands the data path to a kernel module on supported systems for big throughput gains.",
        ),
        initial.get("override-dco").map(String::as_str) == Some("yes"),
    );
    exp_misc.add_row(&or_dco);
    let or_log_level = spin_row(
        "Override log level",
        Some("0 keeps the default. 1–6 raises openvpn3's verbosity."),
        0.0,
        6.0,
        parse_int_default(initial.get("override-log-level"), 0.0),
    );
    exp_misc.add_row(&or_log_level);
    g_advanced.add(&exp_misc);

    page.add(&g_advanced);

    let state = EditorState {
        page,
        contype,
        remote,
        port,
        ca,
        cert,
        key,
        cert_pass,
        username,
        password,
        profile_path,
        static_key,
        static_key_dir,
        dev,
        dev_type,
        proto_tcp,
        tun_mtu,
        mssfix_enabled,
        mssfix_bytes,
        fragment,
        keepalive_ping,
        keepalive_restart,
        reneg_seconds,
        connect_timeout,
        allow_compression,
        comp_lzo,
        compress,
        cipher,
        data_ciphers,
        data_ciphers_fallback,
        tls_cipher,
        auth,
        keysize,
        tls_version_min,
        tls_version_min_or_highest,
        tls_version_max,
        verify_x509_name,
        remote_cert_tls,
        ns_cert_type,
        ta,
        ta_dir,
        tls_crypt,
        tls_crypt_v2,
        proxy_type,
        proxy_server,
        proxy_port,
        proxy_user,
        or_route_nopull,
        or_force_default_gateway,
        or_block_ipv6,
        or_dns_setup_disabled,
        or_dco,
        or_log_level,
        initial_data: RefCell::new(initial.clone()),
        alive: Arc::new(AtomicBool::new(true)),
    };

    // Use the combo's resolved selection, not the raw stored string:
    // combo_row clamps an unknown/missing connection-type to index 0
    // ("tls"), so an out-of-vocabulary initial_ct would otherwise hide
    // credential rows the (TLS-showing) combo says should be visible.
    apply_contype_visibility(&state, state.contype.selected_id());
    wire_contype_visibility(&state);
    wire_mssfix_visibility(&state);
    state
}

/// Bind the MSSfix switch's `notify::active` to the byte-count spin's
/// visibility so the explicit-bytes field only appears when MSSfix is
/// actually enabled.
fn wire_mssfix_visibility(st: &EditorState) {
    let spin_weak: glib::WeakRef<SpinRow> = st.mssfix_bytes.downgrade();
    st.mssfix_enabled.connect_active_notify(move |sw| {
        if let Some(spin) = spin_weak.upgrade() {
            spin.set_visible(sw.is_active());
        }
    });
}

/// Toggle visibility of credential/cert/static-key rows for a given
/// connection-type.  Matches the C tree's per-type field gating.
fn apply_contype_visibility(st: &EditorState, contype: &str) {
    let tls_like = matches!(contype, "tls" | "password" | "password-tls");
    let needs_user_cert = matches!(contype, "tls" | "password-tls");
    let needs_password = matches!(contype, "password" | "password-tls");
    let is_static_key = contype == "static-key";

    st.ca.set_visible(tls_like);
    st.cert.set_visible(needs_user_cert);
    st.key.set_visible(needs_user_cert);
    st.cert_pass.set_visible(needs_user_cert);
    st.username.set_visible(needs_password);
    st.password.set_visible(needs_password);
    st.static_key.set_visible(is_static_key);
    st.static_key_dir.row.set_visible(is_static_key);
}

/// Fire `NMVpnEditor::changed` on the editor GObject so libnma
/// enables the dialog's Apply button.  Signal lives on the libnm
/// interface, registered when our GType added it via
/// g_type_add_interface_static.
///
/// The `alive` flag is the lifetime gate flipped in
/// `instance_finalize`; checking it before dereferencing the
/// GObject pointer keeps a regression in widget-destruction order
/// from causing a use-after-free.
fn emit_changed(editor_ptr: usize, alive: &AtomicBool) {
    if editor_ptr == 0 || !alive.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        nm_vpn_plugin_openvpn3::libnm::g_signal_emit_by_name(
            editor_ptr as *mut std::ffi::c_void,
            c"changed".as_ptr(),
        );
    }
}

/// Mark a path-picker `EntryRow` red when its current text is non-
/// empty and the path does not resolve to a regular file.  Toggled
/// on every `notify::text` so the indicator reflects live state.
fn refresh_path_validity(entry: &EntryRow) {
    let text = entry.text();
    let path = text.as_str();
    let ok = path.is_empty() || std::path::Path::new(path).is_file();
    if ok {
        entry.remove_css_class("error");
    } else {
        entry.add_css_class("error");
    }
}

/// Bind path-existence validation + the editor's `changed` signal
/// onto every path-picker entry.  Call once after building the
/// widget tree.
fn wire_path_validation(st: &EditorState, editor_ptr: usize) {
    let pickers: &[&EntryRow] = &[
        &st.ca,
        &st.cert,
        &st.key,
        &st.profile_path,
        &st.static_key,
        &st.ta,
        &st.tls_crypt,
        &st.tls_crypt_v2,
    ];
    for p in pickers {
        refresh_path_validity(p);
        let weak: glib::WeakRef<EntryRow> = (*p).downgrade();
        let alive = st.alive.clone();
        (*p).connect_changed(move |_| {
            if let Some(row) = weak.upgrade() {
                refresh_path_validity(&row);
            }
            emit_changed(editor_ptr, &alive);
        });
    }
}

/// Hook every interactive widget's change signal so it fires the
/// editor-level `changed` signal libnma listens for.  `editor_ptr`
/// is a `usize`-erased *mut GObject (raw pointer is Copy + safely
/// sharable with gtk4-rs's non-Send closures); the `alive` flag
/// gates each fire against the editor still being live.
fn wire_changed_signals(st: &EditorState, editor_ptr: usize) {
    // ComboRow `notify::selected` fires on every drop-down pick.
    let combos: &[&ComboRow] = &[
        &st.contype.row,
        &st.dev_type.row,
        &st.static_key_dir.row,
        &st.allow_compression.row,
        &st.comp_lzo.row,
        &st.compress.row,
        &st.cipher.row,
        &st.data_ciphers_fallback.row,
        &st.auth.row,
        &st.tls_version_min.row,
        &st.tls_version_max.row,
        &st.remote_cert_tls.row,
        &st.ns_cert_type.row,
        &st.ta_dir.row,
        &st.proxy_type.row,
    ];
    for c in combos {
        let alive = st.alive.clone();
        (*c).connect_selected_item_notify(move |_| emit_changed(editor_ptr, &alive));
    }

    let entries: &[&EntryRow] = &[
        &st.remote,
        &st.username,
        &st.dev,
        &st.data_ciphers,
        &st.tls_cipher,
        &st.verify_x509_name,
        &st.proxy_server,
        &st.proxy_user,
    ];
    for e in entries {
        let alive = st.alive.clone();
        (*e).connect_changed(move |_| emit_changed(editor_ptr, &alive));
    }

    // Passwords are entries too, but the EntryRow path-validation
    // helper already binds the path-picker entries; only the bare
    // entries above are still missing.
    let alive_cp = st.alive.clone();
    st.cert_pass
        .connect_changed(move |_| emit_changed(editor_ptr, &alive_cp));
    let alive_pw = st.alive.clone();
    st.password
        .connect_changed(move |_| emit_changed(editor_ptr, &alive_pw));

    let spins: &[&SpinRow] = &[
        &st.port,
        &st.tun_mtu,
        &st.mssfix_bytes,
        &st.fragment,
        &st.keepalive_ping,
        &st.keepalive_restart,
        &st.reneg_seconds,
        &st.connect_timeout,
        &st.keysize,
        &st.proxy_port,
        &st.or_log_level,
    ];
    for s in spins {
        let alive = st.alive.clone();
        (*s).connect_value_notify(move |_| emit_changed(editor_ptr, &alive));
    }

    let switches: &[&SwitchRow] = &[
        &st.proto_tcp,
        &st.mssfix_enabled,
        &st.tls_version_min_or_highest,
        &st.or_route_nopull,
        &st.or_force_default_gateway,
        &st.or_block_ipv6,
        &st.or_dns_setup_disabled,
        &st.or_dco,
    ];
    for sw in switches {
        let alive = st.alive.clone();
        (*sw).connect_active_notify(move |_| emit_changed(editor_ptr, &alive));
    }
}

/// Wire the connection-type combo's `notify::selected` signal so the
/// row visibility tracks live edits, not just the initial value.
fn wire_contype_visibility(st: &EditorState) {
    // Per-widget weak references captured into the closure.  GTK
    // refcounts the widgets, so they live as long as their parent
    // PreferencesGroup; once the editor dialog is destroyed each
    // `upgrade()` here returns None and `set_visible` is skipped.
    // The closure is owned by the combo row's signal handler — when
    // the row dies, the closure dies, and the WeakRef payload with
    // it.  No leak, no use-after-free.
    struct WeakRows {
        ca: glib::WeakRef<EntryRow>,
        cert: glib::WeakRef<EntryRow>,
        key: glib::WeakRef<EntryRow>,
        cert_pass: glib::WeakRef<PasswordEntryRow>,
        username: glib::WeakRef<EntryRow>,
        password: glib::WeakRef<PasswordEntryRow>,
        static_key: glib::WeakRef<EntryRow>,
        static_key_dir: glib::WeakRef<ComboRow>,
    }

    let weak = Rc::new(WeakRows {
        ca: st.ca.downgrade(),
        cert: st.cert.downgrade(),
        key: st.key.downgrade(),
        cert_pass: st.cert_pass.downgrade(),
        username: st.username.downgrade(),
        password: st.password.downgrade(),
        static_key: st.static_key.downgrade(),
        static_key_dir: st.static_key_dir.row.downgrade(),
    });
    let ids = Rc::new(st.contype.ids.clone());

    st.contype.row.connect_selected_item_notify(move |combo| {
        let idx = combo.selected() as usize;
        let contype = ids.get(idx).map(String::as_str).unwrap_or("");
        let tls_like = matches!(contype, "tls" | "password" | "password-tls");
        let needs_user_cert = matches!(contype, "tls" | "password-tls");
        let needs_password = matches!(contype, "password" | "password-tls");
        let is_static_key = contype == "static-key";

        if let Some(w) = weak.ca.upgrade() {
            w.set_visible(tls_like);
        }
        if let Some(w) = weak.cert.upgrade() {
            w.set_visible(needs_user_cert);
        }
        if let Some(w) = weak.key.upgrade() {
            w.set_visible(needs_user_cert);
        }
        if let Some(w) = weak.cert_pass.upgrade() {
            w.set_visible(needs_user_cert);
        }
        if let Some(w) = weak.username.upgrade() {
            w.set_visible(needs_password);
        }
        if let Some(w) = weak.password.upgrade() {
            w.set_visible(needs_password);
        }
        if let Some(w) = weak.static_key.upgrade() {
            w.set_visible(is_static_key);
        }
        if let Some(w) = weak.static_key_dir.upgrade() {
            w.set_visible(is_static_key);
        }
    });
}

/// Construct a fresh editor wrapping `connection`'s state.
pub unsafe fn new_editor(connection: *mut NMConnection, error: *mut *mut GError) -> *mut GObject {
    // gtk4-rs / libadwaita-rs each track an INITIALIZED atomic per
    // Rust crate instance; when NM dlopens us from a C host the host's
    // C-level init has not touched our Rust state.  Idempotent on the
    // C side, so calling here is cheap.
    if !gtk4::is_initialized() {
        if let Err(e) = gtk4::init() {
            set_error(
                error,
                NM_OPENVPN3_PLUGIN_ERROR_FAILED,
                &format!("gtk4::init failed: {e}"),
            );
            return ptr::null_mut();
        }
    }
    // libadwaita::init is idempotent on the C side, but if it ever
    // fails (no display, missing schemas) widget construction below
    // will panic with "Gtk has to be initialized before using
    // libadwaita".  Surface a clean GError instead of letting the
    // panic cross the C ABI.
    if let Err(e) = libadwaita::init() {
        set_error(
            error,
            NM_OPENVPN3_PLUGIN_ERROR_FAILED,
            &format!("libadwaita::init failed: {e}"),
        );
        return ptr::null_mut();
    }
    gettext_init_once();

    let data = connection_to_nm_data(connection);

    let g_type = editor_get_type();
    let obj = g_object_new(g_type, ptr::null());
    if obj.is_null() {
        set_error(
            error,
            NM_OPENVPN3_PLUGIN_ERROR_FAILED,
            "g_object_new(NMOpenvpn3Editor) returned NULL",
        );
        return ptr::null_mut();
    }

    let state = Box::into_raw(Box::new(build_widget_tree(&data)));
    let inst = obj.cast::<Openvpn3Editor>();
    (*inst).state = state;

    // Wire signal handlers AFTER the EditorState is stashed.  Each
    // closure captures the editor GObject pointer as `usize` so it
    // is cheap to copy and safely shareable with non-Send signal
    // dispatch in gtk-rs.
    let editor_ptr = obj as usize;
    let st = &*state;
    wire_changed_signals(st, editor_ptr);
    wire_path_validation(st, editor_ptr);

    obj
}

// Silence the warning for unused imports brought in for traits.
const _: fn() = || {
    let _ = Path::new("");
};
