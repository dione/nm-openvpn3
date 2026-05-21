//! NetworkManager VPN properties library for openvpn3 — Rust port.
//!
//! Two consumers:
//!
//! * `cdylib` → `libnm-vpn-plugin-openvpn3.so`.  NM dlopens this to
//!   discover the openvpn3 plugin: `nm_vpn_editor_plugin_factory`
//!   returns a `GObject` implementing the `NMVpnEditorPlugin`
//!   interface ([`plugin`]).  Once loaded, the GObject's vtable
//!   provides `import_from_file`, `export_to_file`, `get_editor`
//!   (which dlopens the editor cdylib in turn), and the metadata
//!   properties NM displays in editor UIs.
//! * `rlib` — pure-Rust `.ovpn` import/export ([`import_export`]),
//!   reused by the editor crate when wiring widget state back to a
//!   live `NMConnection`.
//!
//! See `docs/UI-PORT.md` for design + phased plan.

pub mod bridge;
pub mod ffi;
pub mod import_export;
pub mod libnm;
pub mod plugin;
