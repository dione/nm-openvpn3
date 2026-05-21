# UI port — design + phased plan

The runtime side of nm-openvpn3 (service + auth-dialog) is feature-complete on the `rust/main` branch.  The UI side — the libnm discovery shim and the GTK editor that gnome-control-center / nm-applet / plasma-nm spawn — is **scaffolded only**.  This document explains what landed in round 1, the toolchain decisions, and what the next iterations need.

## Status as of rust/main HEAD

End-to-end working against gnome-control-center v49 + libnm 1.54 +
openvpn3-linux v27:

- `libnm-vpn-plugin-openvpn3.so` — `NMVpnEditorPlugin` GObject, hand-
  rolled GType + interface vtable. Implements
  `import_from_file` / `export_to_file` / `get_capabilities` /
  `get_suggested_filename` / `get_editor`.  ABI guard refuses to load
  on libnm < 1.30.
- `libnm-vpn-plugin-openvpn3-editor.so` — `NMVpnEditor` GObject,
  `AdwPreferencesPage` with General group + Advanced expander group
  (Device / Connection / Compression / Security / TLS / Proxy / Misc).
  File pickers via `gtk4::FileDialog`, file-existence indicator (red
  CSS) on path entries, `NMVpnEditor::changed` fires on every widget
  edit so libnma enables the Apply button.
- Connection-type combo gates credential / cert / static-key row
  visibility live.
- 60 gettext catalogs (Polish complete, 59 partial from upstream).
- CI builds both cdylibs, asserts factory symbols, validates every
  `.po` with `msgfmt -c`, and checks that the POT template hasn't
  drifted from `tr()` call sites.

## What landed in round 1

Two new workspace crates:

| Crate | Artifact | Status |
|---|---|---|
| `nm-openvpn3-properties` | `rlib` + `libnm-vpn-plugin-openvpn3.so` | `.ovpn` parser + emitter + NM-data projection complete; libnm cdylib entrypoint is a stub returning `NULL + GError("not yet implemented")` |
| `nm-openvpn3-editor` | `libnm-vpn-plugin-openvpn3-editor.so` | scaffold only — exports the `nm_vpn_editor_factory_openvpn3` C symbol, returns `NULL` |

Plus:

- `install-test.sh` installs both `.so` files when present (skips silently if a partial build did not produce them).
- `data/NetworkManager-VPN/nm-openvpn3-service.name.in` wires `[libnm] plugin=` and `[GNOME] properties=` to the new paths.
- `tests/fixtures/` carries a representative subset of the C tree's `.ovpn` test cases (`port`, `proto-tcp`, `pkcs12`, `pkcs12-with-ca`, `compress`, `connect-timeout`, `crl-file`, `device`, `keepalive`, `keysize`, `mtu-disc`, `ping-with-restart`, `proxy-http`, `proxy-socks` — 14 files).  Every fixture parses **and** round-trips through `parse → emit → parse` to an identical directive stream.

What the `properties` library does cover today:

- Tokeniser matching openvpn's `parse_line` semantics (`'…'`, `"…"`, `\<ch>` escapes, leading `--` stripped, `;`/`#` comments).
- Inline blob parsing for `<ca>`, `<cert>`, `<key>`, `<extra-certs>`, `<crl-verify>`, `<pkcs12>`, `<secret>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>` — unknown blobs return a parse error.
- An `OvpnConfig` data structure preserving directive order (so unknown options survive an import → save cycle — the dreaded "lost my custom directive" footgun the C exporter does *not* protect against).
- A `OvpnConfig::as_nm_data()` projection mapping the option set the editor will eventually expose (TLS, password, password-tls, static-key, pkcs12, http/socks proxy, x509 verification, TLS versions, compression, ping/timeout/MTU/fragment, etc.) onto vpn.data keys.
- connection-type inference matching the C importer's triage.

## Toolchain decisions

- **GUI stack: gtk4-rs + libadwaita**, behind the `gtk4-editor` Cargo feature.  Default cargo build does *not* pull in GTK4 development headers; build with `--features gtk4-editor` once we have a real editor.  GTK3 is end-of-life and the gtk3-rs binding is unmaintained; libadwaita gives us the `AdwPreferencesPage` widgetry the GNOME 45+ control-center expects.
- **libnm bindings: hand-rolled FFI**.  No `libnm-sys` / `libnm-rs` crate exists on crates.io that targets libnm ≥ 1.30 (`NMVpnEditorPlugin` interface).  Generating a binding via `gir` is a multi-week project of its own.  Round 1 declares the C entrypoints directly via `#[no_mangle] pub unsafe extern "C" fn …` and depends on `glib-sys` + `gobject-sys` (mature, low-churn crates) for `GError` / `GObject` / `GQuark` types only.  The full GType registration + interface vtable + property override comes in round 2.
- **Workspace member layout** mirrors the C tree's split: `nm-openvpn3-properties` is "the libnm side" (analog to `properties/nm-openvpn3-editor-plugin.c` + `properties/import-export.c`), `nm-openvpn3-editor` is "the GTK side" (analog to `properties/nm-openvpn3-editor.c`).  Sharing the `OvpnConfig` data structure across both crates means the editor reads/writes the *same* representation as the libnm cdylib + nmcli integration.

## Phased plan

### Round 2 — make `libnm-vpn-plugin-openvpn3.so` usable

1. **GType registration** for `NMOpenvpn3EditorPlugin`.  Hand-write `g_type_register_static_simple` + interface info that implements the `NMVpnEditorPlugin` vtable.  Reference: `properties/nm-openvpn3-editor-plugin.c:50-180`.
2. **Implement the four interface methods**:
   - `import_from_file(path) → NMConnection*` — wrap `OvpnConfig::parse` + libnm `NMConnection` construction.  Read settings via the existing `as_nm_data()` projection and `nm_simple_connection_new` + `nm_setting_vpn_new`.
   - `export_to_file(NMConnection, path)` — inverse: pull keys out of the connection, build a synthetic `OvpnConfig`, call `OvpnConfig::emit`, write the file.
   - `get_editor(plugin, connection)` — `g_module_open` + dlsym the editor cdylib (defer until round 3 produces one).
   - `get_capabilities`, `get_suggested_filename`, name/desc/service property overrides.
3. **nmcli smoke test**:
   ```sh
   nmcli connection import type openvpn3 file fixture.ovpn
   nmcli connection export ovpn3-imported > out.ovpn
   diff <(sort fixture.ovpn) <(sort out.ovpn)
   ```
   Round 2 ships when this command succeeds end-to-end and the editor field in nmcli list shows the plugin.

### Round 3 — `libnm-vpn-plugin-openvpn3-editor.so` (the GTK editor)

1. Add `gtk4`, `libadwaita`, `gtk4-sys`, `libadwaita-sys` workspace deps gated behind the `gtk4-editor` feature.
2. Implement `NMVpnEditor` GObject (interface from `<libnm/nm-vpn-editor.h>`):
   - `get_widget()` → root `AdwPreferencesPage`.
   - `update_connection(NMConnection)` → walk widget state + write back to the connection's `NMSettingVpn`.
   - `changed` signal emission so the dialog's Apply button enables.
3. Page layout mirrors the C tree's `properties/nm-openvpn3-dialog.ui` (Gtk3 GtkBuilder XML, ~3000 lines).  Translate per-tab to `AdwPreferencesGroup`s:
   - General: connection-type, remote(s), auth, cert/key/pkcs12, ca, user/password.
   - Advanced → General: TCP/UDP, port, MSSfix, fragment, MTU, ping, ping-restart, comp-lzo / compress.
   - Advanced → Security: cipher, data-ciphers, data-ciphers-fallback, HMAC auth, tls-cipher, tls-version-min/max, keysize.
   - Advanced → TLS: verify-x509-name, ns-cert-type, remote-cert-tls, tls-auth/tls-crypt/tls-crypt-v2.
   - Advanced → Proxies: http-proxy, socks-proxy.
   - Advanced → Misc: override-* flags (route-nopull, force-default-gateway, block-ipv6, dns-setup-disabled, dco), override-log-level (already plumbed in the service).
4. Translations live elsewhere — the gettext catalog (`po/` on the C branch) is keyed off C-side strings.  Round 3 will introduce a fresh `po/` against the Rust UI strings.

### Round 4 — UX polish + integration tests

1. End-to-end test: install both `.so` files, launch gnome-control-center under `dbus-run-session`, screenshot-diff the VPN tab.
2. `nmcli` round-trip tests against the full 49-file fixture corpus (port the remaining `.ovpn` fixtures from `fork/openvpn3-skeleton:properties/tests/conf/`).
3. Settings migration from the upstream C plugin (`vpn-type=openvpn`) to this one (`vpn-type=openvpn3`) — single-shot helper script driven off existing `~/.config/NetworkManager` entries.

## Risks / open questions

1. **libnm ABI stability.**  `NMVpnEditorPlugin`'s interface signature hasn't changed since 1.30, but the GObject vtable layout is implicit in the libnm header.  A header revision could silently shift offsets; we mitigate by using `gobject-sys`'s `g_type_register_static_simple` plus interface registration (the C type system handles the layout) rather than hand-coding offsets.
2. **gtk4-rs minimum versions.**  libadwaita 1.6 needs gtk4 ≥ 4.14; older distros (RHEL 9, Debian stable < 13) ship 4.10.  Round 3 will pin to the lowest libadwaita that compiles against gtk4 4.10 and document the gap.
3. **`gir`-generated libnm binding.**  Long term we want a maintained `nm-rs` crate; hand-rolled FFI is fine for the small interface surface we touch but does not scale to the full libnm API.  A round-5 task is to upstream the binding to the gtk-rs umbrella.
