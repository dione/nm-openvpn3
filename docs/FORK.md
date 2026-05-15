# nm-openvpn3 fork notes

This repository is a fork of GNOME/NetworkManager-openvpn (1.12.5,
upstream commit 9514bde) adapted to act as a NetworkManager VPN
plugin for the OpenVPN 3 Linux D-Bus stack (net.openvpn.v3.*).

## Differences from upstream

- Plugin D-Bus name: `org.freedesktop.NetworkManager.openvpn3`
- Binaries: `nm-openvpn3-service`, `nm-openvpn3-auth-dialog`,
  `libnm-vpn-plugin-openvpn3.so`, `libnm-openvpn3-properties.so`
- System user: `nm-openvpn3` (chroot under `/var/lib/openvpn3/chroot`)
- Connect path: proxies to `net.openvpn.v3.sessions` via D-Bus
  instead of fork+exec'ing the `openvpn` v2 binary

## Maintaining against upstream

`upstream` remote tracks `gitlab.gnome.org/GNOME/NetworkManager-openvpn`.
To pull future upstream fixes:

    git fetch upstream
    git merge upstream/master   # or rebase; expect conflicts in rename hot spots

Renames live in `git log --diff-filter=R` and are easy to follow because
the openvpn3 prefix is applied uniformly.

## Roadmap

- Plan 0 (done, v0.1.0-skeleton) — fork skeleton, Connect stubbed
- Plan 1 (done, v0.2.0-mvp) — TLS-cert Connect/Disconnect happy path via net.openvpn.v3.*
- Plan 1b (done, v0.3.0) — DNS + search domains via netcfg device
- Plan 1c (done, v0.3.1) — VPN routes forwarded to NM for display
- Plan 1d/1e (done, v0.3.2/v0.3.3) — D-Bus retry, session ACL, split-tunnel, watchdog
- Plan 3 (done, v0.4.0) — UI plugin appears in nm-connection-editor (libdir multiarch + GObject type rename)
- Plan 3b (done, v0.4.1) — UI plugin: hide openvpn2-only advanced-dialog widgets (LZO compress, legacy keysize, cipher-fallback / no-cipher-nego, ns-cert-type, TLS cipher string, push-peer-info)
- Plan 3c (done, v0.4.2) — UI plugin: excise openvpn2-only widget code paths + .ui defs (read/write paths in advanced_dialog_new(), 13 widget defs from nm-openvpn3-dialog.ui, dead helpers); vpn.data keys + service args + import-export round-trip retained for raw .ovpn compat
- Plan 3d (done, v0.5.0) — UI plugin: OVPN profile file chooser on main VPN tab (entry + Browse… → GtkFileChooserNative) wired to vpn.data nm-openvpn3-profile, which build_profile_string() passes verbatim to net.openvpn.v3.configuration.Import; validator relaxes gateway/CA/auth requirements when profile path is set
- Plan 3e (done, v0.5.1) — UI plugin: five SetOverride toggles in Misc tab (route-nopull, force-default-gateway, block-ipv6, dns-setup-disabled, dco); editor stores them as override-* vpn.data keys; service dispatches each via net.openvpn.v3.configuration.SetOverride after Import. New ovpn3_config_set_override_bool() in ovpn3-client
- Plan 3f (done, v0.5.2) — service hygiene: rip ~2.2k lines of dead openvpn2 fork+exec path from src/nm-openvpn3-service.c (start_openvpn_binary, _connect_common, args_* helpers, valid_properties/secrets validator tables, pids_pending_* SIGTERM machinery, management socket auth loop, openvpn binary version detection, chroot helpers, get_connection_permission_user). real_new_secrets reduced to a TODO stub for Plan 2; plugin_state_changed is now a no-op. Build shrank from ~3.1k LOC to ~975 LOC, 4/4 tests still pass.
- Plan 3g (done, v0.5.3) — subscribe net.openvpn.v3.sessions StatusChange signal in real_connect so STARTED → SetIp4Config fires within milliseconds instead of waiting up to one 500 ms poll tick. Polling stays as fallback. emit_started_ip4_config() / status_handle_state() / status_change_signal_cb() extracted from poll_status_cb so both code paths share one idempotent emit (priv->ip4_emitted gate).
- Plan 3h (done, v0.5.4) — code-simplifier pass on Plan 1/3 hot paths in src/nm-openvpn3-service.c.  Twelve helpers extracted: lookup_tun_ipv4, lookup_ext_gateway_be, emit_set_config, add_dns_servers, add_dns_search, add_routes, routes_have_default, poll_fail, apply_config_overrides, grant_access_for_connection, grant_access_run_user_fallback, cleanup_session_state.  real_connect and emit_started_ip4_config now read linearly.  Build clean, 4/4 tests pass, ovpn3-oversee-eu smoke test passes.
- Plan CI (done, v0.5.5) — GitHub Actions workflow (.github/workflows/ci.yml) with two jobs running on fedora:latest: a regular build + `make check`, and a parallel job rebuilding with `-fsanitize=address -fsanitize=undefined` and matching ASAN/UBSAN options.  G_SLICE=always-malloc routes GLib allocations through plain malloc so the leak checker actually sees them.  TODO: 95 pre-existing upstream warnings still block `--enable-more-warnings=error`.
- Plan stats (done, v0.5.6) — periodic openvpn3 session.statistics fetch in the service.  Every 30 s a dedicated stats timer reads bytes_in / bytes_out / packets_in / packets_out and emits a _LOGI line with absolute counters plus per-tick rate (bytes/s); first tick prints no rate so the seeded zeros are not mistaken for instant throughput.  Visible via `journalctl -t nm-openvpn3-service | grep stats`.  New ovpn3_session_get_statistics() in ovpn3-client.
- Plan 2 (code-complete, v0.6.0-alpha, UNTESTED END-TO-END) — auth-dialog around AttentionRequired / UserInputQueue. Service subscribes AttentionRequired, fetches UserInputQueue slots, auto-provides values already known from connection (vpn.data username, persistent vpn.secrets), and forwards the remainder to NM via nm_vpn_service_plugin_secrets_required(). real_new_secrets pushes returned credentials back via UserInputProvide. New ovpn3_session_subscribe_attention / fetch_input_slots / provide_input in ovpn3-client. Slot.name → vpn-key mapping is heuristic (password / cert-pass / challenge-response / http-proxy-*). Smoke test pending: no password-protected openvpn3 server available locally; need ProtonVPN-free or test-server validation before tag bumps to v0.6.0.
