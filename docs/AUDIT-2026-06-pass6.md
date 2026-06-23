# nm-openvpn3 audit — pass 6 (2026-06-23)

Baseline at audit time: `cargo test --workspace` ✅ (140 tests, 1 ignored editor FFI
smoke), `cargo clippy --all-targets --release --locked -- -D warnings` ✅ (zero warnings),
`cargo audit` ✅ (0 advisories across 199 deps). Version `0.6.0-alpha.9`, branch `rust/main`.

Method: dependency refresh + a fan-out bug hunt (10 finders across the five crates ×
security / correctness / concurrency / FFI / resource lenses → triage/dedup against the
documented passes 1–5 → adversarial verification of every candidate against the actual
data flow, default-rejecting on uncertainty → synthesis). Finders were primed with the
prior passes' *refutation and deferral rationale*, not just the fixed-bug list, so settled
items were not re-litigated. Result on 5×-hardened code: **0 CRITICAL / 0 HIGH**, 4 MEDIUM,
2 LOW confirmed; 1 candidate correctly downgraded to uncertain; 1 a duplicate.

Privilege model unchanged: **service runs as root**; auth-dialog + editor/properties
cdylibs run as the user. No memory-safety or reachable injection holes found this pass.
The real signal is structural (see *Structural note* below): the connect-side `.ovpn`
emitter (`build_profile.rs`, root) and the export-side emitter (`import_export.rs`, user)
have independently drifted — three of the six findings are symptoms of that one root cause.

Legend: ☑ = fixed in this pass · ☐ = recommended/deferred, not applied.

---

## Applied in this pass

Fixed with tests; full suite (now **150 tests**) + clippy green; new code `cargo fmt`-clean
against current stable (`rustfmt 1.9.0`).

**M1 ☑ AttentionRequired listener emitted `Failure` ungated** — MEDIUM, correctness/concurrency.
`nm-openvpn3-service/src/plugin.rs`. `spawn_attention_listener` was the only background task
that received neither `disconnect_requested` nor `failure_emitted`; its error arm called
`emitter.failure(LoginFailed)` directly, bypassing the R5 dedup CAS (`emit_failure_once`) and
the disconnect guard. Three real consequences: (1) a likely double-`Failure` for one logical
event (the one emit path R5 left uncovered — listener/poller race it to NM); (2) the
R6-partial stats-timer self-exit (keyed on `failure_emitted`) never fired on this path, so the
stats timer kept polling a dead session until NM's Disconnect; (3) a narrow
spurious-`Failure`-on-Disconnect race (an in-flight `ProvideInput` failing against a
torn-down session). Fix: thread both `Arc<AtomicBool>` guards into the listener (both clones
already in scope at the spawn site); in the error arm skip the emit when `disconnect_requested`,
else route through `emit_failure_once`. Behaviour-preserving — the genuine first failure still
emits `LoginFailed`; only the dedup + deliberate-teardown skip change.

**M2 ☑ SpinRow clamp-on-load → clamp-on-save silently tightened stored timer values** — MEDIUM, data-loss.
`nm-openvpn3-editor/src/editor.rs`. `reneg-seconds` (cap 86400), `ping`/`ping-restart`/
`connect-timeout` (cap 3600) had SpinRow ceilings below valid openvpn values. A stored
value above the cap (set via nmcli or `.ovpn` import — the load path is unclamped) was
clamped on load, then unconditionally re-persisted from widget state on *any* Apply (these
keys are in `WIDGET_DATA_KEYS`, so the round-trip preserve-loop skips them). A 1-week
`reneg-sec=604800` silently became 1 day with no edit and no warning. Fix (variant A,
behaviour-preserving): widen the four ceilings to `TIMER_SECS_MAX = i32::MAX` (≈68 years of
seconds — past any real config, within openvpn's int parse range); only values *above* the
old cap (already corrupted) change. Distinct from the genuinely protocol-bounded spins
(port/MTU/fragment/keysize ≤ 65535, log-level ≤ 6), which keep their real ceilings. The
riskier "remember-raw + dirty-flag replay" variant B was rejected as an R7-class regression.

**L4 ☑ TLS-context directives gated on connect but unconditional on export** — LOW, correctness.
`nm-openvpn3-properties/src/import_export.rs`. `from_nm_data` emitted `remote-cert-tls` /
`ns-cert-type` / `tls-remote` / `tls-version-max` / `extra-certs` (from `pairs_str`) and
`crl-verify` unconditionally, while the connect emitter gates them on `is_tls_like`. After a
TLS→static-key switch left stale keys in vpn.data, an exported `.ovpn` for the static-key
connection carried TLS directives the live connection omits (some make openvpn reject the
file on re-import). Fix: moved those keys + `crl-verify` into the `is_tls_like` block so the
export emitter mirrors `build_profile`. Export-side only (transient file text, no stored
state) — not R7-class.

**L5 ☑ extra-routes safety allow-list enforced on connect but absent on export** — LOW, correctness/defense-in-depth.
`nm-openvpn3-properties/src/import_export.rs`. The connect emitter runs `is_safe_route_line`
(allow-list: `route`/`route-ipv6`/`route-gateway`/`route-metric`/`route-delay`, address-only
args, control chars rejected) and drops anything else; the export emitter re-emitted every
preserved-route line verbatim, so a smuggled `route-up /tmp/x.sh` survived on export but not at
connect. Export runs as the user and the root-side guard remains the privilege boundary, so
this is a consistency/defense-in-depth gap, not an escalation. Fix: applied a local copy of the
`is_safe_route_line` predicate in `from_nm_data`. The two copies' parity is enforced by the new
cross-emitter agreement test (unsafe-route case); the canonical predicate lives in
`build_profile.rs` — a shared crate would be the drift-proof home (see Structural note).

**M6 ☑ `single_use` config orphaned when NewTunnel fails** — MEDIUM, resource leak.
`nm-openvpn3-service/src/plugin.rs` + `ovpn3-client/src/lib.rs`. `do_connect` imports the
config (`single_use=true`) before `new_tunnel`; on a NewTunnel failure `?` returned with the
config never stashed and never removed, and the client exposed no config `Remove`. openvpn3
auto-GCs a `single_use` config only once a backend *Fetches* it during registration; a failed
NewTunnel spawns no backend, so the config orphans in `openvpn3 configs-list` (one per NM
retry). Distinct from the deferred R6 session leak — R6's bound is NM's failure→Disconnect
contract, which only ever calls `session.Disconnect` and never touches the config object. Fix:
added `Client::config_remove` (wraps `net.openvpn.v3.configuration.Remove`, owner-callable) and a
best-effort `Plugin::remove_config`; removed the config on the NewTunnel-failure path, in
`cleanup_session`, and in `disconnect`. Idempotent and safe regardless of the openvpn3 GC
behaviour: an already-GC'd config returns a benign error logged at debug. Safe on the
lost-reply edge too (NewTunnel ran server-side but the reply was lost): the activation is
failing regardless, so dropping the config cannot corrupt a connection being kept. *Premise
note:* the "openvpn3 never GCs an unfetched single_use config" reading was not validated
against a live daemon, but because the remove is best-effort/idempotent the fix is harmless
either way.

**D3 ☑ connect `profile` String not zeroized** — LOW (carry-over), hardening.
`nm-openvpn3-service/src/plugin.rs`. The assembled connect profile can embed inline
`<key>`/`<tls-crypt>` PEM (built path) or whatever the pinned `.ovpn` holds (file path), but
was a plain `String`. Wrapped in `Zeroizing` so plaintext key material is scrubbed on drop,
matching `current_secrets`.

**D5 ☑ `flatten_str_map` all-or-nothing** — LOW (carry-over), robustness/consistency.
`nm-openvpn3-service/src/secrets.rs`. `split_vpn` parsed vpn.data/secrets with a bare
`HashMap::<String,String>::try_from` that fails the whole map on a non-`a{ss}` shape, while
`connection::string_string_dict` (the other vpn.data parser, used in the same `do_connect`)
has an `a{sv}` per-key fallback. So an older-NM `a{sv}` dict left `data_map` empty (→ confusing
"missing remote") even though `vpn_data` parsed it fine. Made `flatten_str_map` mirror the
robust per-key fallback. The well-tested `a{ss}` fast path (the only shape real NM sends) is
unchanged.

---

## Deferred (need design buy-in / external validation)

**M3 ☐ PKCS#12 collapse predicate diverges between connect and export emitters** — MEDIUM.
`build_profile.rs` collapses on `cert==key && is_pkcs12_path` (emitting only `pkcs12 <path>`,
dropping a differing `ca`); `import_export.rs` requires `ca==cert==key`. For a hand-built
config with `cert==key==.p12` and a *separate* `ca`, the live connection presents the bundle's
embedded CA while an export declares the separate CA + split cert/key — different trust
material. Narrow trigger (every import-derived profile sets `ca==cert==key`, so only
hand-edited configs diverge), security-adjacent (silent CA substitution). **Not fixed:** the
obvious convergence (adopt `ca==cert==key` in `build_profile`) is an R7-class regression — it
drops the divergent config into the split-cert/key-against-binary-`.p12` branch that openvpn3
*refuses to parse*, breaking a currently-working connection. The safe direction (keep
`cert==key` collapse and additionally emit `ca` when `ca != cert`) assumes openvpn3 accepts a
`pkcs12` line alongside a separate `ca` line — unverified here. Validate against a live
openvpn3 before shipping; the cross-emitter agreement corpus deliberately avoids this edge.

**Uncertain ☐ non-numeric numeric-field values dropped on connect, emitted raw on export.**
`import_export.rs`. Real code asymmetry (connect's `line_int` drops non-numeric; export's
`pairs_str` emits verbatim), but the stated mechanism is unreachable: both connect and export
take the verbatim pinned-profile branch for any imported connection, so the divergence only
fires for a no-pin connection carrying an out-of-band hand-edited non-numeric value — and
`validate()` already range-checks `port`/`proxy-port` at import. Cosmetic at most. Not
scheduled; if ever fixed, scope the numeric guard to the integer subset of `pairs_str` only
(a whole-loop guard would drop open-vocab cipher/auth values — a B2-class regression).

Also re-verified still-correctly-deferred from prior passes: **R6 (full from-task teardown)**
— the supervisor-channel / cancellation risk the deferral named still holds, and M6 shows the
config-leak facet is separable and fixable without it; **R7 (reneg-sec 0 disable gesture)** —
remains a features item (the low-end `0` is the disable directive, orthogonal to M2's
high-end ceiling fix).

---

## Dependencies updated

`cargo update` — 24 within-semver bumps relocked and re-verified (build + 150 tests + clippy
green): zbus/zvariant 5.15→5.16/5.11→5.12, zeroize 1.8→1.9, regex 1.12.3→1.12.4, uuid, bytes,
bitflags, syn, quote, log, memchr, smallvec, wasm-bindgen, getrandom, cc, js-sys. `cargo audit`
remains clean.

Notes: (1) the GUI crates (gtk4 0.10 / libadwaita 0.8 / glib·gio 0.21) are **deliberately left
pinned** — on `rust/main` they are an apt-archive packaging contract (build against Ubuntu
noble's `librust-*-dev`); the newer minors live on `rust/upstream-deps`. (2) zeroize 1.9 raises
its internal MSRV to 1.85 (edition 2024); the CI `stable` toolchain and local 1.96 both satisfy
it, and the bump is API-additive with no secret-scrubbing behaviour change. (3) On the `.deb`
path the lock is dropped and re-resolved against the archive, so these lock bumps satisfy
"update dependencies" / keep CI `--locked` green but do not change what the package ships.

---

## Tests added (10; total 140 → 150)

- **Cross-emitter agreement** (`nm-openvpn3-service/src/cross_emitter_agreement.rs`, 6 tests) —
  the highest-leverage gap, recommended in passes 1–5. A `#[cfg(test)]` module that pulls in the
  properties crate (new dev-dependency) and compares `build_profile_string` (connect) against
  `OvpnConfig::from_nm_data().emit()` (export) for a corpus of vpn.data dicts (tls / password-tls
  / password / static-key-with-stale-TLS / extra-routes). Comparison is structural — each emitted
  profile is re-parsed with `OvpnConfig::parse` and compared as an order-independent directive
  multiset, so cosmetic quoting differences (connect's verbatim route lines vs export's
  re-escaped args) don't matter. These directly regression-guard L4 and L5 and would have caught
  B1/B6/R2/R3.
- **import_export.rs** (4 tests) — L4 TLS-directive gating (static-key drops stale TLS keys; TLS
  keeps them), L5 unsafe-route drop on export, and a local `is_safe_route_line` allow-list test.

---

## Structural note (recommended for pass 7)

M3, L4, and L5 are the same shape: two hand-maintained `.ovpn` emitters in different crates
(`build_profile.rs`, root service; `import_export.rs::from_nm_data`, user cdylib) with no shared
contract, drifting on pkcs12 collapse, TLS-directive gating, and route allow-listing. The
point-fixes close the current gaps and the new agreement test catches future drift, but the
durable fix is a **single shared emit module** (a small no-deps crate both depend on) so the two
paths are one implementation. That retires this entire finding class and is a better use of pass-7
effort than continuing point-fix audits. Honest assessment: on 5×-hardened code the per-finding
yield is thin and bounded; "applied M1+M2+M6+L4+L5+D3+D5, added the agreement test, bumped deps,
found no HIGH/CRITICAL" is the legitimate outcome.

## Housekeeping (carry-over, intentionally untouched)

`cargo fmt --all -- --check` still flags 5 pre-existing sites (`editor.rs:1979/1990`,
`bridge.rs:94/114/265`) from the older-stable formatting noted in pass 5 — in regions this pass
did not touch. Left for a dedicated formatting commit to avoid burying the audit diff (this
pass's new code is fmt-clean).

## Features (carry-over from passes 1–5, still open — need product buy-in)

IPv6 config to NM (`SetIp6Config`, biggest gap vs the C plugin); static-routes / split-tunnel
editor UI; per-secret storage-mode selector (Saved / Always-ask / Not-required — unlocks the
flags the dialog already reads); wire HTTP/SOCKS proxy auth through to activation; surface the
server login banner (signal declared, never emitted); OpenVPN static-challenge (2FA at connect);
`reneg-sec 0` disable-rekeying switch (R7); PKCS#11 / smartcard certs; "preview generated config"
in the editor.
