# nm-openvpn3 audit — pass 5 (2026-06-17)

Baseline at audit time: `cargo clippy --workspace --all-targets` ✅ (zero warnings),
`cargo test --workspace` ✅ (62 tests), `cargo audit` ✅ (0 advisories across 199 deps).
Version `0.6.0-alpha.8`, branch `rust/main`.

Method: parallel per-crate full read (7 finders, one per crate/concern → security /
correctness / FFI / concurrency lenses), then independent re-verification of every
security-relevant finding against the actual data flow before assigning severity. Findings
de-duped against `docs/AUDIT-2026-06.md` (passes 1–4). Several finder over-claims were
downgraded after tracing reachability — flagged explicitly below.

Privilege model unchanged: **service runs as root**; auth-dialog + editor/properties
cdylibs run as the user. Baseline is high quality and already hardened across four prior
passes. This pass found no memory-safety or currently-reachable injection holes; the real
findings are a defense-in-depth bypass in the root service's route allow-list, two
import-time correctness drifts, one un-guarded FFI callback, and two service-lifecycle
gaps.

Legend: ☑ = fixed in this pass · ☐ = recommended, not yet applied.

## Applied in this pass

Fixed with regression tests, full suite + clippy green, code `cargo fmt`-clean against
current stable (`rustfmt 1.9.0`):

- **R1 ☑** — `is_safe_route_line` now rejects any control char (closes the bare-`\r`
  allow-list bypass). Tests: `safe_route_line_allowlist` (CR/TAB cases) +
  `extra_routes_reject_cr_smuggled_directive`.
- **R2 ☑** — proto match now keys off the `udp` prefix. Test:
  `parse_proto_udp_variants_do_not_set_tcp`.
- **R3 ☑** — standalone `key-direction N` projected to `ta-dir` (tls-auth) / `static-key-direction`
  (secret), inline 2nd-arg keeping precedence. Test: `parse_standalone_key_direction_reaches_vpn_data`.
- **R4 ☑** — the `collect` C callback body is now wrapped in `ffi_guard`.
- **R5 ☑** — added per-session `failure_emitted` + `emit_failure_once`; every listener/poller
  Failure path is now CAS-gated, so NM gets one Failure per event.
- **R6 ☑ (partial)** — the stats timer now self-exits when `failure_emitted` is set (no more
  infinite poll of a dead session). The remaining half — clearing `session_path` / aborting
  siblings from inside a failed background task — is **deferred** (D-Bus session leak is bounded
  by NM's failure→Disconnect contract; a from-task teardown needs a supervisor channel and
  carries deadlock/cancellation risk not worth taking unscheduled).
- **R7 ☑ (subtitle only)** — corrected the factually-wrong `reneg-seconds` subtitle. The
  "disable rekeying (`reneg-sec 0`)" control is **deferred to features** — making the spin's 0
  literal would silently disable rekeying on every existing connection on Apply (a B2-class
  regression); a correct fix needs a separate switch.
- **D1 ☑** — `emit()` now routes the option `name` through `push_escaped` (a no-op for real
  directive keywords, neutralises a whitespace/newline-bearing name), closing the latent
  injection path at its only sink. Guard is emit-side, **not** parse-side, so import stays as
  permissive as openvpn itself (a parse-side reject would fail the whole import for an
  exotic-but-valid name that previously worked via the verbatim profile pin). Misleading
  `as_nm_data` round-trip comment corrected. Test: `emit_neutralises_injected_option_name`.
- **Simplifications ☑** — removed dead `data_mode` (auth-dialog) and dead `have_client`
  (import_export).
- **R8 / D2–D7** — left as analysed above (R8 defers to the prior refutation; D2–D7 are LOW).

Not applied (pre-existing, out of scope): a `cargo fmt --check` run against current stable
flags lines in `editor.rs` and `bridge.rs` that this pass never touched — the tree was last
formatted with an older stable. Reformatting them would churn unrelated code; flag for a
separate housekeeping commit.

---

## Verified-reachable findings

### MEDIUM

**R1 ☐ `is_safe_route_line` allow-list bypassed by a bare `\r` (root service)**
`nm-openvpn3-service/src/build_profile.rs:320-332, 437-464`. Extra-route lines come from
`KEY_EXTRA_ROUTES` (attacker-settable over D-Bus, per the code's own SECURITY comment) and
are emitted verbatim via `raw_line`. The validator `is_safe_route_line` tokenises with
`split_whitespace()` — which treats a bare `\r` as a separator — but the lines are produced
by `routes.lines()`, which splits only on `\n`/`\r\n`, **not** a lone interior `\r`. So
`"route 1.2.3.0/24\rscript-security 3"` (no `\n`) is one line to `lines()`, tokenises to
four benign tokens to the validator (`route`, an address, then `script-security`, `3` — all
pass the `[A-Za-z0-9.:/_-]` class, which freely admits alphabetic keyword tokens), and is
emitted raw with the `\r` intact. If openvpn3's Import parser treats a bare `\r` as a line
terminator, this smuggles exactly the `script-security` / `up` script hooks the allow-list
exists to block — **HIGH if it does, MED otherwise**. The `push_escaped` paths are immune
(a newline takes the double-quote branch → literal `\n`, or fails closed as an unterminated
quote). Verified: mechanism and reachability both confirmed from the code.
Fix: in `is_safe_route_line`, reject any line containing a control char, or require
`line.split_whitespace().collect::<Vec<_>>().join(" ") == line`.

**R2 ☐ UDP proto variants flipped to TCP on import**
`nm-openvpn3-properties/src/import_export.rs:642-647`. `as_nm_data` sets `proto-tcp=yes`
for every proto except the literal `udp` / `udp4` / `udp6`, but `validate` (203-208) accepts
`udp-client`, `udp-server`, `udp4-client`, `udp6-client`. Those four fall through and are
written as TCP — a UDP profile silently becomes TCP on import. Verified.
Fix: `Some(p) if !p.starts_with("udp")` for the no-op arm.

**R3 ☐ Standalone `key-direction` dropped on import**
`nm-openvpn3-properties/src/import_export.rs:158 / as_nm_data`. A standalone
`key-direction N` directive is validated but never projected into vpn.data (only the
`secret`/`tls-auth` second-arg paths map to `static-key-direction`/`ta-dir`). The "survives
via the Directive vector" escape hatch is not wired (see D1), so the value is lost.
Fix: add a `"key-direction"` arm mirroring the C `do_import`.

**R4 ☐ `collect` C callback lacks a panic guard (FFI UB)**
`nm-openvpn3-properties/src/bridge.rs:432`. `collect` is passed to libnm's
`nm_setting_vpn_foreach_data_item` (442) and runs on a C stack frame. A panic in its body
(`to_string` / `BTreeMap::insert`) unwinds across the C frame **before** the outer
`ffi_guard` in `iface_export_to_file` can catch it → UB. The other two C callbacks
(`class_init`, `get_property`) are guarded; this one was missed. Live panic surface is
small (alloc-OOM aborts rather than unwinds), hence MED not CRITICAL.
Fix: wrap the body in `ffi_guard((), || …)`.

**R5 ☐ Duplicate `Failure` emitted on backend failure**
`nm-openvpn3-service/src/plugin.rs:261-271, 823-835`. `ip4_emitted` gates only the
Started/Ip4Config path. On a real (non-user) backend failure, the StatusChange listener
emits `Failure` and the poller's next `status()` read emits `Failure` again — NM gets two
for one event. Fix: add a per-session `failure_emitted: Arc<AtomicBool>`, CAS-gated like
`ip4_emitted`, checked in both Stopped arms.

**R6 ☐ Self-initiated failure paths don't centralise teardown**
`nm-openvpn3-service/src/plugin.rs:253-257, 261-271, 730-736, 806-834, 854-863`. The
poller/listener failure paths `break` out of their task but never clear
`session_path`/`config_path` or abort sibling tasks. The stats timer (no break-on-error)
then loops forever, the other listener stays attached, and `session_path` stays `Some` —
cleanup depends entirely on NM later calling `Disconnect`. If NM delays/drops it, the next
`Connect` is refused ("session already active") against a dead backend and tasks leak.
Fix: route these paths through a shared teardown (signal `quit_tx` / a `cleanup_session`)
rather than a bare `break`.

**R7 ☐ `reneg-seconds 0` (disable rekeying) cannot be expressed**
`nm-openvpn3-editor/src/editor.rs:1259-1265`. The SpinRow uses `int_or_empty`, mapping 0 →
remove-key, and the service skips `reneg-sec` when unset. But in OpenVPN `reneg-sec 0`
*disables* renegotiation — a distinct, meaningful value the UI cannot set. The subtitle
"0 leaves the default (3600)" is also wrong.
Fix: special-case 0 as an explicit write (or add a "disable rekeying" switch); fix subtitle.

### REVISIT (collides with a prior refutation — do not treat as a fresh bug)

**R8 `session_fetch_input_slots` Check/Fetch swallow vs get_type_group fail-fast**
`ovpn3-client/src/lib.rs:355-376`. `user_input_queue_get_type_group` is deliberately
fail-fast (a swallow makes NM hang); `Check`/`Fetch` errors are logged-and-skipped. A
transient bus error on a *required* slot could drop a prompt and reproduce the same NM-hang.
**However**, `docs/AUDIT-2026-06.md` explicitly refuted the fail-fast fix here as
net-negative ("any transient bus hiccup would abort the whole connection") because the path
self-heals across repeated `AttentionRequired` firings. The prior reasoning stands; revisit
only with a real reproduction. No change recommended.

---

## Defense-in-depth / latent (not currently reachable)

**D1 `emit()` writes option names unescaped — latent injection + misleading comment**
`nm-openvpn3-properties/src/import_export.rs:251`. `emit()` pushes the option `name` raw
while args go through `push_escaped`. `parse` accepts arbitrary names (a double-quoted first
token may carry spaces or a literal `\n`, e.g. `"a\nup x" c` → `name="a\nup x"`), so a
direct `parsed_config.emit()` would inject a second physical line (`up x c` — a script
hook). **Not reachable today**: the only non-test `emit()` caller is
`OvpnConfig::from_nm_data(&data).emit()` (bridge.rs:481); `from_nm_data` builds every
directive with hard-coded literal names (attacker data only ever becomes *args*), and
`as_nm_data` drops unknown names. The comment at 610-613 — "[unknown options] survive via
the Directive vector and are emitted unchanged on a Save-As" — describes a path that **is
not wired** (no caller emits the parsed Directive vector). LOW today, but a future Save-As
implementing that comment would make it live.
Fix: validate the option-name charset at parse (`^[A-Za-z0-9_.-]+$` plus the `<…>` blob
form) and reject otherwise — cheap, closes the latent path, and corrects the round-trip
contract. Fix/clarify the misleading comment.

**D2 auth-dialog secret zeroize over-claims coverage**
`nm-openvpn3-auth-dialog/src/main.rs:202-209`. `reader.lines()` reads `SECRET_VAL=…` bytes
through `StdinLock`'s 8 KiB BufReader, which is never zeroized; `read_line` also reallocs
the `String`, leaving intermediate plaintext the per-line `Zeroizing` (207) can't reach. The
comment claims it "scrubs the bytes from process memory" — stronger than reality. Severity
is bounded LOW–MED: these are NM's already-cached creds, never used and never emitted.
Fix: read into a pre-sized `Zeroizing<Vec<u8>>` via `read_until(b'\n', …)`, avoiding `String`
realloc and the un-scrubbable BufReader buffer. (Kernel/libc stdin buffering residue is
inherent — the goal is bounding, not zero.)

**D3 `profile` String not zeroized (may hold inline PEM)**
`nm-openvpn3-service/src/plugin.rs:414-439`. The assembled/read connect `profile` can embed
inline `<key>`/`<tls-crypt>` material but is a plain `String` dropped without scrubbing
(unlike `current_secrets`, correctly `Zeroizing`). LOW — openvpn3 persists the imported
config server-side regardless. Fix: wrap in `Zeroizing<String>`.

**D4 `UnknownMethod` classification couples to daemon message text**
`ovpn3-client/src/retry.rs:94`. Cold-start retry of `UnknownMethod` keys off the literal
substring `"Object does not exist at path"`. If upstream openvpn3 reworms that wording
(localization, version drift), the variant silently becomes permanent and the first
`nmcli connection up` after cold boot fails. LOW; document the coupling, add an integration
test against a real daemon if feasible.

**D5 `flatten_str_map` is all-or-nothing**
`nm-openvpn3-service/src/secrets.rs:99-101`. `HashMap<String,String>::try_from(v)` fails the
whole conversion if any single vpn.data value is non-string, silently yielding an empty map
(then a confusing "missing remote" build error). Real NM only sends string dicts, so LOW.
Fix: iterate entries, skipping/logging per-key.

**D6 IPv6 `connected_to` last-colon misparse** — `ovpn3-client/src/lib.rs:279-289`. LOW,
cosmetic field. **D7 `tls-version-min-or-highest` dropped when min=Default** —
`nm-openvpn3-editor/src/editor.rs:1365-1373`; the flag is a modifier the service only honours
when min is set. LOW; gate the switch on a non-empty min selection.

---

## Simplifications (behaviour-preserving)

- `nm-openvpn3-auth-dialog/src/main.rs:200,215,240` — `data_mode` is dead (sole consumer is
  an empty `else if !data_mode {}`); the `current_key` state machine already enforces the
  data/secret boundary. Remove both.
- `nm-openvpn3-editor/src/editor.rs:1712-1795` — `wire_changed_signals` repeats the
  `clone alive → connect_* → emit_changed` pattern across four loops + three password rows
  (~50 lines); collapse via a `macro_rules!` or a connect-fn helper.
- `nm-openvpn3-properties/src/import_export.rs:1028` — `have_client` computed then
  `let _ = have_client;` (dead); `:217` — `strip_suffix(" or-highest")` never fires
  (tokeniser already split it). Drop both.
- Still open from pass 1–4: S5 — `insert_opt` free fn for the ~20 `if let Some(v)=… { insert }`
  arms in import_export.

---

## Test gaps (highest-leverage first)

1. **Cross-emitter agreement test** (recommended in pass 1–4, validated by R2/R3/D1 and the
   prior B1/B6): assert `build_profile` and `from_nm_data` emit equivalent directives for the
   same vpn.data. This whole finding class is emitter disagreement.
2. `is_safe_route_line("route 1.2.3.0/24\rscript-security 3")` ⇒ false (catches R1).
3. `push_escaped` on a value containing `\n` ⇒ single line, literal `\n` (escaper is untested
   except indirectly via the route gate).
4. `proto udp-client` import ⇒ `proto-tcp` absent (R2); standalone `key-direction 1` ⇒ reaches
   vpn.data (R3).
5. `emit()` round-trip identity for a quoted/newline first token (D1).
6. retry: `SpawnChildExited` ⇒ transient; a non-FDO `zbus::Error` ⇒ permanent (both are
   load-bearing classification claims, currently unverified by tests).
7. editor: `ContypeFlags::from_id` (the single source of truth for save-gating) and
   `parse_int_default` — pure, display-free, untested.
8. auth-dialog: `secret_required_flag` on a non-numeric flag string (fail-safe-to-required,
   untested); `is_encrypted_keyfile_path` case-insensitive extension.
9. `connection_to_nm_data` / the `collect` callback (R4) — needs libnm linkage; gate in CI.

---

## Improvements / hardening

- **CI: add `cargo audit` (and/or `cargo deny`) gate.** Clean today, but ungated — a future
  advisory lands silently. Also: build the Debian package in CI (the deb path drops
  Cargo.lock + skips tests, so it is never exercised) and run the ignored editor FFI smoke
  test under `xvfb`.
- **Fuzz the `.ovpn` parser** + round-trip property tests (the quoted-first-token class that
  hid D1 is exactly what fuzzing surfaces).
- **Reject control chars on every `raw_line` path**, not just routes (general fix for R1's
  class).

## Features (carry-over from pass 1–4, still open — need product buy-in)

IPv6 config to NM (`SetIp6Config`, biggest gap vs the C plugin); static-routes / split-tunnel
editor UI; per-secret storage-mode selector (Saved / Always-ask / Not-required — unlocks the
flags the dialog already reads); wire HTTP/SOCKS proxy auth through to activation; surface the
server login banner (signal declared, never emitted); OpenVPN static-challenge (2FA at
connect); PKCS#11 / smartcard certs; "preview generated config" in the editor.
