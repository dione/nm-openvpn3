# Plan 2 smoke test — interactive auth (v0.6.0-alpha)

**Status**: code-complete, build clean, 4/4 unit tests pass.
**Untested end-to-end**: no password-protected openvpn3 server available
at the time of authoring. This document is the runbook for validating
the AttentionRequired / UserInputQueue plumbing on the first opportunity
that a real auth-user-pass openvpn3 profile shows up.

## Prerequisites

- A `.ovpn` profile that requires interactive credentials. Easiest source:
  - **ProtonVPN free tier** — register → download Linux OpenVPN config
    (gives a profile with `auth-user-pass` and provider username/password).
  - Or a local OpenVPN 2 server with `auth-user-pass-verify` script that
    accepts any credentials.
  - Or any corporate VPN that pushes a static challenge / OTP.
- nm-openvpn3 installed at v0.6.0-alpha or newer (`sudo make install`).
- openvpn3-linux daemons running.
- `journalctl` access for inspecting traces.

## Scenarios

### 1. Plain username + password (no challenge)

Expected flow:

1. **Setup**: create a connection in nm-connection-editor:
   - VPN type: OpenVPN 3
   - Brama: `<gateway>`
   - OVPN profile file: path to the auth-user-pass `.ovpn`
   - Save without typing a password.
2. **Activate**: click the NM tray applet → connect.
3. **Expected NM behaviour**: an inline password prompt appears (the
   built-in NM auth dialog) asking for the VPN password. NM may
   pre-fill `username` from `vpn.user-name` if set; otherwise it
   prompts for both.
4. **Submit**: type the password.
5. **Expected outcome**: tunnel comes up, `tun0` appears, status flips
   to Activated.

Log signature (the lines you should see in journalctl, in order):

    AttentionRequired subscribed sub_id=N
    StatusChange subscribed sub_id=N
    AccessGrant uid=1000 (...) ok
    AttentionRequired: type=N group=M msg='<...>'
    auto-ProvideInput(username) ok       # if username pre-filled
    new_secrets: provided 1 slots         # after NM dialog
    ProvideInput(password) ok
    status: maj=2 min=7 ... -> nm_state=2 # CONNECTED
    STARTED branch: device_name='tun0'

Inspect with:

    journalctl --since '1 min ago' --no-pager _COMM=nm-openvpn3-ser \
      | grep -E 'AttentionRequired|ProvideInput|new_secrets|STARTED'

### 2. Static challenge / OTP

Some servers push a one-time challenge after the password. Expected:

1. Repeat scenario 1 — password gets accepted.
2. openvpn3 emits a second `AttentionRequired` with the challenge text.
3. NM pops a **second** inline dialog with the challenge label as the
   prompt.
4. User types the OTP / response → tunnel comes up.

Log signature additions:

    AttentionRequired: type=N group=M msg='<challenge text>'
    new_secrets: provided 1 slots
    ProvideInput(static_challenge) ok    # or dynamic_challenge

### 3. Cert + key passphrase

When the profile bundles an encrypted `<key>` block, openvpn3 may ask
for the passphrase via the same UserInputQueue:

    AttentionRequired: type=N group=M msg='Enter private key passphrase'
    ProvideInput(private_key_passphrase) ok

## What to check if the flow fails

### Symptom: NM hangs at "Activating connection…" with no password prompt

- Confirm `AttentionRequired subscribed sub_id=N` appears in logs. If not,
  the signal subscription is dropping — investigate
  `src/ovpn3-client.c:attention_signal_cb` and the existing StatusChange
  signal warning about openvpn3 unicast routing.
- Confirm `nm_vpn_service_plugin_secrets_required()` actually runs (add a
  trace before the call if needed).
- Confirm `check_need_secrets()` returns `need_secrets=TRUE` for this
  contype — NM only proxies the dialog if it knows secrets are required.

### Symptom: password prompt appears but typing it fails the connection

- Capture the actual slot name in `AttentionRequired: ... msg='...'` and
  the surrounding `ProvideInput(<name>)` line. The heuristic in
  `slot_name_to_vpn_key()` may not map that name to the correct
  `NM_OPENVPN3_KEY_*` constant — patch the mapping.
- Inspect `new_secrets: slot 'X' has no value in vpn.secrets[Y]` traces:
  they pinpoint slots NM did not collect because the hint did not match
  an NM-known key.

### Symptom: maj=2 min=4 (AUTH_FAILED)

- Real auth failure (wrong password). Not a plugin bug.
- `status_handle_state()` should translate this to a NM failure with
  `NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED` — currently it maps everything
  unknown to `CONNECT_FAILED`. Worth extending `ovpn3_status_to_nm_state`
  once a real AUTH_FAILED status is observed.

## Files involved

- `src/ovpn3-client.{h,c}`
  - `ovpn3_session_subscribe_attention`
  - `ovpn3_session_fetch_input_slots`
  - `ovpn3_session_provide_input`
  - `Ovpn3InputSlot`
- `src/nm-openvpn3-service.c`
  - `attention_required_cb`
  - `auto_provide_known_slots`
  - `slot_name_to_vpn_key`
  - `clear_pending_slots`
  - `real_new_secrets` (Plan 2 implementation)
  - `priv->{attention_sub_id, pending_slots, current_connection}`

## When validated

1. Update `docs/FORK.md` to drop the "UNTESTED END-TO-END" note.
2. Tag `v0.6.0` (drop the `-alpha`).
3. Delete this file — it has served its purpose.
