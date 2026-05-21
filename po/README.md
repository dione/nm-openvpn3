# Translations

The editor cdylib (`libnm-vpn-plugin-openvpn3-editor.so`) binds the
gettext text domain **`nm-openvpn3`** against `/usr/share/locale`.
Every user-visible string in `nm-openvpn3-editor/src/editor.rs`
flows through a `tr()` helper that wraps `gettext()`; missing
catalogs mean the original English string is shown.

## Shipped languages

| Status | Count | Notes |
|--------|-------|-------|
| Complete | 1 (`pl`) | hand-maintained against the POT |
| Partial  | 59 | imported from upstream NetworkManager-openvpn via `msgmerge --no-fuzzy-matching` — only the ~10 msgids that match the HIG-rewritten Rust strings exactly survived |

The upstream C plugin (OpenVPN 2 era) shipped translations for 60+
locales, but the option set, phrasing, and HIG-driven re-titling all
changed in the Rust rewrite, so only ~10 simple labels (`General`,
`Password`, `Default`, `None`, `HTTP`, `SOCKS`, `Asymmetric`,
`Security`, `Misc`, `Connect timeout`) survive verbatim across the
two trees.  Fuzzy matches were dropped — at runtime gettext skips
fuzzies anyway, so keeping them would double the .po size for no
behavioural change.

Run `scripts/import-upstream-translations.sh` to refresh the merge
after editing the POT.

## Adding a language

```sh
# Generate a fresh .po from the template (replace `de` with your lang).
msginit -i po/nm-openvpn3.pot -l de_DE.UTF-8 -o po/de.po

# Translate the msgstr fields in po/de.po by hand.

# Sanity-check.
msgfmt -c -v po/de.po -o /dev/null

# Append your language code to po/LINGUAS, alphabetically.

# Install + smoke-test.
LANG=de_DE.UTF-8 gnome-control-center network
```

`install-test.sh` compiles every `po/*.po` it finds — no extra
plumbing needed.

## Updating an existing translation

When `editor.rs` gains new strings, re-extract the template (manual
for now — Rust strings the simple `gettextrs` API uses do not show up
in `xgettext` cleanly without the `--keyword=tr` and `--add-comments`
hints; the POT here is hand-maintained alongside `editor.rs`).
Merge into each catalog with:

```sh
msgmerge --update --backup=none po/<lang>.po po/nm-openvpn3.pot
```

`msgfmt -c -v` catches malformed merges before install.

## Why not auto-translate?

OpenVPN terminology (`tls-crypt-v2`, `data-ciphers-fallback`,
`override-route-nopull`) is full of false friends.  A
machine-translated catalog routinely ships things like "block IPv6"
as "block sixth IP" or "ping restart" as "restart pinging" — both
have shown up in past automated translations of NM plugins.  Native
speakers vetting against the POT template produces saner results.
