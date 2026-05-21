#!/usr/bin/env bash
# Re-merge translations from the upstream C tree (fork/openvpn3-skeleton)
# into our Rust POT.  Only exact msgid matches are kept — fuzzy
# guesses get stripped because gettext skips fuzzies at runtime
# anyway, so an unreviewed fuzzy would behave identically to "no
# translation" while doubling the .po file size.
#
# Output: regenerate po/<lang>.po for every catalog the upstream tree
# carried.  Re-run this whenever editor.rs grows new msgids and the
# POT template is updated by hand.

set -euo pipefail
cd "$(dirname "$0")/.."

POT=po/nm-openvpn3.pot
UPSTREAM_BRANCH=fork/openvpn3-skeleton

command -v msgmerge >/dev/null || { echo "msgmerge missing — apt install gettext"; exit 1; }
command -v msgattrib >/dev/null || { echo "msgattrib missing — apt install gettext"; exit 1; }

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# Pull every upstream .po into the scratch directory.
mapfile -t upstream_pos < <(
    git ls-tree -r --name-only "$UPSTREAM_BRANCH" -- po/ | grep '\.po$'
)
if [ "${#upstream_pos[@]}" -eq 0 ]; then
    echo "No upstream .po files found under $UPSTREAM_BRANCH:po/"
    exit 1
fi

# Preserve our hand-translated catalogs (po/pl.po today) by skipping
# them — they are higher quality than anything msgmerge can produce.
declare -A skip
for p in po/*.po; do
    [ -e "$p" ] || continue
    skip[$(basename "$p" .po)]=1
done

merged=0
for src_path in "${upstream_pos[@]}"; do
    name=$(basename "$src_path")
    lang="${name%.po}"
    # Skip ca@valencia and other tagged variants for which we don't
    # have a /usr/share/locale equivalent in most distros.
    case "$lang" in
        *@*) continue;;
    esac
    if [ "${skip[$lang]:-0}" = "1" ]; then
        echo "Skipping $lang.po — hand-maintained catalog already present."
        continue
    fi
    git show "$UPSTREAM_BRANCH:$src_path" > "$scratch/$name"

    merged_path="$scratch/${lang}.merged.po"
    msgmerge --no-fuzzy-matching --quiet -o "$merged_path" "$scratch/$name" "$POT"
    # Strip obsolete (#~) entries that survive from the upstream
    # catalog but have no match in our POT.  Without this every file
    # ships ~1000 lines of dead history.
    msgattrib --no-obsolete -o "po/${lang}.po" "$merged_path"
    merged=$((merged + 1))
done

echo "Merged $merged catalogs (kept exact msgid matches only)."
echo "Re-run 'bash install-test.sh' to compile + install the .mo files."
