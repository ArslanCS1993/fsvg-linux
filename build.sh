#!/usr/bin/env bash
# Rebuild every three-pane page from its kernel source and trace.
#
# Paths default to this box; override from the environment:
#   TRACE=/p/trace.json KERNEL=/p/linux-source-6.8.0 ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

TRACE=${TRACE:-/root/gh-cpu3d/src/trace.json}
KERNEL=${KERNEL:-/tmp/ksrc64/linux-source-6.8.0}
fail=0

# file under translation | source window | page title
PAGES=(
  "arch/x86/entry/entry_64.S|60|157|entry_SYSCALL_64"
)

# entry_64.S holds both the SYSCALL and SYSENTER paths, so the page name comes
# from the title, not from string surgery on the filename:
#   arch/x86/entry/ + entry_SYSCALL_64 -> entry_SYSCALL_64.html
for spec in "${PAGES[@]}"; do
  IFS='|' read -r entry lo hi title <<< "$spec"
  out="kernel/$(dirname "$entry")/$title.html"
  echo "=== $entry -> $out"
  if ! python3 tools/three-pane.py --trace "$TRACE" --kernel "$KERNEL" \
        --entry "$entry" --from "$lo" --to "$hi" --title "$title" --out "$out"; then
    echo "FAIL $entry"; fail=1; continue
  fi

  # A page that lost its evidence is not a page: insist on all three panes.
  for probe in 'id="flow"' 'class="a' 'class="c'; do
    grep -q "$probe" "$out" || { echo "FAIL $entry: pane missing ($probe)"; fail=1; }
  done
  # Self-contained, so it works offline and from file://
  if grep -qE '(src|href)="https?://' "$out"; then
    echo "FAIL $entry: external URL"; fail=1
  fi
done

echo
(( fail )) && { echo "BUILD FAILED"; exit 1; }
echo "OK"