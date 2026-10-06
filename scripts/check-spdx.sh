#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that every hand-written script and test file starts with the SPDX header of its directory
# (LICENSE.md): `// SPDX-License-Identifier: <id>` for JavaScript, `# SPDX-License-Identifier: <id>` for shell,
# as the first line or the second line after a shebang. JSON cannot carry a header (openapi.json and the test
# vectors are covered by LICENSE.md and NOTICE); the Markdown documents state their license in the text.
# Usage: scripts/check-spdx.sh [--fix]   (--fix inserts missing headers; wrong ones are only reported)
set -euo pipefail
cd "$(dirname "$0")/.."
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "check-spdx: not a git checkout" >&2; exit 2; }

fix=0
[ "${1:-}" = "--fix" ] && fix=1

# Expected license per path prefix (first match wins). Keep in sync with LICENSE.md.
license_for() {
  case "$1" in
    */node_modules/* | node_modules/* | target/*) echo skip ;;
    scripts/* | test/* | .github/*) echo Apache-2.0 ;;
    *) echo unmapped ;;
  esac
}

comment_for() {
  case "$1" in
    *.sh) echo '#' ;;
    *) echo '//' ;;
  esac
}

missing=0
wrong=0
fixed=0
while IFS= read -r -d '' file; do
  [ -f "$file" ] || continue
  expected=$(license_for "$file")
  [ "$expected" = skip ] && continue
  if [ "$expected" = unmapped ]; then
    echo "no license mapped for $file (add its directory to scripts/check-spdx.sh and LICENSE.md)" >&2
    missing=$((missing + 1))
    continue
  fi
  prefix=$(comment_for "$file")
  header="$prefix SPDX-License-Identifier: $expected"
  first=$(head -n 1 "$file")
  line=1
  if [[ "$first" == '#!'* ]]; then
    line=2
  fi
  actual=$(sed -n "${line}p" "$file")
  [ "$actual" = "$header" ] && continue
  if [[ "$actual" == "$prefix SPDX-License-Identifier:"* ]]; then
    echo "$file: wrong license header '$actual' (expected '$header')" >&2
    wrong=$((wrong + 1))
    continue
  fi
  if [ "$fix" = 1 ]; then
    tmp=$(mktemp)
    if [ "$line" = 2 ]; then
      { head -n 1 "$file"; echo "$header"; tail -n +2 "$file"; } > "$tmp"
    else
      { echo "$header"; cat "$file"; } > "$tmp"
    fi
    cat "$tmp" > "$file" && rm -f "$tmp"
    fixed=$((fixed + 1))
  else
    echo "$file: missing '$header'" >&2
    missing=$((missing + 1))
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- '*.sh' '*.mjs' '*.js' '*.ts')

[ "$fixed" -gt 0 ] && echo "inserted $fixed SPDX headers"
if [ "$missing" -gt 0 ] || [ "$wrong" -gt 0 ]; then
  echo "SPDX check failed: $missing missing, $wrong wrong (run scripts/check-spdx.sh --fix for missing headers)" >&2
  exit 1
fi
echo "SPDX headers ok"
