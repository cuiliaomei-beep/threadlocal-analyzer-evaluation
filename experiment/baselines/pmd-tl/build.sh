#!/usr/bin/env bash
# Build supplied source and generated ruleset against PMD 7.28.0.
set -euo pipefail
BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$BASE/../../gt/runtime.sh"
PMD_HOME="${TL_PMD_HOME:-$HOME/tools/pmd-bin-7.28.0}"
if [ -n "${TL_PMD:-}" ] && [ -z "${TL_PMD_HOME:-}" ]; then
  PMD_HOME=$(cd "$(dirname "$TL_PMD")/.." && pwd -P)
fi
[ -d "$PMD_HOME/lib" ] || { printf 'Missing PMD 7.28.0 lib directory: %s\n' "$PMD_HOME"; exit 2; }
cd "$BASE"
TARGET="$BASE/target"
# The resolved recursive-delete target is exactly this build's child directory.
[[ "$TARGET" == "$BASE/target" ]] || exit 2
rm -rf -- "$TARGET"
mkdir -p "$TARGET/classes"
cp -R resources/. "$TARGET/classes/"
mapfile -d '' SOURCES < <(find src -name '*.java' -print0)
javac -nowarn -cp "$PMD_HOME/lib/*" -d "$TARGET/classes" "${SOURCES[@]}"
(cd "$TARGET/classes" && jar cf ../pmd-threadlocal-rules-1.0-SNAPSHOT.jar .)
sha256sum resources/rulesets/threadlocal-pmd-ruleset.xml "$TARGET/pmd-threadlocal-rules-1.0-SNAPSHOT.jar"
