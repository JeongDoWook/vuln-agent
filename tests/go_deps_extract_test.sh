#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }
CMD_TIMEOUT=5
func=$(awk '/^go_deps_from_binary\(\) \{/{on=1} on{print} on && /^}$/{exit}' \
  "$ROOT/agent/vuln-inventory-agent.sh")
eval "$func"

fixture="$TMP/go-buildinfo.bin"
{
  printf 'binary-noise\0dep\tgithub.com/example/mod\tv1.2.3\th1:hash\n'
  printf 'dep\tgolang.org/x/net\tv0.20.0\th1:hash\0more-noise\n'
} > "$fixture"

got=$(go_deps_from_binary "$fixture" test-container | sort)
expected=$'test-container|go|github.com/example/mod|v1.2.3|\n'
expected+='test-container|go|golang.org/x/net|v0.20.0|'
[ "$got" = "$expected" ] || {
  printf '기대: %s\n실제: %s\n' "$expected" "$got" >&2
  exit 1
}

echo "  ✓ strings 기반 Go 의존성 추출"
