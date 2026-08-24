#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# mktemp 기본 TMPDIR(Windows %TEMP%)에 비-ASCII 사용자명이 섞이면 mingw64 strings.exe 가
#   "Illegal byte sequence" 로 그 경로의 파일을 못 연다 — 콘솔이 없는 실행 경로(git hook 등)에서만
#   재현된다(콘솔 코드페이지 vs 파이프 실행의 차이, 대화형 터미널에선 안 걸림). 저장소 경로는
#   항상 ASCII 이므로 여기에 만든다.
TMP=$(mktemp -d "$ROOT/tests/.tmp-go-deps.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

CMD_TIMEOUT=5
func=$(awk '/^go_deps_from_binary\(\) \{/{on=1} on{print} on && /^}$/{exit}' \
  "$ROOT/agent/vuln-inventory-agent.sh")
eval "$func"

fixture="$TMP/go-buildinfo.bin"
{
  printf 'binary-noise\0dep\tgithub.com/example/mod\tv1.2.3\th1:hash\n'
  printf 'dep\tgolang.org/x/net\tv0.20.0\th1:hash\0more-noise\n'
} > "$fixture"

expected=$'test-container|go|github.com/example/mod|v1.2.3|\n'
expected+='test-container|go|golang.org/x/net|v0.20.0|'

check() {
  local label="$1" got="$2"
  [ "$got" = "$expected" ] || {
    printf '[%s] 기대: %s\n실제: %s\n' "$label" "$expected" "$got" >&2
    exit 1
  }
  echo "  ✓ $label"
}

# strings 경로 — 이 머신에 strings 가 있을 때만 돈다. 없으면 조용히 넘기지 않고 건너뛴 사실을 찍는다.
if command -v strings >/dev/null 2>&1; then
  have() { command -v "$1" >/dev/null 2>&1; }
  got=$(go_deps_from_binary "$fixture" test-container | sort)
  check "strings 기반 Go 의존성 추출" "$got"
else
  echo "  - strings 없음: strings 경로 건너뜀"
fi

# 폴백 경로 — binutils 없는 최소 호스트를 강제로 흉내낸다(have 를 덮어써서 strings 를 없는 셈 침).
have() { return 1; }
got=$(go_deps_from_binary "$fixture" test-container | sort)
check "tr 폴백 기반 Go 의존성 추출(binutils 없는 최소 호스트)" "$got"
