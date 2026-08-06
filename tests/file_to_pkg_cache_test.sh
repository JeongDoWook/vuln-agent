#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export TMP

# 실제 에이전트의 함수 본문을 그대로 읽어 테스트한다. 두 호출을 각각 서브셸에서 실행해
# associative array가 공유되지 않는 운영 경로(명령 치환·파이프라인)를 재현한다.
func=$(awk '/^file_to_pkg\(\) \{/{on=1} on{print} on && /^}$/{exit}' \
  "$ROOT/agent/vuln-inventory-agent.sh")
eval "$func"

PKGMGR=dpkg
declare -A LIBPKG
declare -A RPPATH
COUNT_FILE="$TMP/dpkg-calls"
export COUNT_FILE
dpkg() {
  printf '1\n' >> "$COUNT_FILE"
  printf 'test-package: %s\n' "${3:-$2}"
}
export -f dpkg

target="$TMP/libexample.so"
: > "$target"
first=$(file_to_pkg "$target")
second=$(file_to_pkg "$target")

[ "$first" = test-package ]
[ "$second" = test-package ]
[ "$(wc -l < "$COUNT_FILE")" -eq 1 ] || {
  echo "같은 경로를 dpkg에 두 번 조회했습니다" >&2
  exit 1
}

echo "  ✓ 서브셸 간 파일→패키지 조회 캐시"
