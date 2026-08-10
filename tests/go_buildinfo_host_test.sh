#!/usr/bin/env bash
# 호스트 Go 바이너리 buildinfo 수집(collect_go_binary_deps) e2e 검증.
# 리눅스 + Go 툴체인이 필요하다 — Windows 개발머신에서는 컨테이너로 돌린다:
#   MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/w" -w /w golang:1.22 bash tests/go_buildinfo_host_test.sh
# 에이전트 본체와 같은 셸 옵션으로 돈다 — pipefail 이 없으면 "grep -q 가 먼저 끝나 앞단이
# SIGPIPE 로 죽고 파이프라인이 실패로 잡히는" 부류의 버그를 이 테스트가 못 잡는다(실제로 겪음).
set -uo pipefail
AGENT="${AGENT:-agent/vuln-inventory-agent.sh}"
fail=0
ok()   { echo "  OK   $*"; }
bad()  { echo "  FAIL $*"; fail=1; }

# 에이전트 본문을 실행하지 않고 필요한 함수만 떼어 온다(실제 파일이 정본이라 복붙 사본을 두지 않는다).
have() { command -v "$1" >/dev/null 2>&1; }
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"
eval "$(sed -n '/^go_deps_from_binary() {/,/^}$/p'   "$AGENT")"
eval "$(sed -n '/^collect_go_binary_deps() {/,/^}$/p' "$AGENT")"
eval "$(grep -E '^(GO_BIN_SCAN_MAX|GO_BIN_MIN_SIZE|GO_BIN_PROBE_BYTES|SCAN_MAX_FILES|SCAN_MAX_DEPTH)=' "$AGENT")"

# --- 골든 케이스: 외부 모듈에 의존하는 Go 바이너리를 만들어 /opt 아래 둔다 ---
ROOT=$(mktemp -d)
mkdir -p "$ROOT/bin"
if have go; then
  src=$(mktemp -d)
  cat > "$src/go.mod" <<'EOF'
module vgdemo

go 1.22

require github.com/google/uuid v1.6.0
EOF
  cat > "$src/main.go" <<'EOF'
package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() { fmt.Println(uuid.New().String()) }
EOF
  ( cd "$src" && go mod download github.com/google/uuid >/dev/null 2>&1 \
      && go build -o "$ROOT/bin/vgdemo" . ) || { echo "SKIP: go build 실패(네트워크?)"; rm -rf "$ROOT" "$src"; exit 3; }
  rm -rf "$src"
else
  echo "SKIP: go 툴체인 없음"; rm -rf "$ROOT"; exit 3
fi

# 잡음: Go 가 아닌 실행 파일(스크립트)과 비실행 파일은 걸러져야 한다.
printf '#!/bin/sh\necho hi\n' > "$ROOT/bin/plain.sh"; chmod +x "$ROOT/bin/plain.sh"

export PROJECT_SCAN_ROOTS="$ROOT"
out=$(collect_go_binary_deps)
echo "--- collect_go_binary_deps 출력 ---"; echo "$out"; echo "-----------------------------------"

echo "$out" | grep -q '^go|github.com/google/uuid|v1.6.0$' && ok "골든 모듈 3필드로 추출" || bad "go|github.com/google/uuid|v1.6.0 없음"
if [ -n "$out" ] && ! echo "$out" | grep -qvE '^go\|[^|]+\|[^|]+$'; then ok "모든 줄이 3필드(go|모듈|버전)"; else bad "3필드가 아닌 줄이 있다"; fi
[ "$(echo "$out" | sort -u | md5sum)" = "$(echo "$out" | md5sum)" ] && ok "출력이 정렬·중복제거 상태(content_hash 안정)" || bad "정렬/중복제거가 안 됐다"

# 상한이 실제로 먹는지 — 0 개로 잡으면 아무것도 안 나와야 한다.
GO_BIN_SCAN_MAX=0 out0=$(GO_BIN_SCAN_MAX=0 collect_go_binary_deps)
[ -z "$out0" ] && ok "GO_BIN_SCAN_MAX 상한 동작" || bad "GO_BIN_SCAN_MAX=0 인데 출력이 있다"

# 컨테이너 경로 무회귀: cid 를 주면 기존 5필드 형식 그대로여야 한다.
ctr=$(go_deps_from_binary "$ROOT/bin/vgdemo" "abc123456789" | head -1)
case "$ctr" in
  abc123456789\|go\|*\|*\|) ok "go_deps_from_binary(cid) 5필드 형식 유지: $ctr" ;;
  *) bad "컨테이너 형식이 바뀌었다: $ctr" ;;
esac

rm -rf "$ROOT"
[ "$fail" -eq 0 ] && echo "PASS" || echo "FAIL"
exit "$fail"
