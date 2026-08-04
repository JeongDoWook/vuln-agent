#!/usr/bin/env bash
# =============================================================================
# agent_json_test.sh — 에이전트의 awk JSON 빌더가 **jq 와 같은 JSON** 을 만드는가.
# =============================================================================
# 왜 필요한가: 에이전트는 대상 서버에 아무것도 요구하지 않는다(폐쇄망엔 apt 도 없다).
#   그래서 jq 없이 awk 로 JSON 을 조립하는데, 이스케이프를 한 글자라도 틀리면 중앙이 파싱에
#   실패해 **전송이 통째로 죽는다**. 그 회귀를 기계로 막는다.
#
# 정답(tests/fixtures/agent-json/expected.json)은 **jq 가 만든 것**이다(jq -S -c, 키 정렬).
#   awk 빌더의 출력과 바이트 단위로 같아야 한다. jq 는 이 테스트를 돌릴 때 필요 없다.
#
# 실행: bash tests/agent_json_test.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT/agent/vuln-inventory-agent.sh"
FIX="$ROOT/tests/fixtures/agent-json"

# 빌더 함수만 떼어 온다 — 에이전트를 통째로 실행하면 수집이 돌아버린다(느리고 호스트에 의존).
eval "$(sed -n '/^vg_json_escape_file() {/,/^}/p; /^vg_json_escape_rpmdb_file() {/,/^}/p; /^vg_json_is_rpmdb_safe() {/,/^}/p; /^vg_json_build() {/,/^}/p' "$AGENT")"
if ! declare -f vg_json_build >/dev/null; then
  echo "  ✗ 에이전트에서 vg_json_build 를 못 찾았습니다(함수명이 바뀌었나?)" >&2
  exit 1
fi

TMP="$FIX/in"          # vg_json_build 가 읽는 디렉터리
got="$(vg_json_build)"
want="$(cat "$FIX/expected.json")"

if [ "$got" = "$want" ]; then
  echo "agent_json: awk 빌더 = jq 출력 (일치)"
else
  echo "  ✗ awk 빌더 출력이 jq 정답과 다릅니다" >&2
  echo "  기대: $want" >&2
  echo "  실제: $got"  >&2
  exit 1
fi

rpm_tmp="$(mktemp -d)"
trap 'rm -rf "$rpm_tmp"' EXIT
printf 'abc123|gz|H4sIAAAAAAAA\n' > "$rpm_tmp/containers__rpmdb.txt"
TMP="$rpm_tmp"
rpm_got="$(vg_json_build)"
[ "$rpm_got" = '{"containers":{"rpmdb":"abc123|gz|H4sIAAAAAAAA"}}' ] || {
  echo "  ✗ RPM DB 고속 JSON 경로 출력 불일치: $rpm_got" >&2
  exit 1
}
echo "agent_json: RPM DB Base64 고속 경로 = 정상"
