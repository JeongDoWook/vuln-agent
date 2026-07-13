#!/usr/bin/env bash
# =============================================================================
# vuln-agent · API 스모크 테스트 (curl 기반 end-to-end)
# =============================================================================
# 실행 중인 스택을 대상으로 수집→저장→매칭→웹 로그인까지 자동 검증한다.
#   사용:  ./tests/smoke.sh [BASE_URL]     (기본 http://localhost:8080)
#   사전:  ./compose_runner.sh dev up -d  로 스택이 떠 있어야 함.
#          비밀값은 secrets/*.txt 에서 읽는다.
# 종료코드: 실패가 하나라도 있으면 1.
# =============================================================================
set -uo pipefail

BASE="${1:-http://localhost:8080}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE="$ROOT/tests/sample-scan.json"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
pass=0; fail=0
ok() { printf "  ${GREEN}✓${NC} %s\n" "$1"; pass=$((pass+1)); }
no() { printf "  ${RED}✗${NC} %s\n" "$1"; fail=$((fail+1)); }
assert_eq() { if [ "$1" = "$2" ]; then ok "$3"; else no "$3  (기대=$2, 실제=$1)"; fi; }
assert_contains() { if printf '%s' "$1" | grep -q "$2"; then ok "$3"; else no "$3  ('$2' 없음)"; fi; }

for f in "$ROOT/secrets/ingest_token.txt" "$ROOT/secrets/admin_password.txt"; do
  [ -s "$f" ] || { echo "secrets 없음: $f — 먼저 ./compose_runner.sh init"; exit 2; }
done
TOKEN="$(cat "$ROOT/secrets/ingest_token.txt")"
ADMPW="$(cat "$ROOT/secrets/admin_password.txt")"

printf "${CYAN}== vuln-agent smoke test @ %s ==${NC}\n" "$BASE"

# --- 수신 API ---------------------------------------------------------------
printf "\n[ingest]\n"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ingest.php" \
  -H 'X-Agent-Token: WRONG' --data-binary @"$SAMPLE")
assert_eq "$code" "401" "잘못된 토큰 → 401"

resp=$(curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE")
assert_contains "$resp" '"ok":true' "정상 토큰 → ok:true"
assert_contains "$resp" '"packages":5' "패키지 5건 저장"
assert_contains "$resp" '"exposures":4' "노출 4건 저장"
crit=$(printf '%s' "$resp" | grep -oE '"CRITICAL":[0-9]+' | grep -oE '[0-9]+$')
if [ "${crit:-0}" -ge 1 ]; then ok "CRITICAL ≥ 1 (glibc KEV+외부) = $crit"; else no "CRITICAL 미검출"; fi
high=$(printf '%s' "$resp" | grep -oE '"HIGH":[0-9]+' | grep -oE '[0-9]+$')
if [ "${high:-0}" -ge 2 ]; then ok "HIGH ≥ 2 (openssl/nginx 외부) = $high"; else no "HIGH 부족 (=$high)"; fi
# 억제 2건: curl(설치 ≥ 조치 버전) + sudo(벤더 권고가 이 빌드에서 고침 = 백포트).
supp=$(printf '%s' "$resp" | grep -oE '"SUPPRESSED":[0-9]+' | grep -oE '[0-9]+$')
if [ "${supp:-0}" -ge 2 ]; then ok "억제 ≥ 2 (curl 버전 + sudo errata) = $supp"; else no "억제 부족 (=${supp:-0})"; fi

# --- 재매칭 -----------------------------------------------------------------
printf "\n[rematch]\n"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/rematch.php?token=WRONG")
assert_eq "$code" "401" "잘못된 토큰 → 401"
resp=$(curl -s "$BASE/rematch.php?token=$TOKEN")
assert_contains "$resp" '"ok":true' "재매칭 성공"

# --- 웹 인증 흐름 -----------------------------------------------------------
printf "\n[web auth]\n"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")
assert_eq "$code" "302" "미인증 대시보드 → 302(로그인 리다이렉트)"

csrf=$(curl -s -c "$JAR" "$BASE/login.php" | grep -oE 'name="csrf" value="[a-f0-9]+"' | grep -oE '[a-f0-9]{32}')
if [ -n "$csrf" ]; then ok "로그인 폼 CSRF 토큰 취득"; else no "CSRF 토큰 없음"; fi

code=$(curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' \
  --data-urlencode "csrf=$csrf" --data-urlencode "username=admin" --data-urlencode "password=$ADMPW" \
  "$BASE/login.php")
assert_eq "$code" "302" "올바른 로그인 → 302(대시보드)"

body=$(curl -s -b "$JAR" "$BASE/")
assert_contains "$body" "대시보드" "대시보드 접근(인증됨)"
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/findings.php")
assert_eq "$code" "200" "취약점 페이지 200"
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/users.php")
assert_eq "$code" "200" "사용자 페이지 200(admin)"

body=$(curl -s -b "$JAR" "$BASE/connectors.php")
assert_contains "$body" "CISA KEV" "피드 커넥터 페이지(기본 커넥터 노출)"
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/advisories.php")
assert_eq "$code" "200" "국내 보안공지 페이지 200"
body=$(curl -s -b "$JAR" "$BASE/host.php?id=1")
assert_contains "$body" "런타임 노출" "호스트 상세 페이지(노출·취약점)"

# 잘못된 비번
JAR2="$(mktemp)"; csrf2=$(curl -s -c "$JAR2" "$BASE/login.php" | grep -oE '[a-f0-9]{32}' | head -1)
body=$(curl -s -b "$JAR2" -c "$JAR2" --data-urlencode "csrf=$csrf2" \
  --data-urlencode "username=admin" --data-urlencode "password=WRONG" "$BASE/login.php")
assert_contains "$body" "올바르지 않습니다" "틀린 비밀번호 → 로그인 거부"
rm -f "$JAR2"

# --- 요약 -------------------------------------------------------------------
printf "\n${CYAN}== 결과: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC} ==\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
