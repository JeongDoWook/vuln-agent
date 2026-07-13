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

# --- UI 정적 검사 -----------------------------------------------------------
# 서버를 치기 전에 먼저 돈다(죽은 CSS 클래스·인라인 style·조용히 잘리는 목록).
# 여기서 걸리면 화면은 200 을 주면서도 스타일이 안 입혀지거나 데이터가 잘려 나간다 —
# curl 로는 절대 안 잡히는 종류라 정적으로 본다.
if ! "$ROOT/tests/ui_lint.sh"; then
  fail=$((fail+1))
fi

# --- 수신 API ---------------------------------------------------------------
printf "\n[ingest]\n"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ingest.php" \
  -H 'X-Agent-Token: WRONG' --data-binary @"$SAMPLE")
assert_eq "$code" "401" "잘못된 토큰 → 401"

resp=$(curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE")
assert_contains "$resp" '"ok":true' "정상 토큰 → ok:true"
assert_contains "$resp" '"packages":6' "패키지 6건 저장"
assert_contains "$resp" '"exposures":5' "노출 5건 저장"
# 언어 패키지(pip 2 + npm 2) — 예전엔 수집만 하고 서버가 버렸다.
assert_contains "$resp" '"langpkgs":4' "언어 패키지 4건 저장(pip/npm)"
# 컨테이너 내부 패키지 — 호스트 스캔에서 빠져 통째로 미탐이던 영역.
assert_contains "$resp" '"containers":2'   "컨테이너 2개 저장(alpine/debian)"
assert_contains "$resp" '"ctr_packages":3' "컨테이너 내부 패키지 3건 저장"
crit=$(printf '%s' "$resp" | grep -oE '"CRITICAL":[0-9]+' | grep -oE '[0-9]+$')
if [ "${crit:-0}" -ge 1 ]; then ok "CRITICAL ≥ 1 (glibc KEV+외부) = $crit"; else no "CRITICAL 미검출"; fi
high=$(printf '%s' "$resp" | grep -oE '"HIGH":[0-9]+' | grep -oE '[0-9]+$')
if [ "${high:-0}" -ge 2 ]; then ok "HIGH ≥ 2 (openssl/nginx 외부) = $high"; else no "HIGH 부족 (=$high)"; fi
# 방화벽 차단 포트(redis 0.0.0.0:6379, scope=FILTERED)는 외부노출이 아니다 → HIGH 가 아니라 MEDIUM.
med=$(printf '%s' "$resp" | grep -oE '"MEDIUM":[0-9]+' | grep -oE '[0-9]+$')
if [ "${med:-0}" -ge 1 ]; then ok "MEDIUM ≥ 1 (redis 방화벽 차단 → 외부노출 아님) = $med"; else no "MEDIUM 미검출"; fi
# (예전엔 "HIGH == 2" 로 못박았는데, 피드가 동기화된 DB 에선 HIGH 가 수십 개라 무조건 깨진다.
#  등급 총량이 아니라 **redis 가 FILTERED 로 분류됐는지**를 직접 본다 — 데이터 양과 무관하게 성립.)

# 억제: sudo(벤더 권고가 이 빌드에서 고침 = 백포트).
#   curl 은 설치 ≥ 조치라 원래 억제 대상이지만, nginx 가 옛 libcurl 을 물고 있어(재시작 필요)
#   억제되지 않고 취약으로 남아야 한다 — 이게 미탐 방지의 핵심이다.
supp=$(printf '%s' "$resp" | grep -oE '"SUPPRESSED":[0-9]+' | grep -oE '[0-9]+$')
if [ "${supp:-0}" -ge 1 ]; then ok "억제 ≥ 1 (sudo errata) = $supp"; else no "억제 부족 (=${supp:-0})"; fi

# --- 데비안 호스트: debsecan 기반 백포트 억제 --------------------------------
#   web02(Debian 12)의 curl·openssl 은 둘 다 조치 버전보다 낮아 "버전만 보면" 취약하다.
#   debsecan(데비안 보안 트래커)이 curl 만 지목했다 → openssl 은 백포트로 이미 고쳐진 것(억제).
printf "\n[debsecan · 데비안 백포트 억제]\n"
resp=$(curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" \
  --data-binary @"$ROOT/tests/sample-scan-debian.json")
assert_contains "$resp" '"ok":true' "데비안 호스트 수집 → ok:true"
assert_contains "$resp" '"debsecan":1' "debsecan 판정 1건 저장"
dlow=$(printf '%s' "$resp" | grep -oE '"LOW":[0-9]+' | grep -oE '[0-9]+$')
if [ "${dlow:-0}" -ge 1 ]; then ok "curl 은 취약 유지 (debsecan 이 지목) = $dlow"; else no "curl 이 사라짐(과잉 억제?)"; fi
dsupp=$(printf '%s' "$resp" | grep -oE '"SUPPRESSED":[0-9]+' | grep -oE '[0-9]+$')
if [ "${dsupp:-0}" -ge 1 ]; then ok "openssl 억제 (debsecan 미지목 → 백포트) = $dsupp"; else no "억제 안 됨 (=${dsupp:-0})"; fi
# 서드파티 저장소(nginx.org) 패키지는 배포판 기준으로 판정할 수 없다 → 억제하지 않고 남긴다.
#   버전만 보면 "설치 1.24.0 ≥ 조치 1.22.1" 이라 억제될 뻔했고, debsecan 목록에도 없어
#   "백포트로 수정됨" 으로도 억제될 뻔했다. 둘 다 미탐이다.
if [ "${dsupp:-0}" -eq 1 ]; then ok "서드파티 nginx 는 억제되지 않음 (억제는 openssl 1건뿐)"; else no "서드파티 nginx 가 억제됨 (억제 ${dsupp}건 — 미탐!)"; fi

# --- 바뀔 때만 스냅샷 --------------------------------------------------------
#   같은 내용을 다시 보내면 새 스캔을 만들지 않는다(수집시각만 갱신). 패키지가 바뀌면 새 스냅샷 +
#   변경이력. 매시간 수집이 대부분 "직전과 동일"이라 이게 없으면 데이터가 무한히 불어난다.
printf "\n[변경 추적]\n"
resp=$(curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE")
assert_contains "$resp" '"changed":false' "동일 내용 재전송 → 새 스냅샷 안 만듦"

UPG="$(mktemp)"; sed 's/0:2.34-60.el9_2.3/0:2.34-83.el9_3.7/' "$SAMPLE" > "$UPG"
resp=$(curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$UPG")
assert_contains "$resp" '"changed":true'  "glibc 업그레이드 → 새 스냅샷"
assert_contains "$resp" '"pkg_changes":1' "패키지 변경 1건 기록"
rm -f "$UPG"
# 되돌려 놓는다(뒤의 검사들이 원래 샘플 기준이라 상태를 원복해야 한다).
curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE" >/dev/null

# --- 피드 미지원 배포판: 0건이 "안전"이 아니라 "판정 불가" -------------------
#   Amazon Linux 는 OSV 생태계 목록에 없다(질의하면 INVALID_ARGUMENT). 매칭 후보가 아예 없어
#   취약점이 0건으로 뜨는데, 운영자가 "안전하다"고 읽으면 침묵하는 미탐이 된다 → 명시적으로 알린다.
printf "\n[미지원 배포판 경고]\n"
resp=$(curl -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" \
  --data-binary @"$ROOT/tests/sample-scan-amzn.json")
assert_contains "$resp" '"ok":true' "Amazon Linux 호스트 수집 → ok:true"
assert_contains "$resp" 'ALAS' "ingest 응답에 미지원 경고(자체 ALAS 피드 필요)"

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
assert_contains "$body" "최고 위험도" "호스트 상세(자산 식별 히어로 + 섹션 탭)"
# curl 은 조치 버전 이상이지만 nginx 가 옛 libcurl 을 물고 있다 → 억제 대신 "재시작 필요"로 남는다(기본=취약점 탭).
assert_contains "$body" "재시작 필요" "재시작 필요 근거 노출(패치됐지만 옛 라이브러리 사용 중)"
body=$(curl -s -b "$JAR" "$BASE/host.php?id=1&tab=runtime")
assert_contains "$body" "런타임 노출" "호스트 상세 · 런타임 탭(노출·프로세스)"
# redis 는 0.0.0.0:6379 지만 방화벽이 막는다 → EXTERNAL 이 아니라 FILTERED 로 분류돼야 한다.
body=$(curl -s -b "$JAR" "$BASE/findings.php?st=FILTERED")
assert_contains "$body" "redis" "방화벽 차단(FILTERED) 분류 — redis 가 외부노출로 새지 않음"
# 미지원 배포판 호스트가 있으면 취약점 화면 상단에 경고가 떠야 한다("0건 = 판정 불가").
body=$(curl -s -b "$JAR" "$BASE/findings.php")
assert_contains "$body" "판정 불가" "취약점 화면에 미지원 배포판 경고 노출"

# 잘못된 비번
JAR2="$(mktemp)"; csrf2=$(curl -s -c "$JAR2" "$BASE/login.php" | grep -oE '[a-f0-9]{32}' | head -1)
body=$(curl -s -b "$JAR2" -c "$JAR2" --data-urlencode "csrf=$csrf2" \
  --data-urlencode "username=admin" --data-urlencode "password=WRONG" "$BASE/login.php")
assert_contains "$body" "올바르지 않습니다" "틀린 비밀번호 → 로그인 거부"
rm -f "$JAR2"

# --- 요약 -------------------------------------------------------------------
printf "\n${CYAN}== 결과: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC} ==\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
