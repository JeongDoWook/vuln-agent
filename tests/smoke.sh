#!/usr/bin/env bash
# =============================================================================
# vuln-agent · API 스모크 테스트 (curl 기반 end-to-end)
# =============================================================================
# 실행 중인 스택을 대상으로 수집→저장→매칭→웹 로그인까지 자동 검증한다.
#   사용:  ./tests/smoke.sh [BASE_URL]     (기본 http://localhost:8000)
#   사전:  ./compose_runner.sh dev up -d  로 스택이 떠 있어야 함.
#          비밀값은 secrets/*.txt 에서 읽는다.
# 종료코드: 실패가 하나라도 있으면 1.
# =============================================================================
set -uo pipefail

BASE="${1:-http://localhost:8000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 서버가 요청을 받고도 응답을 안 주면(PHP 가 외부 API 호출에서 멈춤·DB 락 대기 등) curl 이
# 무한 대기해 push 가 그대로 멈춘 것처럼 보인다 — 모든 curl 호출에 상한을 둔다.
#   curl_  : 단순 GET/로그인류 (20초)
#   curl_i : ingest.php — 매칭 파이프라인이 도는 요청이라 여유 있게 (30초)
curl_()  { curl --max-time 20 "$@"; }
curl_i() { curl --max-time 30 "$@"; }

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
pass=0; fail=0
ok() { printf "  ${GREEN}✓${NC} %s\n" "$1"; pass=$((pass+1)); }
no() { printf "  ${RED}✗${NC} %s\n" "$1"; fail=$((fail+1)); }
assert_eq() { if [ "$1" = "$2" ]; then ok "$3"; else no "$3  (기대=$2, 실제=$1)"; fi; }
# 통과도 실패도 아닌 세 번째 상태 — **환경이 없어서 못 돈** 검사. 통과로 세면 거짓 초록불이고,
# 실패로 세면 회귀도 아닌 것에 빨간불이 켜져 스모크를 못 믿게 된다. 그래서 눈에는 보이되
# pass/fail 어느 쪽으로도 안 센다(요약에 건너뜀 개수로 따로 찍는다).
# 지금 유일한 사용처는 go_buildinfo_host_test.sh 다(Go 툴체인 필요).
skip=0
sk() { printf "  ${YELLOW}-${NC} %s\n" "$1"; skip=$((skip+1)); }
# 본문 검사는 **파이프로 넘기지 않는다** — `printf … | grep -q` 는 위의 `set -o pipefail` 과 만나면
#   문자열이 있는데도 실패로 뒤집힌다: grep -q 는 첫 매치에서 즉시 끝나므로, 본문이 파이프
#   버퍼(64KB)보다 크고 매치가 앞쪽이면 아직 쓰던 printf 가 SIGPIPE 로 죽어 파이프라인 종료코드가
#   141 이 된다. 공용 dev DB 가 자라 findings.php 응답이 64KB 를 넘긴 뒤로 '컨테이너 nodb' 검사가
#   모든 워크트리에서 상시 실패했다(응답에는 그 문자열이 멀쩡히 있었다). here-string 은 파이프가
#   아니라서 grep 의 종료코드가 그대로 결과가 된다.
#
# 이제 grep 자체를 쓰지 않는다 — **bash 내장 패턴 매칭**이라 프로세스도 파이프도 없다.
#   따라서 위의 SIGPIPE(141) 함정은 구조적으로 사라졌다(기록으로 남겨 둔다: 다시 grep 으로
#   되돌린다면 반드시 here-string 을 써야 한다).
#   왜 바꿨나: Windows git-bash 에서 fork 한 번이 44~48ms 라, 서버를 치지도 않는 이 헬퍼가
#   102회 호출에 7초를 썼다(스모크 [패키지 서브탭] 구간 11.4초 중 61%). 측정은
#   docs/dev/packages-screen-profiling.md.
#   의미 차이: grep 은 $2 를 정규식(BRE)으로 봤지만 `*"$2"*` 는 **리터럴 부분문자열**이다.
#   전환 시 102개 단언을 전수 확인했다 — 메타문자는 `.` 뿐이었고 전부 실제 문자열의 일부
#   (`2.10.8`·`host.php`·`pom.xml` 등)라 리터럴이 더 엄격할 뿐 결과가 같다. 일부러 정규식을
#   쓴 단언은 없었다. 앞으로 정규식이 필요하면 이 헬퍼를 고치지 말고 별도 헬퍼를 만든다.
assert_contains() { if [[ "$1" == *"$2"* ]]; then ok "$3"; else no "$3  ('$2' 없음)"; fi; }
assert_not_contains() { if [[ "$1" == *"$2"* ]]; then no "$3  ('$2' 있음)"; else ok "$3"; fi; }

# 아래 단위테스트 13개(vercmp~ui_structure)는 실행 방식(마운트·php:8.3-cli·리다이렉션)이 전부
# 동일하고 파일명·라벨·메시지만 다르다 — DRY 로 묶는다. 각 테스트가 왜 존재하는지는
# 호출부 바로 위 주석에 그대로 남아 있다(도메인 지식이라 이 헬퍼로 뭉개지 않는다).
#   $1=tests/ 밑 파일명  $2=printf 라벨  $3=성공 메시지  $4=실패 메시지(생략 시 성공 메시지 재사용)
#
# 실행은 **호출 시점이 아니라 아래 prerun_phpunit() 에서 한 번에** 한다 — 예전엔 이 함수가
#   호출될 때마다 `docker run` 을 새로 띄워서, 27개 × 기동 1.5초 ≈ 39초가 통째로 컨테이너를
#   띄우는 데만 쓰였다(실제 PHP 실행은 파일당 수십 ms). 한 컨테이너에서 순차로 돌리면 ~7초다.
#   호출부와 그 위의 도메인 주석은 제자리에 두고, 이 함수만 "실행" 에서 "결과 조회" 로 바꾼다.
run_phpunit() {
  local file="$1" label="$2" okmsg="$3"
  local nomsg="${4:-$okmsg}"
  printf "\n[%s]\n" "$label"
  # 키가 없으면(= PHPUNIT_FILES 목록에서 빠졌다) 조용히 통과시키지 않고 실패로 본다.
  if [ "${PHPUNIT_RESULT[$file]:-MISSING}" = "PASS" ]; then
    ok "$okmsg"
  else
    no "$nomsg  (자세히: docker run --rm -v \$PWD:/w -w /w php:8.3-cli php tests/$file)"
  fi
}

# 위 27개 호출부가 참조하는 파일 목록 — **정본은 여기 하나뿐이다.**
#   호출부에 있는데 여기 없으면 위 조회가 MISSING 으로 떨어져 빨간불이 된다(누락이 눈에 띈다).
PHPUNIT_FILES=(
  vercmp_test.php
  osv_precision_test.php
  pkgdep_rollup_test.php
  matcher_suppress_test.php
  suppression_test.php
  ingest_parse_test.php
  assetgrade_history_test.php
  account_inventory_test.php
  ssg_test.php
  cce_new_rules_test.php
  rhunfixed_test.php
  rpmdb_test.php
  distro_test.php
  asset_state_test.php
  assetgrade_test.php
  debtracker_test.php
  rhoval_test.php
  ubuntuoval_test.php
  kernelcve_test.php
  schedule_test.php
  ui_config_test.php
  asset_grade_review_test.php
  ui_structure_test.php
  documentation_consistency_test.php
  route_query_contract_test.php
  agent_api_contract_test.php
  update_order_contract_test.php
  generic_api_config_test.php
  finding_evidence_test.php
  db_retry_test.php
)
declare -A PHPUNIT_RESULT=()

# 27개를 **컨테이너 한 번**으로 몰아 돌리고 파일별 PASS/FAIL 을 연관배열에 담는다.
#   · 컨테이너 안 루프는 if 로 종료코드를 받으므로 한 파일이 fatal 을 내도 나머지가 계속 돈다.
#   · 출력은 파이프가 아니라 임시 파일로 받는다 — 위 assert_contains 주석의 SIGPIPE(141) 함정과 같은 자리다.
#   · 마운트 경로 계산(MSYS_NO_PATHCONV=1 · pwd -W 폴백)은 기존 방식 그대로다.
prerun_phpunit() {
  local out st file
  out="$(mktemp)"
  MSYS_NO_PATHCONV=1 docker run --rm -v "$(cd "$ROOT" && { pwd -W 2>/dev/null || pwd; }):/w" \
    -w /w php:8.3-cli sh -c '
      for f in "$@"; do
        if php "tests/$f" >/dev/null 2>&1; then echo "PASS $f"; else echo "FAIL $f"; fi
      done' _ "${PHPUNIT_FILES[@]}" >"$out" 2>/dev/null
  while read -r st file; do
    [ -n "$file" ] || continue
    PHPUNIT_RESULT["$file"]="$st"
  done < "$out"
  rm -f "$out"
}

for f in "$ROOT/secrets/admin_password.txt"; do
  [ -s "$f" ] || { echo "secrets 없음: $f — 먼저 ./compose_runner.sh init"; exit 2; }
done
ADMPW="$(cat "$ROOT/secrets/admin_password.txt")"

printf "${CYAN}== vuln-agent smoke test @ %s ==${NC}\n" "$BASE"

# --- 이 트리의 web 컨테이너가 떠 있나 -----------------------------------------
# web+scheduler 는 이제 워크트리별로 독립된 컨테이너명(vulnagent-web-dev-<워크트리>)을 쓴다
#   (메인 트리는 접미사 없이 vulnagent-web-dev). 컨테이너명이 애초에 트리마다 겹치지 않으므로
#   "다른 트리 스택을 검사해 초록불을 주는" 옛 문제가 구조적으로 없다 — 그래서 예전처럼 마운트
#   경로를 대조할 필요 없이, 이 트리 전용 컨테이너가 떠 있는지만 보면 된다.
#   일부러 다른 대상을 칠 때는 끈다: VG_SMOKE_ANY=1, 또는 VG_SMOKE_BASE 로 대상을 명시했을 때.
WT_NAME=""
if [ "$(basename "$(dirname "$ROOT")")" = "wt" ]; then
  WT_NAME="$(basename "$ROOT")"
fi
DEFAULT_WEB_CONTAINER="vulnagent-web-dev${WT_NAME:+-$WT_NAME}"
WEB_CONTAINER="${VG_WEB_CONTAINER:-$DEFAULT_WEB_CONTAINER}"

container_running() {
  # healthcheck 가 있으면(떠 있어도 응답 불가능한 상태일 수 있다) healthy 여부까지 본다.
  # 없으면 예전처럼 running 여부만 본다. (deploy/migrate.sh 의 이중 판정 패턴과 동일)
  local st
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Running}}{{end}}' "$WEB_CONTAINER" 2>/dev/null)
  case "$st" in healthy|true) return 0 ;; *) return 1 ;; esac
}
SMOKE_GUARD=0
if [ "${VG_SMOKE_ANY:-0}" != "1" ] && [ -z "${VG_SMOKE_BASE:-}" ] && command -v docker >/dev/null 2>&1; then
  SMOKE_GUARD=1
fi

# 이 트리 전용 컨테이너가 떠 있는지 확인한다. 아니면 즉시 중단(exit 2).
#   $1 = 시점("시작"|"종료"). 종료에도 다시 보는 이유: smoke 는 수십 초 걸리는데, 그 도중 누가
#   `dev down` 을 치면 뒷부분 검사가 죽은 컨테이너를 친다.
assert_my_stack() {
  [ "$SMOKE_GUARD" = 1 ] || return 0
  if ! container_running; then
    printf "${RED}✗ [%s] 이 트리의 web 컨테이너(%s)가 떠 있지 않습니다 — 스모크를 중단합니다.${NC}\n" "$1" "$WEB_CONTAINER" >&2
    if [ "$1" = "종료" ]; then
      printf "    ${RED}스모크 도중 컨테이너가 사라졌습니다 — 위 결과는 무효입니다.${NC}\n" >&2
    fi
    printf "    올리려면: ./deploy/compose_runner.sh dev up -d\n" >&2
    printf "    (여기가 워크트리면 에이전트가 스스로 올려도 된다 — 이 트리 전용 web+scheduler 만 뜬다.\n" >&2
    printf "     메인 트리 스택과 공용 DB 는 사람이 올린다. 일부러 다른 대상을 칠 때만 VG_SMOKE_ANY=1)\n" >&2
    exit 2
  fi
}
assert_my_stack "시작"

# --- 이 트리 전용 fqdn -------------------------------------------------------
# dev DB 는 모든 워크트리가 공유하는 하나다(vulnagent-db-dev). 그런데 아래 e2e 는 호스트 레코드에
#   상태를 쓰고 **바로 그 상태를 assert** 한다 — fqdn 이 고정이면 두 트리가 동시에 스모크를 돌 때
#   같은 호스트를 서로 덮어써, 아무 잘못 없는 트리의 검사가 깨진다. 제일 먼저 무너지는 건
#   [변경 추적] 의 "동일 내용 재전송 → changed:false" 다(남이 그 사이에 다른 내용을 밀어넣으므로).
# 그래서 검사를 느슨하게 만드는 대신 **데이터를 격리한다**: fqdn 에 트리 이름을 라벨 하나로 끼운다.
#   메인 트리 → web01.main.example.com · 워크트리 X → web01.X.example.com
# 라벨을 점으로 감싸는 게 핵심이다. assets.php 의 검색은 `fqdn LIKE '%q%'` 라 부분문자열이 걸리는데,
#   라벨엔 점이 없으므로(비-DNS 문자는 - 로 치환) 한 트리의 fqdn 이 다른 트리의 fqdn 을 부분문자열로
#   품는 일이 구조적으로 불가능하다 — 전체 fqdn 으로 조회하면 항상 자기 호스트만 집힌다.
# WT_NAME 은 위에서 이미 계산했다(워크트리면 그 이름, 메인 트리면 빈 문자열) — 재사용한다.
WT_LABEL="$(printf '%s' "${WT_NAME:-main}" | tr -c 'a-zA-Z0-9-' '-')"
FQDN_WEB01="web01.$WT_LABEL.example.com"   # sample-scan.json        (Rocky 9.3)
FQDN_WEB02="web02.$WT_LABEL.example.com"   # sample-scan-debian.json (Debian 12)
FQDN_WEB03="web03.$WT_LABEL.example.com"   # sample-scan-amzn.json   (Amazon Linux 2023)

# 샘플은 원본을 두고 전송 직전에 fqdn 만 바꾼 사본을 쓴다($UPG·$SPOOF 와 같은 sed 패턴).
#   원본을 템플릿화하면 사람이 읽는 샘플에 플레이스홀더가 새고, 다른 테스트도 같이 고쳐야 한다.
SAMPLE="$(mktemp)"; SAMPLE_DEB="$(mktemp)"; SAMPLE_AMZN="$(mktemp)"
PRG_FQDN=""
cleanup_smoke() {
  rm -f "$SAMPLE" "$SAMPLE_DEB" "$SAMPLE_AMZN" "${JAR:-}"
  # 스모크가 발급한 토큰만 지운다. 테스트 FQDN과 라벨을 함께 제한해
  # 같은 DB를 쓰는 운영·수동 발급 토큰에는 영향을 주지 않는다.
  if [ -n "${WEB_CONTAINER:-}" ] && container_running; then
    docker exec "$WEB_CONTAINER" php -r \
      '$cfg=require "/var/www/html/src/config.php";
       require "/var/www/html/src/db.php";
       $fqdn=array_values(array_filter(array_slice($argv,1)));
       if (!$fqdn) { exit; }
       $marks=implode(",",array_fill(0,count($fqdn),"?"));
       $sql="DELETE FROM tb_agent_token WHERE host_fqdn IN ($marks) AND label LIKE ?";
       vg_pdo()->prepare($sql)->execute(array_merge($fqdn,["smoke%"]));' \
      "$FQDN_WEB01" "$FQDN_WEB02" "$FQDN_WEB03" "${PRG_FQDN:-}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_smoke EXIT
sed "s/web01\.example\.com/$FQDN_WEB01/g" "$ROOT/tests/sample-scan.json"        > "$SAMPLE"
sed "s/web02\.example\.com/$FQDN_WEB02/g" "$ROOT/tests/sample-scan-debian.json" > "$SAMPLE_DEB"
sed "s/web03\.example\.com/$FQDN_WEB03/g" "$ROOT/tests/sample-scan-amzn.json"   > "$SAMPLE_AMZN"
printf "  이 트리의 호스트: %s (트리 라벨 =%s)\n" "$FQDN_WEB01" "$WT_LABEL"

# 수집은 공유 시크릿을 허용하지 않는다. 각 샘플 호스트에 바인딩된 토큰을 발급해 사용한다.
issue_agent_token() {
  docker exec "$WEB_CONTAINER" php -r \
    '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/agenttoken.php"; echo vg_agent_token_issue(vg_pdo(), $argv[1], "smoke bootstrap", null)["token"];' \
    "$1"
}
TOKEN="$(issue_agent_token "$FQDN_WEB01")"
TOKEN_DEB="$(issue_agent_token "$FQDN_WEB02")"
TOKEN_AMZN="$(issue_agent_token "$FQDN_WEB03")"
if [ -n "$TOKEN" ] && [ -n "$TOKEN_DEB" ] && [ -n "$TOKEN_AMZN" ]; then
  ok "호스트별 수집 토큰 준비"
else
  no "호스트별 수집 토큰 준비 실패"
fi

# --- 워크트리 전용 로그인 계정 ------------------------------------------------
# admin 은 DB 가 공용이라 전 워크트리가 같은 행을 쓴다. vg_login() 은 로그인마다
#   session_token 을 덮어써 "새 로그인 = 이전 세션 강제종료"를 강제한다(auth.php) — 그래서
#   워크트리 여러 개가 동시에 admin 으로 스모크를 돌리면 서로의 세션을 계속 걷어차 뒤쪽
#   웹 인증 검사가 302 연쇄로 실패한다(실제로 겪음). 워크트리마다 admin-<라벨> 계정을 따로
#   써서 세션을 격리한다. DB 를 직접 upsert 하는 이유: users.php 로 만들려면 이미 로그인된
#   admin 세션이 있어야 하는데, 그 세션을 지키자고 이 계정을 만드는 것이라 순서가 안 맞는다.
#   메인 트리는 원래 하나뿐이라(동시에 도는 스모크가 없다) 손대지 않고 admin 을 그대로 쓴다.
SMOKE_USER="admin"
if [ -n "$WT_NAME" ] && command -v docker >/dev/null 2>&1; then
  SMOKE_USER="admin-$WT_LABEL"
  DB_CONTAINER="vulnagent-db-dev"   # 공용 DB, 트리와 무관하게 고정(compose_runner.sh 와 동일 전제)
  db_mysql() {
    docker exec -i "$DB_CONTAINER" sh -c \
      'MYSQL_PWD="$(cat /run/secrets/mysql_root_password)" mysql -uroot vulnagent "$@"' _ "$@"
  }
  SMOKE_HASH="$(docker run --rm -e P="$ADMPW" php:8.3-cli php -r 'echo password_hash(getenv("P"), PASSWORD_DEFAULT);' 2>/dev/null)"
  if [ -n "$SMOKE_HASH" ] && db_mysql -e \
      "INSERT INTO tb_user (username, password_hash, role, is_deleted)
       VALUES ('$SMOKE_USER', '$SMOKE_HASH', 'admin', 0)
       ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = 'admin',
         is_deleted = 0, failed_login_count = 0, locked_until = NULL, session_token = NULL" \
      >/dev/null 2>&1
  then
    printf "  이 트리의 계정: %s (다른 워크트리와 세션 격리)\n" "$SMOKE_USER"
  else
    printf "  ${RED}⚠ 워크트리 전용 계정(%s) 준비 실패 — admin 으로 폴백(다른 트리와 세션 경합 가능)${NC}\n" "$SMOKE_USER" >&2
    SMOKE_USER="admin"
  fi
fi


# --- UI 정적 검사 -----------------------------------------------------------
# 서버를 치기 전에 먼저 돈다(죽은 CSS 클래스·인라인 style·조용히 잘리는 목록).
# 여기서 걸리면 화면은 200 을 주면서도 스타일이 안 입혀지거나 데이터가 잘려 나간다 —
# curl 로는 절대 안 잡히는 종류라 정적으로 본다.
if ! "$ROOT/tests/ui_lint.sh"; then
  fail=$((fail+1))
fi

# --- 단위테스트 선(先)실행 ---------------------------------------------------
# 아래에 흩어져 있는 run_phpunit 호출 27개가 볼 결과를 여기서 한 번에 만든다(컨테이너 1회).
# 호출부는 그대로 순서대로 결과만 조회하므로 출력 순서·라벨·메시지는 이전과 동일하다.
prerun_phpunit

# --- vercmp 단위 테스트 -----------------------------------------------------
# 버전 비교는 매처 오탐의 1순위다(같은 패키지인데 이미 고친 버전을 취약하다고 부르는 것).
# 기대값을 dpkg/rpm 실측으로 뽑아 둔 테스트라 회귀를 정확히 잡는데, 예전엔 아무도 안 불러서
# server/src/vercmp.php 를 고쳐도 조용히 지나갔다 — 스모크에 묶는다.
# php 8.3 컨테이너로 돈다: 호스트 php 는 7.2 라 8.x 문법을 오탐한다(pre-push 와 같은 이유).
run_phpunit "vercmp_test.php" "vercmp" "vercmp 단위 테스트"
run_phpunit "osv_precision_test.php" "osv_precision" "OSV 구간·소스 버전 정밀 매칭 단위 테스트"

# --- 손댈 대상(부모)별 묶음 집계 단위 테스트 ----------------------------------
# "이 하나를 올리면 N건" 의 N 은 운영자가 조치 순서를 정하는 근거다. 판정 캐시(패키지 단위)와
# 건수 집계(행 단위)를 섞으면 조용히 과소집계되고, 화면만 봐선 그게 틀렸는지 알 수 없다.
run_phpunit "pkgdep_rollup_test.php" "pkgdep_rollup" "손댈 대상(부모)별 묶음 집계 단위 테스트"

# --- 매처 억제 게이트 단위 테스트 ---------------------------------------------
# "어느 근거가 어느 가드에 막히는가" 는 오탐(잘못 뜸)과 미탐(잘못 숨김)이 직접 갈리는 자리인데
# 눈으로 읽어선 회귀를 못 잡는다 — 실제로 changelog 억제가 서드파티 가드에 막혀 운영에서
# 억제 0건이었다(docs/dev/changelog-억제층-실측.md). 계약을 테스트로 고정한다.
run_phpunit "matcher_suppress_test.php" "matcher_suppress" "매처 억제 게이트 단위 테스트"

# 억제 근거를 화면 어휘로 옮기는 표(server/src/suppression.php)가 판정 문구와 어긋나면,
# 억제 목록이 통째로 '근거 미분류' 로 떨어진다 — 화면은 여전히 뜨므로 사람 눈엔 안 보인다.
run_phpunit "suppression_test.php" "suppression" "억제 근거 겹 분류 단위 테스트"

# --- ingest_parse 단위 테스트 -------------------------------------------------
# ingest.php 의 순수 변환(패키지/노출/컨테이너/changelog 파싱, 내용해시, 패키지 diff)을
# server/src/ingest_parse.php 로 뽑아냈다. 예전엔 이 파싱 로직에 단위테스트가 0개였다 —
# vercmp 처럼 서버 없이 도는 정적 검사라 스모크 앞단에 묶는다.
run_phpunit "ingest_parse_test.php" "ingest_parse" "ingest_parse 단위 테스트"
run_phpunit "assetgrade_history_test.php" "assetgrade_history" "자산등급 제안 이력 단위 테스트"

# --- 계정 인벤토리 단위 테스트 -------------------------------------------------
# 계정 판정은 "판정 불가(NA)"가 "정상(PASS)"으로 새는 순간 감사에서 거짓 안심이 된다
# (비-root 로 돌면 /etc/shadow·sudoers 를 못 읽는다 — 그건 점검한 게 아니다).
# 그 경계와 공유·퇴직자 계정이 **추정**임을 테스트로 고정한다.
run_phpunit "account_inventory_test.php" "account_inventory" "계정 인벤토리 단위 테스트 (NA·PASS 구분)" "계정 인벤토리 단위 테스트"

# --- 에이전트 JSON 빌더 -------------------------------------------------------
# 에이전트는 대상 서버에 아무것도 요구하지 않는다 → jq 없이 awk 로 JSON 을 만든다.
# 이스케이프를 한 글자라도 틀리면 중앙이 파싱에 실패해 전송이 통째로 죽는다. jq 출력과 대조한다.
printf "\n[에이전트 JSON]\n"
if bash "$ROOT/tests/agent_json_test.sh" >/dev/null 2>&1; then
  ok "awk JSON 빌더 = jq 출력 (jq 없이도 동일)"
else
  no "awk JSON 빌더  (자세히: bash tests/agent_json_test.sh)"
fi

# --- 에이전트 패키지 출처 -----------------------------------------------------
# 출처를 잘못 찍으면 중앙이 서드파티로 보고 "자동 판정 불가" 로 남긴다 — 억제도 조치 가능 여부도
# 못 붙는다. 보안 업데이트에 뒤처진 데비안 패키지를 LOCAL(수동 설치)로 읽던 버그를 고정한다.
if bash "$ROOT/tests/agent_origin_test.sh" >/dev/null 2>&1; then
  ok "패키지 출처 판정 (뒤처진 배포판 패키지 ≠ 수동 설치)"
else
  no "패키지 출처 판정  (자세히: bash tests/agent_origin_test.sh)"
fi

# --- 에이전트 방화벽 노출 판정 -------------------------------------------------
# nft/iptables 파서가 틀리면 **외부 노출을 조용히 감춘다**(EXTERNAL 이어야 할 포트를 FILTERED 로).
# 원칙은 "확신이 있을 때만 강등" 이다 — policy drop 을 확인 못 하거나 하위 체인 jump 로 accept 를
# 따라갈 수 없으면 강등하지 않아야 한다. 그 경계를 22개 케이스로 고정한다.
if bash "$ROOT/tests/fw_detect_test.sh" >/dev/null 2>&1; then
  ok "방화벽 노출 판정 (nft·iptables 파서, 확신 없으면 강등 안 함)"
else
  no "방화벽 노출 판정  (자세히: bash tests/fw_detect_test.sh)"
fi

# --- ssg 단위 테스트 ----------------------------------------------------------
# 보안설정 점검(CCE)을 검증된 룰셋(SCAP Security Guide)에 묶는다. 매핑에 오타가 나면 조용히
# "자체 기준" 으로 떨어져 근거가 사라진다. 파서도 Jinja 섞인 실제 형식으로 고정한다.
run_phpunit "ssg_test.php" "ssg" "ssg 단위 테스트 (룰 파싱 · CIS/NIST 매핑)" "ssg 단위 테스트"

# --- CCE 신규 룰 단위 테스트 ---------------------------------------------------
# 시간동기화·로그설정·암호화 룰. 가장 중요한 계약은 "수집값이 없으면 PASS 가 아니라 NA" 다 —
# 비-root 실행에서 조용히 PASS 가 되면 점검을 안 한 서버가 통과한 것처럼 보인다.
run_phpunit "cce_new_rules_test.php" "cce_new_rules" "CCE 신규 룰 단위 테스트 (시간·로그·암호화)" "CCE 신규 룰 단위 테스트"

# --- rhunfixed 단위 테스트 ----------------------------------------------------
# Red Hat 미수정 CVE(조치 불가) 판정. 컴포넌트 매핑이나 릴리스 매칭이 틀리면 조용히 미탐이 된다
# (바이너리 이름으로 물으면 API 가 0건을 주고, "Linux 1" 이 "Linux 10" 에 걸리면 남의 상태를 쓴다).
run_phpunit "rhunfixed_test.php" "rhunfixed" "rhunfixed 단위 테스트 (컴포넌트·릴리스 판정)" "rhunfixed 단위 테스트"

# --- rpmdb 단위 테스트 --------------------------------------------------------
# 컨테이너의 rpm DB 를 중앙이 파싱한다 — 컨테이너에 rpm 바이너리가 없고 호스트에도 rpm 이 없으면
# 이 경로 말고는 그 패키지를 볼 방법이 아예 없다. 파서가 틀리면 통째로 사라진다(미탐).
run_phpunit "rpmdb_test.php" "rpmdb" "rpmdb 단위 테스트 (rpm 헤더 파싱)" "rpmdb 단위 테스트"

# --- distro 단위 테스트 -------------------------------------------------------
# 패키지 출처·커널 판정(server/src/distro.php). 판정 하나가 findings 수천 건을 좌우한다 —
# 커널 소스에서 나온 헤더·메타패키지 21개에 커널 CVE 369건이 곱해져 LOW 7,925건이 뜬 적이 있다.
run_phpunit "distro_test.php" "distro" "distro 단위 테스트 (출처·커널 판정)" "distro 단위 테스트"

# 수집 주기가 길어도 10초 poll 이 살아 있으면 자산 연결 상태는 정상이어야 한다.
run_phpunit "asset_state_test.php" "asset_state" "자산 연결 상태 단위 테스트 (poll·수집 주기 분리)" "자산 연결 상태 단위 테스트"

# 자산 등급 초안은 scope·역할별 근거를 과장하지 않고 사람 확정값과 격리해야 한다.
run_phpunit "assetgrade_test.php" "assetgrade" "자산 등급 초안 분류 단위 테스트 (scope·역할·근거 격리)"

printf "\n[file_to_pkg_cache]\n"
if bash "$ROOT/tests/file_to_pkg_cache_test.sh"; then
  ok "런타임 파일→패키지 조회를 서브셸 간 1회로 캐시"
else
  no "런타임 파일→패키지 조회 캐시 회귀"
fi

printf "\n[go_deps_extract]\n"
if bash "$ROOT/tests/go_deps_extract_test.sh"; then
  ok "대형 Go 바이너리 의존성 고속 추출"
else
  no "Go 바이너리 의존성 추출 회귀"
fi

# 위가 고정 픽스처(strings 파싱)라면 이건 **진짜 Go 바이너리**로 도는 e2e 다 — Go 툴체인이 필요해
# Windows 개발머신에서는 못 돈다. 그래서 테스트 머리주석이 적어 둔 대로 golang 이미지 안에서 돌린다
# (마운트 방식은 위 prerun_phpunit 과 같다). 이미지가 없으면 수백 MB 를 몰래 받지 않고 건너뛴다.
printf "\n[go_buildinfo_host]\n"
if ! command -v docker >/dev/null 2>&1 || ! docker image inspect golang:1.22 >/dev/null 2>&1; then
  sk "호스트 Go buildinfo e2e 건너뜀 (golang:1.22 이미지 없음 — docker pull golang:1.22)"
else
  MSYS_NO_PATHCONV=1 docker run --rm -v "$(cd "$ROOT" && { pwd -W 2>/dev/null || pwd; }):/w" \
    -w /w golang:1.22 bash tests/go_buildinfo_host_test.sh >/dev/null 2>&1
  gbi=$?
  if [ "$gbi" -eq 0 ]; then
    ok "호스트 Go 바이너리 buildinfo 수집 (실제 빌드 바이너리 e2e)"
  elif [ "$gbi" -eq 3 ]; then
    # 테스트 자신의 SKIP 종료코드 — go build 가 네트워크 없이 모듈을 못 받은 경우다(회귀가 아니다).
    sk "호스트 Go buildinfo e2e 건너뜀 (테스트가 SKIP — go build 실패, 네트워크?)"
  else
    no "호스트 Go buildinfo 수집 회귀  (자세히: MSYS_NO_PATHCONV=1 docker run --rm -v \"\$(pwd -W):/w\" -w /w golang:1.22 bash tests/go_buildinfo_host_test.sh)"
  fi
fi

printf "\n[project_deps_parser]\n"
if bash "$ROOT/tests/project_deps_parser_test.sh"; then
  ok "go.mod·requirements.txt·pom.xml 파서 (exclusions·scope·--hash 배제)"
else
  no "프로젝트 선언 파일 파서 회귀"
fi

printf "\n[ruby_deps_parser]\n"
if bash "$ROOT/tests/ruby_deps_parser_test.sh"; then
  ok "Gemfile.lock·vendored gemspec 파서 (6칸 제약·PATH/GIT 배제, 플랫폼 접미사)"
else
  no "Ruby 의존성 파서 회귀"
fi

printf "\n[node_python_locks]\n"
if bash "$ROOT/tests/node_python_locks_test.sh"; then
  ok "yarn(v1/v2+)·pnpm·poetry·Pipfile·egg-info 파서 (스코프 이름·범위 유출)"
else
  no "Node/Python 보조 lock 파서 회귀"
fi

# --- debtracker 단위 테스트 ---------------------------------------------------
# 데비안 보안 트래커 파서·판정(백포트 억제 근거). 느슨하면 오탐이 남고, 빡빡하면 진짜 취약점을
# "고쳐졌다"고 지운다(미탐). 규칙을 debsecan 원본과 대조해 옮겼으므로 회귀를 여기서 막는다.
run_phpunit "debtracker_test.php" "debtracker" "debtracker 단위 테스트 (데비안 백포트 판정)" "debtracker 단위 테스트"

# --- rhoval 단위 테스트 -------------------------------------------------------
# RHEL 계열 OVAL 파서·백포트 판정. 같은 (패키지,CVE)가 마이너 스트림마다 다른 EVR 로 고쳐지는데
# (el9_2 · el9_4), 스트림을 잘못 고르면 오탐(안 지움) 또는 미탐(잘못 지움)이 난다.
run_phpunit "rhoval_test.php" "rhoval" "rhoval 단위 테스트 (OVAL 파싱·스트림 판정)" "rhoval 단위 테스트"

# --- ubuntuoval 단위 테스트 ---------------------------------------------------
# 우분투 OVAL 한 파일이 억제(조치 EVR)와 조치 불가(state 없는 테스트)를 동시에 만든다.
# state 없는 테스트를 버리면 "아직 수정본 없음" 이 통째로 미탐이 된다 — 그걸 고정한다.
run_phpunit "ubuntuoval_test.php" "ubuntuoval" "ubuntuoval 단위 테스트 (조치 EVR · 미수정 CVE · 코드명)" "ubuntuoval 단위 테스트"

# --- kernelcve 단위 테스트 ----------------------------------------------------
# 커널은 배포판이 아니라 업스트림(kernel.org CNA)이 판정한다. 스트림(6.1.y·6.18.y)을 잘못 고르면
# 다른 스트림의 수정본을 내 것으로 읽어 진짜 커널 취약점을 조용히 지운다(미탐).
run_phpunit "kernelcve_test.php" "kernelcve" "kernelcve 단위 테스트 (CNA 파싱 · 스트림 판정 · tar 스캔)" "kernelcve 단위 테스트"

# --- schedule 단위 테스트 -----------------------------------------------------
# feeds.php 의 cron 파싱·스케줄 계산(vg_cron_*/vg_schedule_*)을 server/src/schedule.php 로
# 뽑아냈다 — 피드 실행과 무관한 순수 시간 계산이라 SRP 상 분리. ingest_parse 처럼 서버 없이
# 도는 정적 검사라 스모크 앞단에 묶는다.
run_phpunit "schedule_test.php" "schedule" "schedule 단위 테스트"

# --- UI 설정·감사 마스킹 단위 테스트 -----------------------------------------
run_phpunit "ui_config_test.php" "ui_config" "UI 설정 범위·감사정보 마스킹 단위 테스트"
run_phpunit "asset_grade_review_test.php" "asset_grade_review" "자산 등급 구조화 검토 단위 테스트"

# --- UI 공통 구조 회귀 테스트 -----------------------------------------------
run_phpunit "ui_structure_test.php" "ui_structure" "UI 공통 컴포넌트·검색·인라인 이벤트 회귀 테스트"
run_phpunit "documentation_consistency_test.php" "documentation_consistency" "DB 명세·ERD·사이트맵 문서 일관성 테스트"
run_phpunit "route_query_contract_test.php" "route_query_contract" "public route·query·redirect 계약 테스트"
run_phpunit "agent_api_contract_test.php" "agent_api_contract" "설치 에이전트 poll·progress·ingest 계약 테스트"
run_phpunit "update_order_contract_test.php" "update_order_contract" "운영 staged migration·live source 전환 순서 계약 테스트"

# --- 범용 API 지원 역할 회귀 테스트 -----------------------------------------
run_phpunit "generic_api_config_test.php" "generic_api_config" "범용 API 지원 역할 단위 테스트"

# --- 취약점 판정 출처·구조화 근거 회귀 테스트 -------------------------------
run_phpunit "finding_evidence_test.php" "finding_evidence" "취약점 판정 출처 단위 테스트"

# --- DB 재시도 단위 테스트 ----------------------------------------------------
# 접속 실패(2002)·교착(1213) 재시도 판정과 vg_with_tx 의 재시도 흐름(server/src/db.php).
# 판정이 넓어지면 인증 실패·DB 없음에도 매달려 배포가 늦고, 좁아지면 DB 재시작 때 스케줄러
# 실행이 통째로 유실된다(운영 실측 2026-07-26). 재시도가 남의 트랜잭션까지 다시 돌리면
# 반쪽 커밋이 되므로 "소유할 때만 재시도" 안전조건도 여기서 잠근다.
run_phpunit "db_retry_test.php" "db_retry" "DB 접속·교착 재시도 단위 테스트"

# --- 수신 API ---------------------------------------------------------------
printf "\n[ingest]\n"
code=$(curl_i -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ingest.php" \
  -H 'X-Agent-Token: WRONG' --data-binary @"$SAMPLE")
assert_eq "$code" "401" "잘못된 토큰 → 401"
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE")
assert_contains "$resp" '"ok":true' "정상 토큰 → ok:true"
assert_contains "$resp" '"packages":7' "패키지 7건 저장"
assert_contains "$resp" '"exposures":5' "노출 5건 저장"
# 언어 패키지(pip 2 + npm 2) — 예전엔 수집만 하고 서버가 버렸다.
assert_contains "$resp" '"langpkgs":4' "언어 패키지 4건 저장(pip/npm)"
# 컨테이너 내부 패키지 — 호스트 스캔에서 빠져 통째로 미탐이던 영역.
assert_contains "$resp" '"containers":5'   "컨테이너 5개 저장(apk/dpkg/DB없음/Go/업스트림)"
#   5건(apk 2 + dpkg 1 + Go 1 + 업스트림 nginx 1) + api 컨테이너 SBOM 컴포넌트 3건 = 8건.
#   SBOM 은 의존성 그래프 화면(depgraph.php)의 회귀 근거라 픽스처에 함께 들어 있다.
assert_contains "$resp" '"ctr_packages":8' "컨테이너 내부 패키지 8건(apk/dpkg + Go + 업스트림 nginx + SBOM 3)"
# 컨테이너 런타임 증거 — 이게 없으면 컨테이너 취약점은 근거가 "설치만 됨" 뿐이라 전부 LOW 로 깔린다.
assert_contains "$resp" '"ctr_processes":2' "컨테이너 프로세스 2건 저장"
assert_contains "$resp" '"ctr_exposures":1' "컨테이너 노출 1건 저장(api:8443 EXTERNAL)"
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

# CCE(보안설정) — KISA U-XX + 시간동기화·로그·암호화 항목. 수집값이 다 있으면 판정돼야 한다.
#   NA 가 생기면 "정상"을 "판정 불가"로 표시하는 것이라 운영자가 안심할 수 없다.
#   예외는 CCE-CRYPTO-KCMVP 하나뿐 — 검증필 암호모듈(N2SF EA-1)은 알고리즘 목록만으로 준수를
#   단정할 수 없어 **의도적으로** 정보성(NA)이다. 그래서 상한이 0 이 아니라 1 이고, 2 가 되면
#   다른 룰이 판정을 놓친 것이라 잡힌다.
ccePass=$(printf '%s' "$resp" | grep -oE '"cce":\{"PASS":[0-9]+' | grep -oE '[0-9]+$')
cceFail=$(printf '%s' "$resp" | grep -oE '"FAIL":[0-9]+' | tail -1 | grep -oE '[0-9]+$')
cceNa=$(printf '%s' "$resp"   | grep -oE '"NA":[0-9]+'   | tail -1 | grep -oE '[0-9]+$')
cceTotal=$(( ${ccePass:-0} + ${cceFail:-0} + ${cceNa:-0} ))
if [ "$cceTotal" -ge 39 ]; then ok "CCE 39개 항목 판정 (총 $cceTotal)"; else no "CCE 항목 부족 (=$cceTotal)"; fi
if [ "${cceNa:-9}" -le 1 ]; then ok "CCE NA ≤1 (정보성 KCMVP 외에는 전부 판정) = ${cceNa:-?}"; else no "CCE NA=$cceNa (정상을 판정불가로 표시?)"; fi
if [ "${cceFail:-0}" -ge 5 ]; then ok "CCE FAIL 검출 (shadow 640·hosts 644·MaxAuthTries 6 등) = $cceFail"; else no "CCE FAIL 미검출 (=${cceFail:-0})"; fi

# --- 데비안 호스트: debsecan 기반 백포트 억제 --------------------------------
#   web02(Debian 12)의 curl·openssl 은 둘 다 조치 버전보다 낮아 "버전만 보면" 취약하다.
#   debsecan(데비안 보안 트래커)이 curl 만 지목했다 → openssl 은 백포트로 이미 고쳐진 것(억제).
printf "\n[debsecan · 데비안 백포트 억제]\n"
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN_DEB" \
  --data-binary @"$SAMPLE_DEB")
assert_contains "$resp" '"ok":true' "데비안 호스트 수집 → ok:true"
assert_contains "$resp" '"debsecan":1' "debsecan 판정 1건 저장"
dlow=$(printf '%s' "$resp" | grep -oE '"LOW":[0-9]+' | grep -oE '[0-9]+$')
if [ "${dlow:-0}" -ge 1 ]; then ok "curl 은 취약 유지 (debsecan 이 지목) = $dlow"; else no "curl 이 사라짐(과잉 억제?)"; fi
dsupp=$(printf '%s' "$resp" | grep -oE '"SUPPRESSED":[0-9]+' | grep -oE '[0-9]+$')
if [ "${dsupp:-0}" -ge 1 ]; then ok "openssl 억제 (debsecan 미지목 → 백포트) = $dsupp"; else no "억제 안 됨 (=${dsupp:-0})"; fi
# 서드파티 저장소(nginx.org) 패키지는 배포판 기준으로 판정할 수 없다 → 억제하지 않고 남긴다.
#   버전만 보면 "설치 1.24.0 ≥ 조치 1.22.1" 이라 억제될 뻔했고, debsecan 목록에도 없어
#   "백포트로 수정됨" 으로도 억제될 뻔했다. 둘 다 미탐이다.
#   **억제 건수로 판정하지 않는다** — 그건 DB 에 실제 피드 데이터가 들어오면 바로 깨진다
#   (dev DB 가 공용이 된 뒤 실측으로 깨졌다: 기대 1건 vs 실제 72건).
#   억제 목록에 nginx 가 있는지를 직접 본다. 그게 이 테스트가 진짜 지키려는 것이다.
# 억제 목록의 nginx 검사는 로그인 세션이 준비된 뒤 web auth 구간에서 수행한다.
# 여기서 $JAR 를 쓰면 set -u 아래에서 로그인 전 미정의 변수로 중단된다.

# --- 바뀔 때만 스냅샷 --------------------------------------------------------
#   같은 내용을 다시 보내면 새 스캔을 만들지 않는다(수집시각만 갱신). 패키지가 바뀌면 새 스냅샷 +
#   변경이력. 매시간 수집이 대부분 "직전과 동일"이라 이게 없으면 데이터가 무한히 불어난다.
printf "\n[변경 추적]\n"
docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("UPDATE tb_host SET grade=\"C\" WHERE fqdn=?"); $s->execute([$argv[1]]);' "$FQDN_WEB01"
run_count_before=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COUNT(*) FROM tb_scan_run r JOIN tb_host h ON h.host_id=r.host_id WHERE h.fqdn=?");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
grade_history_before=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COUNT(*) FROM tb_asset_grade_suggestion_history g JOIN tb_host h ON h.host_id=g.host_id WHERE h.fqdn=?");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
confirmed_grade_before=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COALESCE(grade, \"NULL\") FROM tb_host WHERE fqdn=?");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE")
assert_contains "$resp" '"changed":false' "동일 내용 재전송 → 새 스냅샷 안 만듦"
run_count_after=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COUNT(*) FROM tb_scan_run r JOIN tb_host h ON h.host_id=r.host_id WHERE h.fqdn=?");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
assert_eq "$run_count_after" "$((run_count_before + 1))" "동일 내용이어도 수집 실행 이력 1건 누적"
grade_history_after=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COUNT(*) FROM tb_asset_grade_suggestion_history g JOIN tb_host h ON h.host_id=g.host_id WHERE h.fqdn=?");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
confirmed_grade_after=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COALESCE(grade, \"NULL\") FROM tb_host WHERE fqdn=?");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
if [ "$grade_history_before" -ge 1 ]; then ok "시스템 등급 제안 관찰 이력 생성"; else no "시스템 등급 제안 관찰 이력 없음"; fi
assert_eq "$grade_history_after" "$grade_history_before" "동일 scan·결과 replay는 제안 이력 중복 없음"
assert_eq "$confirmed_grade_after" "$confirmed_grade_before" "ingest 제안 관찰은 사람 확정 grade를 변경하지 않음"
# #542 후속: replay 는 행 대신 마지막 관찰 시각을 갱신하고, effective_at 은 신선도 클램프 안에 있다.
grade_history_invalid=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->query("SELECT COUNT(*) FROM tb_asset_grade_suggestion_history
     WHERE last_observed_at < observed_at
        OR effective_at > last_observed_at
        OR effective_at < DATE_SUB(last_observed_at, INTERVAL 7 DAY)");
   echo $s->fetchColumn();')
assert_eq "$grade_history_invalid" "0" "제안 이력의 마지막 관찰 시각·신선도 클램프 불변식 유지"
grade_replayed=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $s=vg_pdo()->prepare("SELECT COUNT(*) FROM tb_asset_grade_suggestion_history g
     JOIN tb_host h ON h.host_id=g.host_id WHERE h.fqdn=? AND g.last_observed_at >= g.observed_at");
   $s->execute([$argv[1]]); echo $s->fetchColumn();' "$FQDN_WEB01")
assert_eq "$grade_replayed" "$grade_history_after" "replay 는 행을 늘리지 않고 마지막 관찰 시각만 앞으로 간다"

UPG="$(mktemp)"; sed 's/0:2.34-60.el9_2.3/0:2.34-83.el9_3.7/' "$SAMPLE" > "$UPG"
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$UPG")
assert_contains "$resp" '"changed":true'  "glibc 업그레이드 → 새 스냅샷"
assert_contains "$resp" '"pkg_changes":1' "패키지 변경 1건 기록"
rm -f "$UPG"
# 되돌려 놓는다(뒤의 검사들이 원래 샘플 기준이라 상태를 원복해야 한다).
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN" --data-binary @"$SAMPLE")
SCAN_ID=$(printf '%s' "$resp" | grep -oE '"scan_id":[0-9]+' | grep -oE '[0-9]+$')

# --- 피드 미지원 배포판: 0건이 "안전"이 아니라 "판정 불가" -------------------
#   Amazon Linux 는 OSV 생태계 목록에 없다(질의하면 INVALID_ARGUMENT). 매칭 후보가 아예 없어
#   취약점이 0건으로 뜨는데, 운영자가 "안전하다"고 읽으면 침묵하는 미탐이 된다 → 명시적으로 알린다.
printf "\n[미지원 배포판 경고]\n"
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $TOKEN_AMZN" \
  --data-binary @"$SAMPLE_AMZN")
assert_contains "$resp" '"ok":true' "Amazon Linux 호스트 수집 → ok:true"
assert_contains "$resp" 'ALAS' "ingest 응답에 미지원 경고(자체 ALAS 피드 필요)"

# 공개 강제 재매칭 API는 제공하지 않는다. 피드·수집 경로가 필요한 스캔을 내부에서 직접 재매칭한다.
printf "\n[removed endpoint]\n"
code=$(curl_i -s -o /dev/null -w '%{http_code}' "$BASE/rematch.php")
assert_eq "$code" "404" "폐기된 공개 재매칭 API → 404"

# --- 웹 인증 흐름 -----------------------------------------------------------
printf "\n[web auth]\n"
JAR="$(mktemp)"   # 정리는 위 trap 이 샘플 사본과 함께 맡는다.
code=$(curl_ -s -o /dev/null -w '%{http_code}' "$BASE/")
assert_eq "$code" "302" "미인증 대시보드 → 302(로그인 리다이렉트)"

csrf=$(curl_ -s -c "$JAR" "$BASE/login.php" | grep -oE 'name="csrf" value="[a-f0-9]+"' | grep -oE '[a-f0-9]{32}')
if [ -n "$csrf" ]; then ok "로그인 폼 CSRF 토큰 취득"; else no "CSRF 토큰 없음"; fi

code=$(curl_ -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' \
  --data-urlencode "csrf=$csrf" --data-urlencode "username=$SMOKE_USER" --data-urlencode "password=$ADMPW" \
  "$BASE/login.php")
assert_eq "$code" "302" "올바른 로그인 → 302(대시보드)"

body=$(curl_ -s -b "$JAR" "$BASE/")
assert_contains "$body" "대시보드" "대시보드 접근(인증됨)"
assert_not_contains "$body" "/remediations.php" "대시보드·메뉴에 조치관리 링크 없음"
code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/remediations.php")
assert_eq "$code" "404" "조치관리 페이지 제거"
code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/findings.php")
assert_eq "$code" "200" "취약점 페이지 200"
code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/users.php")
assert_eq "$code" "200" "사용자 페이지 200(관리자 권한)"

code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/connectors.php")
assert_eq "$code" "200" "데이터 수집 페이지 200(관리자 권한)"
code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/advisories.php")
assert_eq "$code" "200" "보안 공지 페이지 200"

# --- Export·SBOM: API 토큰 폐지 → 로그인 세션 인증 --------------------------
#   전용 읽기 토큰(X-API-Token)과 발급 화면을 없앴다. 기능은 남기고 인증만 세션으로 옮겼으므로
#   "미로그인은 로그인으로 튀고, 로그인하면 그대로 받아진다" 두 방향을 다 본다.
printf "\n[export/sbom 세션 인증]\n"
code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/api-tokens.php")
assert_eq "$code" "404" "API 키 화면 제거"
body=$(curl_ -s -b "$JAR" "$BASE/permissions.php")
assert_not_contains "$body" "API 키" "권한 매트릭스에 API 키 행 없음"
assert_contains "$body" "컴플라이언스" "권한 매트릭스에 컴플라이언스 메뉴 행"
assert_contains "$body" "참조 카탈로그" "권한 매트릭스에 참조 카탈로그 메뉴 행"
code=$(curl_ -s -o /dev/null -w '%{http_code}' "$BASE/export.php")
assert_eq "$code" "302" "미인증 export → 302(로그인 리다이렉트)"
code=$(curl_ -s -o /dev/null -w '%{http_code}' "$BASE/sbom.php?host=$FQDN_WEB01")
assert_eq "$code" "302" "미인증 sbom → 302(로그인 리다이렉트)"
exportbody=$(curl_ -s -b "$JAR" "$BASE/export.php?format=json&host=$FQDN_WEB01")
assert_contains "$exportbody" '"ok": true' "로그인 세션으로 export JSON 수신"
sbombody=$(curl_ -s -b "$JAR" "$BASE/sbom.php?host=$FQDN_WEB01&format=cyclonedx")
assert_contains "$sbombody" '"bomFormat": "CycloneDX"' "로그인 세션으로 SBOM(CycloneDX) 수신"

# --- 컴플라이언스 매핑 ------------------------------------------------------
printf "\n[compliance]\n"
code=$(curl_ -s -o /dev/null -w '%{http_code}' "$BASE/compliance.php")
assert_eq "$code" "302" "미인증 컴플라이언스 매핑 → 302(로그인 리다이렉트)"
compliancebody=$(curl_ -s -b "$JAR" "$BASE/compliance.php")
assert_contains "$compliancebody" "컴플라이언스 매핑" "컴플라이언스 매핑 페이지 200(인증됨)"
assert_contains "$compliancebody" "ISMS-P 2.10.8" "패치관리 통제(ISMS-P 2.10.8) 표시"
assert_contains "$compliancebody" "ISO 27001 A.5.9" "자산식별 통제(ISO 27001 A.5.9) 표시"
# 문구가 "수동 확인 필요(자동판정 불가)" 에서 바뀌었다 — 제품이 못 해서 빠진 것처럼 읽혀서다.
#   검사하는 사실은 그대로다: 증적이 제품 밖에 있는 항목은 판정 없이 목록으로만 노출된다.
assert_contains "$compliancebody" "정책·절차 문서 심사" "자동판정 대상이 아닌 항목은 체크리스트로만 노출"
assert_contains "$compliancebody" "통제 종" "판정 결론(통제 종 수)이 첫 화면에 집계된다"
# 호스트 id 를 하드코딩(=1)하면 빈 볼륨에서만 통과한다. 스택·DB 를 재사용하면 auto_increment 가
# 밀려(삭제·재등록) id 가 6,7,11 처럼 바뀌고, 그때부터 아래 검사가 전부 "호스트 없음" 을 본다.
# 자산 목록에서 web01 의 실제 id 를 찾아 쓴다 — 데이터가 어디서 시작하든 무관하게.
WEB01_ID=$(curl_ -s -b "$JAR" "$BASE/assets.php?q=$FQDN_WEB01" | grep -oE 'host\.php\?id=[0-9]+' | head -1 | grep -oE '[0-9]+')
if [ -n "$WEB01_ID" ]; then
  ok "web01 호스트 id 확인 (=$WEB01_ID)"
else
  no "web01 호스트를 자산 목록에서 못 찾음"
  WEB01_ID=1
fi
# 공용 dev DB 의 목록 첫 페이지에 기대지 않도록 이 실행이 만든 호스트 ID를 모두 고정한다.
WEB02_ID=$(curl_ -s -b "$JAR" "$BASE/assets.php?q=$FQDN_WEB02" | grep -oE 'host\.php\?id=[0-9]+' | head -1 | grep -oE '[0-9]+')
WEB03_ID=$(curl_ -s -b "$JAR" "$BASE/assets.php?q=$FQDN_WEB03" | grep -oE 'host\.php\?id=[0-9]+' | head -1 | grep -oE '[0-9]+')
assetbody=$(curl_ -s -b "$JAR" "$BASE/assets.php?q=$FQDN_WEB01")
assert_not_contains "$assetbody" 'host_delete' "자산 목록에 삭제 작업 없음"
assetpkgsearch=$(curl_ -s -b "$JAR" "$BASE/assets.php?q=glibc")
assert_contains "$assetpkgsearch" 'host.php?id=' "자산 목록에서 설치 패키지명으로 호스트 검색"
assert_contains "$assetbody" 'class="on" href="/assets.php">자산 목록' "자산 목록 탭 활성 표시"
assert_contains "$assetbody" 'href="/asset-packages.php">전체 설치 패키지' "자산 목록에 전체 설치 패키지 탭 표시"
allpackages=$(curl_ -s -b "$JAR" "$BASE/asset-packages.php?q=glibc")
assert_contains "$allpackages" '실제 서버 설치 현황' "전체 설치 패키지 화면이 취약 패키지 카탈로그와 구분됨"
assert_contains "$allpackages" 'class="on" href="/asset-packages.php">전체 설치 패키지' "전체 설치 패키지 탭 활성 표시"
assert_contains "$allpackages" 'glibc' "전체 호스트 설치 패키지 검색 결과 표시"
assert_contains "$allpackages" "$FQDN_WEB01" "설치 패키지 검색 결과에 호스트 표시"
# 변화 추적 — 사이드바에 올린 화면인데 스모크가 한 번도 치지 않아, 패키지 셀이 부르는
#   vg_osv_ecosystem() 의 require 누락(distro.php)이 Fatal error 로 오래 남아 있었다.
#   목록에 행이 있어야 그 코드 경로를 지나므로, 응답 본문에 표가 렌더됐는지까지 본다.
changesbody=$(curl_ -s -b "$JAR" "$BASE/changes.php")
assert_not_contains "$changesbody" 'Fatal error' "변화 추적 화면이 오류 없이 렌더됨"
assert_contains "$changesbody" '변화 추적' "변화 추적 화면 제목 표시"
catalogpackages=$(curl_ -s -b "$JAR" "$BASE/packages.php?q=glibc")
assert_contains "$catalogpackages" '/package.php?name=glibc' "취약 영향 패키지가 패키지 상세에 연결"
packageurl=$(grep -oE '/package.php\?name=glibc[^" ]*' <<<"$catalogpackages" | head -1 | sed 's/&amp;/\&/g')
packagedetail=$(curl_ -s -b "$JAR" "$BASE$packageurl")
assert_contains "$packagedetail" 'CVE-2023-4911' "패키지 상세에서 관련 CVE 조회"

# --- 패키지 화면 서브탭(os/lang) ---------------------------------------------
#   language-packages.php 는 packages.php 의 언어 탭으로 흡수됐다 — 옛 링크는 쿼리스트링을
#   유지한 채 302 리다이렉트돼야 하고, 잘못된 tab 값은 조용히 OS 탭으로 떨어져야 한다.
printf "\n[패키지 서브탭]\n"
langredirect=$(curl_ -s -o /dev/null -w '%{http_code} %{redirect_url}' "$BASE/language-packages.php?q=test")
assert_contains "$langredirect" '302' "옛 언어 패키지 화면 → 302 리다이렉트"
assert_contains "$langredirect" 'tab=lang' "리다이렉트가 언어 탭으로 이동"
assert_contains "$langredirect" 'q=test' "리다이렉트가 기존 쿼리스트링(q) 유지"
langtabbody=$(curl_ -s -b "$JAR" "$BASE/packages.php?tab=lang")
assert_contains "$langtabbody" "언어 패키지" "언어 탭 응답에 언어 패키지·라이선스 문구 포함"
badtabbody=$(curl_ -s -b "$JAR" "$BASE/packages.php?tab=zzz")
assert_contains "$badtabbody" 'class="on" href="?tab=os">OS 패키지' "잘못된 tab 값은 OS 탭으로 안전하게 폴백"
# 설정류(수집 제어·자산 등급·자산 삭제)는 '자산 설정' 탭(?tab=manage)으로 내려갔다 —
#   자산 상세의 첫 화면은 "이 서버가 얼마나 위험한가" 여야 한다. 기능은 그대로 살아 있다.
hostmanage=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=manage")
assert_contains "$hostmanage" 'name="action" value="host_delete"' "자산 설정 탭에 관리자 삭제 작업 표시"
assert_contains "$hostmanage" 'name="action" value="agent_run_now"' "자산 설정 탭에 수집 즉시 실행 유지"
assert_contains "$hostmanage" 'name="action" value="agent_set_schedule"' "자산 설정 탭에 수집 주기 변경 유지"
assert_contains "$hostmanage" 'name="action" value="host_set_grade"' "자산 설정 탭에 자산 등급 확정 유지"
hostvuln=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID")
assert_not_contains "$hostvuln" 'name="action" value="agent_run_now"' "첫 화면(취약점 탭)엔 수집 설정 폼이 없다"
assert_contains "$hostvuln" 'tab=manage' "첫 화면에서 자산 설정 탭으로 갈 수 있다"
assert_contains "$assetbody" "host.php?id=$WEB01_ID&amp;tab=packages" "자산 목록 패키지 수가 설치 패키지 탭에 연결"
# '노출'(리스닝 소켓 수) 열은 자산 목록에서 걷어냈다 — 개수로는 우선순위를 못 정하고,
#   범위(EXTERNAL/LAN/…)별 목록은 호스트 상세의 런타임 탭이 답한다. 그 탭 자체는 그대로 산다.
assert_not_contains "$assetbody" "host.php?id=$WEB01_ID&amp;tab=runtime" "자산 목록에 노출 수 열이 없다"
# '리소스' 탭은 '스캔 이력' 탭으로 흡수됐다 — 옛 URL 은 302 로 그 탭에 떨군다(북마크 보존).
resredir=$(curl_ -s -i -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=resources")
assert_contains "$resredir" "302" "옛 리소스 탭 URL 이 302 로 응답"
assert_contains "$resredir" "tab=scans" "옛 리소스 탭 URL 이 스캔 이력 탭으로 이동"
scansbody=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=scans")
assert_contains "$scansbody" "스캔 이력" "스캔 이력 탭 표시"
assert_contains "$scansbody" "에이전트 메모리 사용률" "스캔 이력 탭이 리소스 추이를 함께 보여준다"
assert_not_contains "$scansbody" 'href="?tab=resources"' "리소스 탭이 탭 줄에서 사라졌다"
packagebody=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=packages")
assert_contains "$packagebody" '설치 패키지' "자산 상세 설치 패키지 탭 표시"
assert_contains "$packagebody" 'glibc' "최신 스캔의 설치 패키지 전체 목록 조회"
if [ -n "$WEB02_ID" ]; then ok "web02 호스트 id 확인 (=$WEB02_ID)"; else no "web02 호스트를 자산 목록에서 못 찾음"; WEB02_ID=1; fi
if [ -n "$WEB03_ID" ]; then ok "web03 호스트 id 확인 (=$WEB03_ID)"; else no "web03 호스트를 자산 목록에서 못 찾음"; WEB03_ID=1; fi

# --- 패키지 의존성 그래프(depgraph.php) -------------------------------------
# 에이전트가 보낸 SBOM/pom 엣지는 저장만 되고 읽는 화면이 없었다. "무엇이 이 패키지를
#   끌어왔나" 가 루트 → 직접 → 전이 순으로 실제로 펼쳐지는지, 엣지가 없는 자산의 빈 상태가
#   빈 화면이 아니라 설명으로 뜨는지를 고정한다.
assert_contains "$packagebody" 'depgraph.php?id=' "설치 패키지 탭에서 의존성 그래프로 진입"
depbody=$(curl_ -s -b "$JAR" "$BASE/depgraph.php?id=$WEB01_ID")
assert_contains "$depbody" '무엇이 이 패키지를 끌어왔나' "의존성 그래프 화면 표시"
# 호스트(cid=0) 단위는 pom.xml 직접 선언 — 부모가 없어 트리 대신 목록으로 나온다.
assert_contains "$depbody" 'pom.xml 직접 선언' "pom.xml 직접선언이 별도 목록으로 구분됨"
assert_contains "$depbody" 'com.myco:myco-common' "pom 직접선언 패키지 표시"
# SBOM 엣지는 컨테이너 단위에 있다 — 조회 단위 링크에서 컨테이너 container_id 를 집는다.
DEP_CID=$(grep -oE 'depgraph\.php\?id='"$WEB01_ID"'&amp;cid=[0-9]+' <<<"$depbody" | grep -oE '[0-9]+$' | grep -v '^0$' | head -1)
if [ -n "$DEP_CID" ]; then ok "SBOM 엣지를 가진 컨테이너 조회 단위 노출 (cid=$DEP_CID)"; else no "SBOM 컨테이너 조회 단위를 못 찾음"; DEP_CID=0; fi
ctrdep=$(curl_ -s -b "$JAR" "$BASE/depgraph.php?id=$WEB01_ID&cid=$DEP_CID")
assert_contains "$ctrdep" '루트' "SBOM 루트 표식행이 루트로 표시됨"
assert_contains "$ctrdep" 'myco-web' "루트(최상위 프로젝트) 표시"
assert_contains "$ctrdep" 'myco-http' "직접 의존 표시"
assert_contains "$ctrdep" 'myco-utf8' "전이 의존(3단계)까지 펼쳐짐"
# 역추적 — 전이 의존에서 루트까지의 경로가 나와야 "무엇이 끌어왔나" 에 답이 된다.
frombody=$(curl_ -s -b "$JAR" "$BASE/depgraph.php?id=$WEB01_ID&cid=$DEP_CID&mgr=npm&name=myco-utf8&ver=0.9.1&tab=from")
assert_contains "$frombody" '이 패키지를 끌어온 경로' "역추적 탭 표시"
assert_contains "$frombody" 'myco-parser' "역추적 경로에 중간 부모 포함"
assert_contains "$frombody" 'myco-web' "역추적 경로가 루트까지 도달"
# 그래프에 없는 패키지를 지정하면 조용히 빈 화면이 아니라 이유를 밝혀야 한다.
missbody=$(curl_ -s -b "$JAR" "$BASE/depgraph.php?id=$WEB01_ID&cid=$DEP_CID&mgr=npm&name=nosuchpkg&ver=9.9.9&tab=from")
assert_contains "$missbody" '요청한 패키지가 이 조회 단위의 엣지에 없습니다' "없는 패키지 지정 시 이유 표시"
# 빈 상태 — SBOM·pom 이 없는 자산은 이 화면이 비는 것이 정상이고, 그렇게 설명해야 한다.
emptydep=$(curl_ -s -b "$JAR" "$BASE/depgraph.php?id=$WEB02_ID")
assert_contains "$emptydep" '의존성 엣지가 없습니다' "엣지 없는 자산의 빈 상태 안내"
assert_not_contains "$emptydep" 'depgraph.php?id='"$WEB02_ID"'&amp;cid=' "엣지 없는 자산엔 조회 단위 선택지도 없다"

# --- 컨테이너 드릴다운(container.php) + 컨테이너 SBOM ------------------------
# 컨테이너 안의 OS·패키지·프로세스·취약점은 처음부터 수집·저장되고 있었는데 읽는 화면이 없었다
#   (자산 상세의 패키지 탭은 container_id = 0 으로 고정이었다). 계층 카드 → 상세 → 탭 →
#   컨테이너 SBOM 까지 실제로 이어지는지, 그리고 범위가 호스트와 안 섞이는지를 고정한다.
printf "\n[컨테이너 드릴다운]\n"
ctrtab=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=containers")
assert_not_contains "$ctrtab" 'Fatal error' "컨테이너 탭이 오류 없이 렌더됨"
assert_contains "$ctrtab" 'class="ctree__root"' "컨테이너 탭이 호스트를 루트로 둔 계층으로 렌더"
assert_contains "$ctrtab" 'class="ctrcard' "컨테이너가 카드로 펼쳐짐"
assert_contains "$ctrtab" 'container.php?id='"$WEB01_ID" "카드에서 컨테이너 상세로 들어가는 링크"
CTR_CID=$(grep -oE 'container\.php\?id='"$WEB01_ID"'&amp;cid=[A-Za-z0-9._%-]+' <<<"$ctrtab" | head -1 | sed 's/.*cid=//')
if [ -n "$CTR_CID" ]; then ok "컨테이너 cid 확인 (=$CTR_CID)"; else no "컨테이너 카드에서 cid 를 못 찾음"; CTR_CID="api"; fi
ctrbody=$(curl_ -s -b "$JAR" "$BASE/container.php?id=$WEB01_ID&cid=$CTR_CID")
assert_not_contains "$ctrbody" 'Fatal error' "컨테이너 상세가 오류 없이 렌더됨"
assert_contains "$ctrbody" '최고 위험도' "컨테이너 상세 히어로(위험도) 표시"
assert_contains "$ctrbody" "host.php?id=$WEB01_ID&amp;tab=containers" "컨테이너 상세에 호스트로 돌아가는 브레드크럼"
ctrpkg=$(curl_ -s -b "$JAR" "$BASE/container.php?id=$WEB01_ID&cid=$CTR_CID&tab=packages")
assert_contains "$ctrpkg" '설치 패키지' "컨테이너 안 설치 패키지 탭 표시"
assert_not_contains "$ctrpkg" 'Fatal error' "컨테이너 패키지 탭이 오류 없이 렌더됨"
ctrrt=$(curl_ -s -b "$JAR" "$BASE/container.php?id=$WEB01_ID&cid=$CTR_CID&tab=runtime")
assert_contains "$ctrrt" '실행 프로세스' "컨테이너 런타임 탭 표시"
# 없는 컨테이너는 조용히 빈 화면이 아니라 이유를 밝힌다(호스트 화면으로 떨구지도 않는다).
missctr=$(curl_ -s -b "$JAR" "$BASE/container.php?id=$WEB01_ID&cid=nosuchctr")
assert_contains "$missctr" '최신 수집에 없습니다' "없는 컨테이너 지정 시 이유 표시"

# SBOM — 화면 링크(예전엔 sbom.php 를 링크하는 화면이 0건이었다) + 컨테이너 범위.
assert_contains "$hostvuln" 'sbom.php?host=' "자산 상세에 SBOM 내려받기 링크"
assert_contains "$ctrbody" 'cid='"$CTR_CID"'&amp;format=cyclonedx' "컨테이너 상세에 그 컨테이너 SBOM 링크"
ctrsbom=$(curl_ -s -b "$JAR" "$BASE/sbom.php?host=$FQDN_WEB01&cid=$CTR_CID&format=cyclonedx")
assert_contains "$ctrsbom" '"type": "container"' "컨테이너 SBOM 이 컨테이너를 대상으로 서술"
ctrspdx=$(curl_ -s -b "$JAR" "$BASE/sbom.php?host=$FQDN_WEB01&cid=$CTR_CID&format=spdx")
assert_contains "$ctrspdx" '"spdxVersion": "SPDX-2.3"' "컨테이너 SBOM(SPDX) 수신"
# 범위를 섞지 않는다 — 없는 컨테이너를 주면 호스트 SBOM 이 대신 나가면 안 된다(404).
code=$(curl_ -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/sbom.php?host=$FQDN_WEB01&cid=nosuchctr")
assert_eq "$code" "404" "없는 컨테이너 SBOM 은 호스트로 떨어지지 않고 404"

# 에이전트 진행 heartbeat — 바인딩 토큰이 자기 호스트의 pending 명령만 running으로 바꿔야 한다.
PROGRESS_CMD=$(docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   $p=vg_pdo(); $p->prepare("INSERT INTO tb_agent_command(host_id,created_by) VALUES(?,NULL)")->execute([(int)$argv[1]]);
   echo $p->lastInsertId();' "$WEB01_ID")
progress_resp=$(curl_ -s -X POST "$BASE/agent-progress.php" -H "X-Agent-Token: $TOKEN" \
  --data-urlencode "command_id=$PROGRESS_CMD" --data-urlencode "stage=patches" \
  --data-urlencode "percent=40" --data-urlencode "message=패치 상태 확인 중" --data-urlencode "state=running")
assert_contains "$progress_resp" '"ok":true' "에이전트 진행 heartbeat 인증·저장"
assert_contains "$progress_resp" '"cancel_requested":false' "취소 요청 전 진행 응답"
progress_status=$(curl_ -s -b "$JAR" "$BASE/agent-command-status.php?id=$WEB01_ID")
assert_contains "$progress_status" '"status":"running"' "진행 상태 API가 running 반환"
assert_contains "$progress_status" '"progress_percent":40' "진행 상태 API가 40% 반환"
progress_overview=$(curl_ -s -b "$JAR" "$BASE/agent-command-overview.php")
assert_contains "$progress_overview" '"active":' "전체 수집 현황 API가 활성 작업 집계"
assert_contains "$progress_overview" '"progress_percent":40' "전체 수집 현황 API가 전체 진행률 집계"
assert_contains "$progress_overview" "\"agent_command_id\":$PROGRESS_CMD" "전체 수집 현황 API가 실행 중인 자산 반환"
docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php"; require "/var/www/html/src/agentcommand.php";
   vg_agent_command_cancel(vg_pdo(), (int)$argv[1], (int)$argv[2], null);' \
  "$WEB01_ID" "$PROGRESS_CMD"
cancel_check=$(curl_ -s -X POST "$BASE/agent-progress.php" -H "X-Agent-Token: $TOKEN" \
  --data-urlencode "command_id=$PROGRESS_CMD" --data-urlencode "stage=patches" \
  --data-urlencode "percent=40" --data-urlencode "message=중단 확인" --data-urlencode "state=running")
assert_contains "$cancel_check" '"cancel_requested":true' "실행 중 수집에 취소 요청 전달"
cancel_done=$(curl_ -s -X POST "$BASE/agent-progress.php" -H "X-Agent-Token: $TOKEN" \
  --data-urlencode "command_id=$PROGRESS_CMD" --data-urlencode "stage=cancelled" \
  --data-urlencode "percent=100" --data-urlencode "message=사용자 요청으로 중단" --data-urlencode "state=cancelled")
assert_contains "$cancel_done" '"ok":true' "에이전트 취소 완료 저장"
cancel_status=$(curl_ -s -b "$JAR" "$BASE/agent-command-status.php?id=$WEB01_ID")
assert_contains "$cancel_status" '"status":"cancelled"' "진행 상태 API가 cancelled 반환"
docker exec "$WEB_CONTAINER" php -r \
  '$cfg=require "/var/www/html/src/config.php"; require "/var/www/html/src/db.php";
   vg_pdo()->prepare("DELETE FROM tb_agent_command WHERE agent_command_id=?")->execute([(int)$argv[1]]);' \
  "$PROGRESS_CMD" >/dev/null

# debsecan 억제 검사는 인증이 필요한 호스트 상세에서 확인한다.
supbody=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB02_ID&tab=suppressed")
if grep -q 'nginx' <<<"$supbody"; then
  no "서드파티 nginx 가 억제됨 — 미탐!"
else
  ok "서드파티 nginx 는 억제되지 않음(억제 목록에 없음)"
fi

body=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID")
assert_contains "$body" "최고 위험도" "호스트 상세(자산 식별 히어로 + 섹션 탭)"
# curl 은 조치 버전 이상이지만 nginx 가 옛 libcurl 을 물고 있다 → 억제 대신 "재시작 필요"로 남는다(기본=취약점 탭).
assert_contains "$body" "재시작 필요" "재시작 필요 근거 노출(패치됐지만 옛 라이브러리 사용 중)"
# 커널은 패치가 설치돼도 재부팅 전까지 옛 커널이 돈다 → 억제하지 않고 "재부팅"을 조치로 제시한다.
assert_contains "$body" "재부팅 필요" "커널 재부팅 필요 뱃지(설치 -503 / 실행 -427)"
assert_contains "$body" "재부팅</span>" "조치가 '재부팅' (프로세스 재시작으로는 안 고쳐진다)"
assert_contains "$body" 'data-finding-detail=' "취약점 행에 상세 데이터 연결"
assert_contains "$body" 'id="findingDetailModal"' "취약점 상세 모달 렌더링"
assert_contains "$body" 'data-finding-rationale' "상세 모달에 전체 판정 근거 영역 제공"
# 수집 단계 누락 — tb_collection_stage 는 스캔마다 5단계를 COMPLETE/EMPTY/MISSING 으로 남긴다.
#   MISSING("있어야 하는데 못 걷음")만 경고한다. EMPTY("정상적으로 없음")까지 경고하면 정상 호스트마다
#   경고가 떠서 아무도 안 보게 된다 — 위 CCE NA 와 같은 함정이라 두 방향을 다 고정한다.
#   web01 샘플은 5단계 전부 COMPLETE, web02(데비안) 샘플은 runtime_processes 만 MISSING 이고
#   컨테이너·언어 패키지·네트워크 노출은 EMPTY 다 — 샘플만으로 양쪽이 성립한다(새 수집 불필요).
if grep -q '수집하지 못했습니다' <<<"$body"; then
  no "전 단계 COMPLETE 인 호스트(web01)에 수집 실패 경고 — 오경고"
else
  ok "전 단계 COMPLETE 면 수집 실패 경고 없음(web01)"
fi
stagebody=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB02_ID")
assert_contains "$stagebody" "수집하지 못했습니다" "수집 못한 단계(MISSING)를 호스트 상세에 경고"
assert_contains "$stagebody" "수집 실패 — 실행 프로세스" "누락 단계를 한글 라벨로 지목"
if grep -q '수집 실패 — 컨테이너' <<<"$stagebody"; then
  no "EMPTY(컨테이너 없음)까지 수집 실패로 경고 — 정상을 실패로 표시"
else
  ok "EMPTY 단계(컨테이너·언어 패키지)는 경고하지 않음"
fi
body=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=runtime")
assert_contains "$body" "런타임 노출" "호스트 상세 · 런타임 탭(노출·프로세스)"
# 컨테이너의 프로세스·포트는 호스트 것과 섞이면 안 된다 — 어느 쪽인지 표에 드러나야 한다.
assert_contains "$body" "컨테이너 api" "런타임 탭이 컨테이너 출처를 구분해 표시"
# 재시작 필요(tb_stale_lib)는 **억제를 취소하는** 신호라 런타임 축에 자기 자리가 있어야 한다.
#   예전엔 이 표가 화면에 아예 없어서, 근거는 DB 에만 있고 사람은 못 봤다.
assert_contains "$body" "재시작 필요 (억제 취소 신호)" "런타임 탭에 재시작 필요 목록"
assert_contains "$body" "해당 서비스 재시작" "조치를 재시작으로 명시(업데이트로는 안 고쳐진다)"
# 같은 표의 0건이 "깨끗함"으로 읽히면 안 된다 — 프로세스를 못 걷은 호스트는 판정 불가다(NA ≠ PASS).
stalebody=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB02_ID&tab=runtime")
assert_contains "$stalebody" "재시작 필요 여부를 판정할 수 없습니다" "프로세스 미수집은 0건이 아니라 판정 불가"

# 억제 근거 노출 — CONTEXT.md §7 의 "근거는 숨기지 않는다" 가 화면에 실제로 있는지 본다.
#   근거 겹 분류가 어긋나면 전부 '근거 미분류' 로 떨어진다(suppression_test 가 문구를 고정한다).
supev=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=suppressed")
assert_contains "$supev" "근거 상세" "억제 행마다 근거 상세(접이식)를 제공"
if grep -qE '① 버전 비교|② 배포판 보안 트래커|③ 벤더 권고|④ changelog 백포트' <<<"$supev"; then
  ok "억제 근거를 겹(①~④)으로 분류해 표시"
else
  no "억제 근거 겹 뱃지가 없음 — 어느 겹이 억제했는지 화면에서 읽을 수 없다"
fi

# 등급 제안 근거 — 한 줄 문자열이 아니라 신호 목록으로 보여야 사람이 확정 근거로 쓴다.
gradebody=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID&tab=manage")
assert_contains "$gradebody" "시스템이 본 신호" "자산 설정 탭에 등급 제안 근거 신호 노출"
# redis 는 0.0.0.0:6379 지만 방화벽이 막는다 → EXTERNAL 이 아니라 FILTERED 로 분류돼야 한다.
body=$(curl_ -s -b "$JAR" "$BASE/findings.php?host=$WEB01_ID&st=FILTERED")
assert_contains "$body" "redis" "방화벽 차단(FILTERED) 분류 — redis 가 외부노출로 새지 않음"
# 미지원 배포판 호스트가 있으면 취약점 화면 상단에 경고가 떠야 한다("0건 = 판정 불가").
body=$(curl_ -s -b "$JAR" "$BASE/findings.php?host=$WEB03_ID")
assert_contains "$body" "판정 불가" "취약점 화면에 미지원 배포판 경고 노출"
# 이후 컨테이너·Go 검사는 web01 하나로 좁혀 공용 DB 페이지네이션의 영향을 제거한다.
body=$(curl_ -s -b "$JAR" "$BASE/findings.php?host=$WEB01_ID")
# **패키지 DB 가 없는 컨테이너**(Calico 같은 이미지)도 0건이 나온다 — rhel 은 피드 지원 배포판이라
#   미지원 경고에 안 걸린다. 이걸 침묵하면 "안전함"으로 읽힌다(운영 실측 9개).
assert_contains "$body" "컨테이너 nodb" "패키지 DB 없는 컨테이너도 '판정 불가'로 경고"
if grep -qF "컨테이너 gosvc" <<<"$body"; then
  no "중앙에서 패키지를 저장한 컨테이너가 pkg_count=0으로 판정 불가 처리됨"
else
  ok "중앙 저장 패키지로 컨테이너 pkg_count 보정"
fi
# Go 바이너리에서 뽑은 의존 모듈이 **Go 생태계로** 매칭돼야 한다. 배포판 생태계로 물으면
#   조회가 통째로 빗나가 미탐이 된다(kube-apiserver 는 dpkg 4개 vs Go 의존 248개다).
#   (LOW 라 목록 1페이지엔 안 뜬다 → 검색으로 집어서 확인한다.)
gobody=$(curl_ -s -b "$JAR" "$BASE/findings.php?host=$WEB01_ID&q=golang.org%2Fx%2Fnet")
assert_contains "$gobody" "CVE-2023-45288" "컨테이너의 Go 의존성 취약점이 매칭됨(golang.org/x/net v0.20.0)"
# 패키지 DB 도 Go 도 없는 이미지(whisker=nginx) — 바이너리에서 뽑은 버전을 OSV 의 Bitnami
#   생태계로 매칭한다. 이게 죽으면 그 컨테이너는 다시 "판정 불가"로 돌아간다.
# cve.php?tab=locations 는 전역(모든 워크트리·모든 호스트) 목록이라 공용 dev DB 가 자랄수록
#   (실측 1,138건) 1페이지 밖으로 밀려 깨진다 — findings.php 의 host 필터(위 WEB01_ID)로
#   이 워크트리의 호스트 하나로 좁히고, q 로 이 CVE 하나만 골라 전역 건수와 무관하게 만든다.
upbody=$(curl_ -s -b "$JAR" "$BASE/findings.php?host=$WEB01_ID&q=CVE-2023-44487")
assert_contains "$upbody" "upsvc" "업스트림 바이너리(nginx 1.24.0) 취약점이 그 컨테이너에 매칭됨"
# 정확한 사유 문구는 아래 호스트 상세에서 검증한다. findings 경고는 대상명·판정 불가 노출을 위에서 검증함.
body=$(curl_ -s -b "$JAR" "$BASE/host.php?id=$WEB01_ID")
assert_contains "$body" "패키지 DB 가 없는 이미지" "호스트 상세에도 패키지DB 없는 컨테이너 경고"

# CVE 상세은 전역 영향 범위와 실제 설치 위치를 따로 보여준다. 발견 위치에서 사용자가 두 표를
# 직접 대조하지 않아도 설치 버전 → 이 호스트의 수정 버전을 한 줄로 확인할 수 있어야 한다.
cvebody=$(curl_ -s -b "$JAR" "$BASE/cve.php?cve=CVE-2023-4911&per_page=100")
assert_contains "$cvebody" "현재 → 권장 조치" "CVE 상세에 호스트별 권장 조치 열"
assert_contains "$cvebody" "0:2.34-60.el9_2.3 → 2.34-83.el9_3.7 이상" "CVE 상세가 설치→수정 버전을 함께 안내"

# findings.php 검색 0건 안내(empty.title)에 $q 를 그대로 넣는다 — vg_empty() 가 vg_h() 로
#   이스케이프하는 것에 기대는 코드다. "이스케이프된 문자열이 응답 어딘가에 있다"만 보면
#   vg_toolbar 의 검색창 value 가 이미 그걸 만족시켜 공허하게 통과한다(raw 값이 title 에도
#   새는지는 안 잡힘) — 그래서 raw 페이로드가 "없다"는 부정 검사로 확인하고, 0건 안내가
#   실제로 그 경로를 탔는지도 함께 못박는다.
xssbody=$(curl_ -s -b "$JAR" -G "$BASE/findings.php" --data-urlencode 'q=<script>alert(1)</script>')
if grep -qF '<script>alert(1)</script>' <<<"$xssbody"; then
  no "findings.php 검색어가 raw HTML 로 출력됨 — 반사형 XSS!"
else
  ok "findings.php 검색어 XSS 이스케이프(vg_empty 의존)"
fi
assert_contains "$xssbody" '이 화면(실제 스캔·매칭된 현재 판정)에는 없습니다' "검색 0건 안내가 노출됨(빈 상태 분기 확인)"

# 필터초기화 CTA 의 href(vg_qs() 결과) — q/sev/st/fx 는 지우지만, 목록에 없는 임의 쿼리값은
#   그대로 실어 나른다. vg_qs() 의 urlencode() + vg_empty() 의 vg_h() 이중 이스케이프에
#   기대는 코드라, href 속성을 깨고 나가는 raw 값이 없는지 부정 검사로 확인한다.
evilbody=$(curl_ -s -b "$JAR" -G "$BASE/findings.php" --data-urlencode 'q=zzz-no-match-xyz-999' \
  --data-urlencode 'evil="><script>alert(1)</script>')
if grep -qF '"><script>alert(1)</script>' <<<"$evilbody"; then
  no "findings.php 필터초기화 CTA href 에 임의 쿼리값이 이스케이프 없이 흘러듦 — XSS!"
else
  ok "findings.php 필터초기화 CTA href 의 임의 쿼리값이 안전하게 인코딩됨"
fi

# 잘못된 비번
JAR2="$(mktemp)"; csrf2=$(curl_ -s -c "$JAR2" "$BASE/login.php" | grep -oE '[a-f0-9]{32}' | head -1)
body=$(curl_ -s -b "$JAR2" -c "$JAR2" --data-urlencode "csrf=$csrf2" \
  --data-urlencode "username=$SMOKE_USER" --data-urlencode "password=WRONG" "$BASE/login.php")
assert_contains "$body" "올바르지 않습니다" "틀린 비밀번호 → 로그인 거부"
rm -f "$JAR2"

# --- 에이전트 토큰: 호스트 바인딩 & 스푸핑 차단 (PR-4 보안) ------------------
#   개별 토큰은 발급 시 정한 fqdn 만 갱신할 수 있다. 침해된 대상 1대가 그 토큰으로 다른 호스트를
#   위조해 스캔을 덮어쓰는 것을 ingest.php 가 403 으로 막는지 회귀로 고정한다(HIGH-2).
printf "\n[에이전트 토큰 · 호스트 바인딩]\n"
# 로그인 세션($JAR)으로 web01 에 바인딩된 개별 토큰 발급 → 원문(vgt_...)을 1회 표시에서 추출.
#   발급은 303 으로 GET 에 되돌려주므로(-L) 원문은 리다이렉트 뒤 화면에 실린다.
ATCSRF=$(curl_ -s -b "$JAR" "$BASE/agent-tokens.php" | grep -oE 'name="csrf" value="[a-f0-9]+"' | grep -oE '[a-f0-9]{32}' | head -1)
#   -X POST 를 쓰지 않는다 — -X 는 리다이렉트 뒤에도 POST 를 강제해 발급이 무한 재전송된다.
issued=$(curl_ -sL -b "$JAR" "$BASE/agent-tokens.php" \
  --data-urlencode "csrf=$ATCSRF" --data-urlencode "action=create" \
  --data-urlencode "fqdn=$FQDN_WEB01" --data-urlencode "label=smoke $WT_LABEL")
AGTOK=$(printf '%s' "$issued" | grep -oE 'vgt_[0-9a-f]{40}' | head -1)
if [ -n "$AGTOK" ]; then ok "개별 토큰 발급 + 원문 1회 표시"; else no "개별 토큰 발급 실패"; fi
# 목록엔 prefix(앞자리)만 — 원문 전체는 저장/표시되지 않아야 한다(DB 엔 해시만).
listed=$(curl_ -s -b "$JAR" "$BASE/agent-tokens.php")
if [ -n "$AGTOK" ] && grep -q "$AGTOK" <<<"$listed"; then
  no "목록에 토큰 원문 노출(해시만 저장돼야 함)"
else
  ok "목록엔 원문 없음(DB 엔 해시만 저장)"
fi
# 새로고침이 토큰을 재발급하지 않는다(PRG) — 예전엔 POST 응답을 그대로 그려서, F5 한 번이
#   방금 받은 토큰을 자동 폐기하고 또 발급했다. 이제 발급은 303 으로 GET 에 되돌린다.
# 이 fqdn 만 **매 실행 고유**로 잡는다($$ = 이 스모크 프로세스). 아래에서 "재발급이 없었다"를
#   내 토큰 행 수로 재기 때문이다 — 같은 fqdn 으로 재발급하면 옛 행이 폐기된 채 목록에 남아
#   실행이 쌓일수록 행 수가 늘고, 그러면 "1개" 라는 기대가 성립하지 않는다.
PRG_FQDN="prg.$$.$WT_LABEL.example.com"
prgcode=$(curl_ -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/agent-tokens.php" \
  --data-urlencode "csrf=$ATCSRF" --data-urlencode "action=create" \
  --data-urlencode "fqdn=$PRG_FQDN" --data-urlencode "label=smoke-prg $WT_LABEL")
assert_eq "$prgcode" "303" "발급 POST 는 303 으로 GET 에 되돌린다(새로고침 재전송 방지)"
prg1=$(curl_ -s -b "$JAR" "$BASE/agent-tokens.php")    # 리다이렉트된 GET — 원문 1회 표시
assert_contains "$prg1" '한 번만 표시됨' "리다이렉트된 GET 에 발급 카드가 실린다"
prg2=$(curl_ -s -b "$JAR" "$BASE/agent-tokens.php")    # 새로고침 = 같은 GET 재요청
if grep -q '한 번만 표시됨' <<<"$prg2"; then
  no "새로고침에도 발급 카드가 남아 있음(1회 표시 위반)"
else
  ok "새로고침하면 발급 카드가 사라진다(1회 표시)"
fi
# 새로고침이 반복하는 것은 이제 GET 이다 — 발급된 내 토큰이 딱 1개면 재발급이 없었다는 뜻.
#   예전엔 페이지의 `(N개)` 뱃지(=DB 전체 토큰 수)를 새로고침 전후로 비교했다. 그건 공용 dev DB
#   에서 남의 트리가 그 사이에 토큰 하나만 발급해도 깨진다 — 실측으로 깨졌다(기대 314 vs 실제 315).
#   검사가 지키려는 건 "새로고침이 **내** 토큰을 또 발급하지 않는다" 이므로 내 것만 센다.
#   목록은 fqdn 을 행마다 한 번 싣고(발급 카드엔 안 실린다) 내 토큰은 방금 만든 최신이라 1페이지에 있다.
#   (-c 는 "맞는 줄 수" 라 한 줄에 두 번 실려도 1 로 읽는다 — 실제 등장 횟수를 센다.)
prgcnt1=$(printf '%s' "$prg1" | grep -o "$PRG_FQDN" | wc -l | tr -d ' ')
prgcnt2=$(printf '%s' "$prg2" | grep -o "$PRG_FQDN" | wc -l | tr -d ' ')
# 0 이면 "없어서 통과" 하는 빈 검사가 되므로 둘 다 정확히 1 인지 본다(재발급이 있었다면 2가 된다).
if [ "$prgcnt1" = "1" ] && [ "$prgcnt2" = "1" ]; then
  ok "새로고침해도 토큰이 다시 발급되지 않는다(내 토큰 1개 그대로)"
else
  no "새로고침해도 토큰이 다시 발급되지 않는다  (발급 직후=$prgcnt1, 새로고침 후=$prgcnt2, 기대=둘 다 1)"
fi
# (a) 바인딩된 호스트(web01)로 수신 → 200 ok, 저장 호스트가 바인딩 fqdn.
resp=$(curl_i -s -X POST "$BASE/ingest.php" -H "X-Agent-Token: $AGTOK" --data-binary @"$SAMPLE")
assert_contains "$resp" '"ok":true' "(a) 개별 토큰 + 바인딩 호스트 → ok:true"
assert_contains "$resp" "\"fqdn\":\"$FQDN_WEB01\"" "(a) 저장 호스트가 바인딩 fqdn"
# (b) 같은 토큰으로 다른 호스트(evil)를 주장 → 403 거부. 스푸핑 차단의 핵심 회귀.
SPOOF="$(mktemp)"; sed "s/web01\.$WT_LABEL\.example\.com/evil.$WT_LABEL.example.com/g" "$SAMPLE" > "$SPOOF"
code=$(curl_i -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ingest.php" \
  -H "X-Agent-Token: $AGTOK" --data-binary @"$SPOOF")
assert_eq "$code" "403" "(b) 같은 토큰으로 다른 호스트 위조 → 403 (스푸핑 차단)"
rm -f "$SPOOF"

# --- 종료 시 재확인: 스모크 도중 이 트리 전용 컨테이너가 내려갔으면 위 결과는 전부 무효다. ----
assert_my_stack "종료"

# --- 요약 -------------------------------------------------------------------
printf "\n${CYAN}== 결과: ${GREEN}%d 통과${NC}, ${RED}%d 실패${NC}" "$pass" "$fail"
[ "$skip" -gt 0 ] && printf ", ${YELLOW}%d 건너뜀${NC}" "$skip"
printf " ${CYAN}==${NC}\n"
[ "$fail" -eq 0 ]
