#!/usr/bin/env bash
# =============================================================================
# deploy/update.sh 시나리오 검증 — "배포 마커" 기준선이 실제로 동작하는지 재현한다.
# =============================================================================
# 왜 필요한가: `bash -n` 은 문법만 본다. 이 스크립트가 고치는 건 **판단**(무엇과 비교해
# 재빌드할지)이라, 판단이 맞는지는 실제로 돌려봐야 안다. 운영 서버를 칠 수는 없으므로
# 임시 git 저장소 + docker/curl 스텁을 PATH 에 얹어 update.sh 를 통째로 실행한다.
#
#   1. OLD = NEW(코드가 먼저 도착) + Dockerfile 변경  → 재빌드해야 한다
#   2. OLD = NEW + PHP·문서만 변경                    → 재빌드/재생성 없음
#   3. 정상 pull(OLD ≠ NEW) + Caddyfile 변경          → 기존과 동일하게 재빌드
#   4. 같은 상태에서 연속 2회 실행                     → 2회차는 할 일 없음(멱등)
#   5. 미적용 마이그레이션 0건                         → 백업 없음. migrate.sh 는 돌지만 적용 0건(멱등 스킵)
#   6. 미적용 1건 이상                                 → 적용은 하되 **백업은 만들지 않는다**(이번 변경의 핵심)
#   7. 파일 변경 0 + 미적용 1건(앞선 배포가 중단됨)    → 건너뛰지 않고 적용(git diff 로 보면 틀리는 케이스)
#   8. DB 상태가 이상해도                              → 백업으로 도피하지 않는다(백업 경로 자체가 없다)
#
# 실행: bash tests/update_sh_scenarios.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT=$PWD

# 임시 경로는 저장소 안 ASCII 경로로 잡는다 — %TEMP% 가 한글 사용자명이면 mingw 도구가
# 경로를 못 읽는 사례가 있었다(tests/go_deps_extract_test.sh 와 같은 이유).
SANDBOX="$REPO_ROOT/tests/.tmp-update-sh.$$"
trap 'rm -rf "$SANDBOX"' EXIT

PASS=0; FAIL=0
ok()   { printf '  [OK]   %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
head2() { printf '\n=== %s\n' "$*"; }

# --- 스텁: docker / curl -----------------------------------------------------
make_stubs() {
  mkdir -p "$SANDBOX/bin"
  cat > "$SANDBOX/bin/docker" <<'EOS'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *"inspect vulnagent-web"*"/var/www/html"*) echo yes ;;
  *"inspect vulnagent-db"*".State.Status"*)  echo running ;;
  *"inspect vulnagent-db"*"/var/lib/mysql"*) echo "$DB_DATA_DIR" ;;
  *"inspect vulnagent-db"*".State.Health"*)  echo healthy ;;
  "ps "*)  printf '  vulnagent-web\tUp 3 minutes\n  vulnagent-db\tUp 3 minutes (healthy)\n' ;;
  "exec "*) echo 0 ;;
  *) exit 0 ;;
esac
EOS
  cat > "$SANDBOX/bin/curl" <<'EOS'
#!/usr/bin/env bash
echo 200
EOS
  chmod +x "$SANDBOX/bin/docker" "$SANDBOX/bin/curl"
}

# --- 샌드박스 저장소 ---------------------------------------------------------
# origin(bare) + work(clone). work/deploy/update.sh 는 검사 대상 실물을 복사한다.
# backup_db.sh / migrate.sh / compose_runner.sh 는 스텁 — 이 테스트가 보는 건
# "update.sh 가 무엇을 부르느냐"지 그것들의 내부 동작이 아니다.
seed_repo() {
  rm -rf "$SANDBOX"
  mkdir -p "$SANDBOX/origin.git" "$SANDBOX/backups" "$SANDBOX/dbdata"
  make_stubs
  # 기본값은 "미적용 1건" — 시나리오 1~4 는 마이그레이션이 도는 상태를 본다(백업은 어느 경우에도 안 돈다).
  set_pending 20260101000000_stub.sql
  STUB_MIGRATE_FAIL=0
  STUB_LAST_APPLIED=none
  git init --quiet --bare "$SANDBOX/origin.git"
  git -C "$SANDBOX/origin.git" symbolic-ref HEAD refs/heads/main   # clone 이 main 을 체크아웃하도록
  git init --quiet "$SANDBOX/seed"
  (
    cd "$SANDBOX/seed"
    git config user.email t@t; git config user.name t; git config commit.gpgsign false
    git config core.autocrlf false
    mkdir -p deploy/caddy deploy/hooks server/public db/migrations
    # SRC_UPDATE_SH 로 옛 버전을 가리키면 "고치기 전엔 어땠나"를 같은 시나리오로 재현할 수 있다.
    cp "${SRC_UPDATE_SH:-$REPO_ROOT/deploy/update.sh}" deploy/update.sh
    cp "$REPO_ROOT/.gitignore" .gitignore
    printf 'FROM php:8.3-apache\n' > server/Dockerfile
    printf ':80 {\n}\n' > deploy/caddy/Caddyfile
    printf '<?php echo 1;\n' > server/public/index.php
    printf '# readme\n' > README.md
    # 백업 스텁: 호출 사실을 로그에 남기고 매번 **새 파일**을 만든다(개수로 "안 돌았음"을 본다).
    # 실물 backup_db.sh 가 띄우는 검증 컨테이너도 이 안에 있으므로, 이 스텁이 안 불렸다는 것은
    # 곧 검증 컨테이너도 안 떴다는 뜻이다. **지금은 어느 시나리오에서도 불리면 안 된다** —
    # cron 이 쓰는 파일이라 저장소에는 남아 있고, 배포가 다시 부르는 회귀를 이 스텁이 잡는다.
    cat > deploy/backup_db.sh <<'EOS'
#!/usr/bin/env bash
echo "backup_db 실행" >> "$CALL_LOG"
mkdir -p "$BACKUP_DIR"; : > "$BACKUP_DIR/vulnagent_stub_$$_${RANDOM}.sql.gz"; echo "  [stub] backup_db"
EOS
    # migrate 스텁: 실물처럼 STUB_PENDING_FILE 의 줄 수만큼 "적용"하고 같은 모양의 로그를 낸다.
    # STUB_MIGRATE_FAIL=1 이면 마이그레이션 실패(DB 접속 불가 등)를 흉내낸다.
    cat > deploy/migrate.sh <<'EOS'
#!/usr/bin/env bash
n=0
[ -s "${STUB_PENDING_FILE:-}" ] && n=$(grep -c . "$STUB_PENDING_FILE")
echo "  [stub] migrate.sh 실행(적용 $n)" >> "$CALL_LOG"
echo "  preflight: db=stub · schema_version=${STUB_LAST_APPLIED:-none} · free_kb=9 · backup=not-required"
if [ "${STUB_MIGRATE_FAIL:-0}" = 1 ]; then echo "마이그레이션 중단: DB 접속 불가(stub)" >&2; exit 1; fi
[ "$n" -gt 0 ] && sed 's/^/  적용: /' "$STUB_PENDING_FILE"
echo "마이그레이션 완료 — 적용 $n · 스킵 0"
EOS
    cat > deploy/compose_runner.sh <<'EOS'
#!/usr/bin/env bash
echo "compose_runner $*" >> "$CALL_LOG"
EOS
    chmod +x deploy/*.sh
    git add -A && git commit --quiet -m "base"
    git branch -M main
    git remote add origin "$SANDBOX/origin.git"
    git push --quiet -u origin main
  )
  git -c core.autocrlf=false clone --quiet "$SANDBOX/origin.git" "$SANDBOX/work"
  git -C "$SANDBOX/work" config core.autocrlf false
  git -C "$SANDBOX/work" config user.email t@t
  git -C "$SANDBOX/work" config user.name t
  git -C "$SANDBOX/work" config commit.gpgsign false
}

# origin 에 커밋 하나를 얹는다: push_commit <파일> <내용> <메시지>
push_commit() {
  (
    cd "$SANDBOX/seed"
    printf '%s\n' "$2" >> "$1"
    git add -A && git commit --quiet -m "$3" && git push --quiet origin main
  )
}

# 미적용 목록을 갈아끼운다: set_pending [파일명...] (인자 없으면 0건)
set_pending() { : > "$SANDBOX/pending.txt"; [ "$#" -gt 0 ] && printf '%s\n' "$@" > "$SANDBOX/pending.txt"; return 0; }
count_backups() { ls -1 "$SANDBOX/backups"/*.sql.gz 2>/dev/null | grep -c . || true; }

run_update() {
  : > "$SANDBOX/calls.log"
  (
    cd "$SANDBOX/work"
    PATH="$SANDBOX/bin:$PATH" \
    BACKUP_DIR="$SANDBOX/backups" DB_DATA_DIR="$SANDBOX/dbdata" \
    HEALTH_URL="http://stub/" CALL_LOG="$SANDBOX/calls.log" \
    STUB_PENDING_FILE="$SANDBOX/pending.txt" \
    STUB_MIGRATE_FAIL="${STUB_MIGRATE_FAIL:-0}" STUB_LAST_APPLIED="${STUB_LAST_APPLIED:-none}" \
      bash deploy/update.sh
  ) > "$SANDBOX/out.log" 2>&1
  echo $? > "$SANDBOX/rc"
}

calls() { cat "$SANDBOX/calls.log" 2>/dev/null; }
out()   { cat "$SANDBOX/out.log"; }
rc()    { cat "$SANDBOX/rc"; }

expect_rc0()      { [ "$(rc)" = 0 ] && ok "종료코드 0" || { bad "종료코드 $(rc)"; out | tail -20; }; }
expect_build()    { calls | grep -q -- '--build' && ok "재빌드 수행(compose up -d --build)" || { bad "재빌드가 일어나지 않았다"; out | tail -30; }; }
expect_no_build() { calls | grep -q -- '--build' && { bad "불필요한 재빌드가 일어났다"; calls; } || ok "재빌드 없음"; }
expect_no_compose(){ calls | grep -q 'compose_runner' && { bad "컨테이너를 건드렸다"; calls; } || ok "컨테이너 재생성 없음(다운타임 0)"; }
# 배포는 어떤 경우에도 백업을 만들지 않는다(정기 백업은 04:00 cron) → 모든 시나리오 공통 단언.
expect_no_backup()      { calls | grep -q 'backup_db 실행' && { bad "배포가 백업을 돌렸다(cron 전용이어야 한다)"; calls; } || ok "백업 안 돎(덤프도 검증 컨테이너도 없음)"; }
expect_migrate_applied(){ calls | grep -qE 'migrate\.sh 실행\(적용 [1-9]' && ok "마이그레이션 적용됨" || { bad "마이그레이션이 적용되지 않았다"; calls; }; }
expect_migrate_noop()   { calls | grep -q 'migrate.sh 실행(적용 0)' && ok "migrate.sh 는 돌았고 적용 0건(멱등 스킵)" || { bad "적용 0건이 아니다"; calls; }; }
expect_marker()   { [ -f "$SANDBOX/work/deploy/.deploy-state/last-deployed" ] && ok "배포 마커 기록됨: $(cat "$SANDBOX/work/deploy/.deploy-state/last-deployed")" || bad "배포 마커가 없다"; }
expect_clean()    { [ -z "$(git -C "$SANDBOX/work" status --porcelain)" ] && ok "마커가 git status 를 더럽히지 않음" || { bad "저장소가 더러워졌다"; git -C "$SANDBOX/work" status --short; }; }
expect_migrate_first() {
  # migrate 호출이 compose_runner 호출보다 먼저인지 (한 줄도 없으면 compose 도 없어야 통과)
  local m c
  m=$(calls | grep -n 'migrate.sh' | head -1 | cut -d: -f1)
  c=$(calls | grep -n 'compose_runner' | head -1 | cut -d: -f1)
  if [ -n "$m" ] && { [ -z "$c" ] || [ "$m" -lt "$c" ]; }; then
    ok "마이그레이션이 코드 반영보다 먼저"
  else
    bad "마이그레이션 순서 이상 (migrate=$m compose=$c)"; calls
  fi
}
# 마커를 특정 SHA 로 미리 심는다(= 그 커밋까지는 이미 배포된 상태).
seed_marker() {
  mkdir -p "$SANDBOX/work/deploy/.deploy-state"
  printf '%s\n' "$1" > "$SANDBOX/work/deploy/.deploy-state/last-deployed"
}

# =============================================================================
head2 "시나리오 1 — OLD = NEW(코드가 먼저 도착) + Dockerfile 변경 → 재빌드해야 한다"
seed_repo
MARK=$(git -C "$SANDBOX/work" rev-parse HEAD)          # 여기까지는 배포된 상태
push_commit server/Dockerfile 'RUN echo layer' 'dockerfile 변경'
git -C "$SANDBOX/work" pull --quiet --ff-only          # 사람이 손으로 먼저 pull 한 상황
seed_marker "$MARK"
run_update
expect_rc0; expect_build; expect_migrate_first; expect_no_backup; expect_marker; expect_clean
out | grep -q '기준선: 배포 마커' && ok "기준선으로 마커를 썼다" || bad "마커를 기준선으로 쓰지 않았다"

head2 "시나리오 2 — OLD = NEW + PHP·문서만 변경 → 재빌드/재생성 없음"
seed_repo
MARK=$(git -C "$SANDBOX/work" rev-parse HEAD)
push_commit server/public/index.php '// php 수정' 'php 변경'
push_commit README.md '문서 한 줄' '문서 변경'
git -C "$SANDBOX/work" pull --quiet --ff-only
seed_marker "$MARK"
run_update
expect_rc0; expect_no_build; expect_no_compose; expect_migrate_first; expect_no_backup; expect_marker; expect_clean

head2 "시나리오 3 — 정상 pull(OLD ≠ NEW) + Caddyfile 변경 → 기존과 동일하게 재빌드"
seed_repo
push_commit deploy/caddy/Caddyfile 'header Cache-Control x' 'caddyfile 변경'
run_update                                             # 마커 없음 → 현재 체크아웃이 기준선
expect_rc0; expect_build; expect_migrate_first; expect_no_backup; expect_marker; expect_clean
out | grep -q '기준선: 배포 마커 없음' && ok "마커 없을 때 OLD 로 폴백(하위호환)" || bad "폴백 문구가 없다"

head2 "시나리오 4 — 같은 update.sh 연속 2회 → 2회차는 할 일 없음(멱등)"
run_update                                             # 3번 이어서 그대로 한 번 더
expect_rc0; expect_no_build; expect_no_compose; expect_no_backup; expect_clean
out | grep -q '반영할 것 없음' && ok "2회차: 반영할 것 없음" || { bad "2회차가 할 일을 찾았다"; out | tail -30; }
expect_migrate_first                                   # 마이그레이션은 멱등이라 2회차에도 돈다

head2 "시나리오 5 — 미적용 0건 → 백업 없음, migrate.sh 는 돌되 적용 0건(멱등 스킵)"
seed_repo
set_pending                                            # 미적용 0건
STUB_LAST_APPLIED=20260816230500_perf_distinct_lookup_indexes.sql
push_commit server/public/index.php '// php 수정' 'php 변경'
BEFORE=$(count_backups)
run_update
expect_rc0; expect_no_backup; expect_migrate_noop; expect_marker; expect_clean
[ "$(count_backups)" = "$BEFORE" ] && ok "백업 파일이 새로 안 생김($BEFORE개 그대로)" || bad "백업 파일이 늘었다($BEFORE → $(count_backups))"
out | grep -q '백업은 만들지 않습니다' && ok "백업을 안 한다는 사실을 로그에 분명히 남긴다" || { bad "백업 없음 문구가 없다"; out | tail -30; }
out | grep -q "schema_version=$STUB_LAST_APPLIED" && ok "마지막 적용 파일명을 같이 보여준다" || bad "마지막 적용 표기가 없다"
out | grep -q '마이그레이션 완료 — 적용 0' && ok "적용 0건임을 로그가 말한다" || { bad "적용 0건 표기가 없다"; out | tail -30; }
STUB_LAST_APPLIED=none

head2 "시나리오 6 — 미적용 1건 이상 → 적용은 하되 **백업은 안 만든다**(이번 변경의 핵심)"
seed_repo
set_pending 20260817090000_add_col.sql 20260817091000_add_idx.sql
push_commit db/migrations/20260817090000_add_col.sql 'ALTER TABLE t ADD COLUMN c INT;' '마이그레이션 추가'
BEFORE=$(count_backups)
run_update
expect_rc0; expect_no_backup; expect_migrate_applied; expect_migrate_first; expect_marker; expect_clean
[ "$(count_backups)" = "$BEFORE" ] && ok "미적용분이 있어도 백업 파일은 안 생김($BEFORE개 그대로)" || bad "백업 파일이 늘었다($BEFORE → $(count_backups))"
out | grep -q '적용: 20260817090000_add_col.sql' && ok "무엇을 적용했는지 목록을 보여준다" || { bad "적용 목록 표기가 없다"; out | tail -30; }

head2 "시나리오 7 — 파일 변경 0 + 미적용 1건(앞선 배포 중단) → 건너뛰지 않고 적용"
seed_repo
set_pending 20260817090000_add_col.sql                 # 파일은 그대로인데 DB 엔 안 들어감
seed_marker "$(git -C "$SANDBOX/work" rev-parse HEAD)" # 기준선 = 현재 → CHANGED 0건
BEFORE=$(count_backups)
run_update
expect_rc0; expect_no_backup; expect_migrate_applied; expect_marker; expect_clean
[ "$(count_backups)" = "$BEFORE" ] && ok "백업 파일이 새로 안 생김($BEFORE개 그대로)" || bad "백업 파일이 늘었다($BEFORE → $(count_backups))"
out | grep -q '반영할 것 없음' && ok "코드 변경은 0건인 상태가 맞다" || { bad "코드 변경 0건 상태가 아니다"; out | tail -30; }

head2 "시나리오 8 — 마이그레이션 실패 → 배포 중단(백업으로 도피하지 않는다)"
seed_repo
STUB_MIGRATE_FAIL=1
push_commit server/public/index.php '// php 수정' 'php 변경'
BEFORE=$(count_backups)
run_update
[ "$(rc)" != 0 ] && ok "종료코드 $(rc) — 마이그레이션 실패를 삼키지 않는다" || { bad "실패했는데 종료코드 0"; out | tail -30; }
expect_no_backup
[ "$(count_backups)" = "$BEFORE" ] && ok "실패해도 백업은 안 만든다(백업 경로 자체가 없다)" || bad "백업 파일이 늘었다"
calls | grep -q 'compose_runner' && { bad "마이그레이션이 실패했는데 코드가 반영됐다"; calls; } || ok "코드 반영 전에 멈췄다"
[ ! -f "$SANDBOX/work/deploy/.deploy-state/last-deployed" ] && ok "실패 배포는 마커를 남기지 않는다" || bad "실패했는데 배포 마커가 기록됐다"
STUB_MIGRATE_FAIL=0

printf '\n---------------------------------------------\n'
printf '통과 %d · 실패 %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
