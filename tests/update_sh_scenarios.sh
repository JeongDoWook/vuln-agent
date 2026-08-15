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
    cat > deploy/backup_db.sh <<'EOS'
#!/usr/bin/env bash
mkdir -p "$BACKUP_DIR"; : > "$BACKUP_DIR/vulnagent_stub.sql.gz"; echo "  [stub] backup_db"
EOS
    cat > deploy/migrate.sh <<'EOS'
#!/usr/bin/env bash
echo "  [stub] migrate.sh 실행" >> "$CALL_LOG"
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

run_update() {
  : > "$SANDBOX/calls.log"
  (
    cd "$SANDBOX/work"
    PATH="$SANDBOX/bin:$PATH" \
    BACKUP_DIR="$SANDBOX/backups" DB_DATA_DIR="$SANDBOX/dbdata" \
    HEALTH_URL="http://stub/" CALL_LOG="$SANDBOX/calls.log" \
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
expect_rc0; expect_build; expect_migrate_first; expect_marker; expect_clean
out | grep -q '기준선: 배포 마커' && ok "기준선으로 마커를 썼다" || bad "마커를 기준선으로 쓰지 않았다"

head2 "시나리오 2 — OLD = NEW + PHP·문서만 변경 → 재빌드/재생성 없음"
seed_repo
MARK=$(git -C "$SANDBOX/work" rev-parse HEAD)
push_commit server/public/index.php '// php 수정' 'php 변경'
push_commit README.md '문서 한 줄' '문서 변경'
git -C "$SANDBOX/work" pull --quiet --ff-only
seed_marker "$MARK"
run_update
expect_rc0; expect_no_build; expect_no_compose; expect_migrate_first; expect_marker; expect_clean

head2 "시나리오 3 — 정상 pull(OLD ≠ NEW) + Caddyfile 변경 → 기존과 동일하게 재빌드"
seed_repo
push_commit deploy/caddy/Caddyfile 'header Cache-Control x' 'caddyfile 변경'
run_update                                             # 마커 없음 → 현재 체크아웃이 기준선
expect_rc0; expect_build; expect_migrate_first; expect_marker; expect_clean
out | grep -q '기준선: 배포 마커 없음' && ok "마커 없을 때 OLD 로 폴백(하위호환)" || bad "폴백 문구가 없다"

head2 "시나리오 4 — 같은 update.sh 연속 2회 → 2회차는 할 일 없음(멱등)"
run_update                                             # 3번 이어서 그대로 한 번 더
expect_rc0; expect_no_build; expect_no_compose; expect_clean
out | grep -q '반영할 것 없음' && ok "2회차: 반영할 것 없음" || { bad "2회차가 할 일을 찾았다"; out | tail -30; }
expect_migrate_first                                   # 마이그레이션은 멱등이라 2회차에도 돈다

printf '\n---------------------------------------------\n'
printf '통과 %d · 실패 %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
