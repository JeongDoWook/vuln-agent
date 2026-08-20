#!/usr/bin/env bash
# 스키마 문서 drift 사전검사 — docker 없이 git diff 만으로 1초 안에 끝난다.
#
# 왜 있나: 마이그레이션을 추가하면서 스키마 문서 산출물 4종을 같이 갱신하지 않는 사고가
# #703(tb_report_job)·#706(verify_files)로 연달아 났다. 둘 다 중앙 `central` 프로파일 전용인
# 무거운 schema-docs 게이트(tests/schema_docs_test.sh — disposable MySQL, 실측 132초·126초)에서야
# 뒤늦게 걸렸다. 로컬 pre-push 에는 그 게이트가 없어 전부 통과한 것처럼 보인다.
#
# 무엇을 하나: base..HEAD 에 새 마이그레이션(또는 initdb db/*.sql 변경)이 있는데 산출물 4종이
# 하나도 안 바뀌었으면 실패시킨다. 그게 전부다.
#
# 한계(의도적): **"산출물이 바뀌었는가"까지만 본다.** 내용이 실제 스키마와 맞는지는 판단하지
# 않는다 — 그건 information_schema 를 정본으로 대조하는 tests/schema_docs_test.sh 의 일이다.
# 여기서 통과했다고 문서가 맞다는 뜻이 아니고, 이 스크립트는 그 게이트를 대체하지 않는다.
# 오직 "아예 잊고 안 건드린 경우"를 값싸게 먼저 잡을 뿐이다.
#
# exit 0 = 통과 또는 검사 대상 아님 / exit 1 = drift 감지.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# docs/specs/gen_table_spec.py 가 한 묶음으로 생성하는 4종. 하나라도 바뀌었으면 "손댔다"로 본다.
artifacts=(
  'docs/dev/데이터베이스.md'
  'docs/specs/diagrams/erd.puml'
  'docs/specs/diagrams/erd.svg'
  'docs/specs/테이블명세서.xlsx'
)

ok() { printf 'schema docs precheck: ok (%s)\n' "$1"; exit 0; }

git rev-parse --git-dir >/dev/null 2>&1 || ok 'git 저장소가 아님 — 검사 생략'

# 비교 기준은 deploy/run-gates.sh 의 check_migration_rehearsal 과 같은 merge-base 방식이다.
# 다만 fallback 방향은 반대다: 저쪽은 판단 불가 시 무거운 rehearsal 을 돌려 정확성을 택하지만,
# 여기는 값싼 1차 방어일 뿐이고 뒤에 진짜 게이트가 있으므로 판단 불가를 실패로 만들지 않는다.
base=''
if b="$(git merge-base HEAD origin/main 2>/dev/null)"; then base="$b"; fi
[ -n "$base" ] || ok 'origin/main 기준점을 못 구함(얕은 clone 등) — 무거운 schema-docs 게이트에 맡긴다'

short="$(git rev-parse --short "$base" 2>/dev/null || printf '%s' "$base")"

# 새로 추가된 마이그레이션(A)과 initdb 최상위 db/*.sql 변경.
# ':(glob)' 을 붙여야 '*' 가 '/' 를 안 넘어간다 — 없으면 db/migrations/*.sql 까지 같이 걸린다.
new_migrations="$(git -c core.quotepath=false diff --name-only --diff-filter=A "$base" HEAD -- db/migrations 2>/dev/null || true)"
initdb_changed="$(git -c core.quotepath=false diff --name-only "$base" HEAD -- ':(glob)db/*.sql' 2>/dev/null || true)"

if [ -z "$new_migrations" ] && [ -z "$initdb_changed" ]; then
  ok "새 마이그레이션·initdb 변경 없음 (base=$short)"
fi

changed_docs="$(git -c core.quotepath=false diff --name-only "$base" HEAD -- "${artifacts[@]}" 2>/dev/null || true)"
if [ -n "$changed_docs" ]; then
  ok "스키마 변경과 문서 산출물이 함께 바뀜 (base=$short)"
fi

{
  printf 'schema docs precheck: 스키마 문서 drift — 스키마를 바꿨는데 문서 산출물이 하나도 안 바뀌었습니다 (base=%s)\n' "$short"
  printf '  바뀐 스키마 파일:\n'
  # 파이프 대신 here-document 를 쓴다. 'printf | while' 로 하면 마지막 빈 줄에서 while 이 1로 끝나고
  # set -e 가 그 자리에서 스크립트를 죽여 아래 안내가 통째로 안 찍힌다(실제로 밟았다).
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    printf '    - %s\n' "$f"
  done <<LIST
$new_migrations
$initdb_changed
LIST
  printf '  그런데 아래 산출물 4종은 base..HEAD 에서 한 줄도 안 바뀌었습니다:\n'
  for f in "${artifacts[@]}"; do printf '    - %s\n' "$f"; done
  printf '  갱신: SCHEMA_DOCS_UPDATE=1 tests/schema_docs_test.sh  → 이어서 docs/specs/diagrams/render.sh\n'
  printf '  (이 검사는 "안 건드렸다"만 잡습니다. 내용 일치는 tests/schema_docs_test.sh 가 봅니다.)\n'
} >&2
exit 1
