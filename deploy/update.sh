#!/usr/bin/env bash
# =============================================================================
# vuln-agent 서버 업데이트 (운영 중앙 서버에서 실행)
# =============================================================================
# 로컬(개발 PC)에서 코드 수정 → git push 한 뒤, 서버에서 이 한 줄:
#     bash update.sh
#
# 하는 일: 최신 코드 pull → 운영 스택 재빌드·재시작 → 상태 표시.
#   .env.prod / secrets/*.txt 는 gitignore 라 pull 로 덮이지 않음(안전).
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "== [1/3] 최신 코드 받기 (git pull) =="
git pull --ff-only

echo ""
echo "== [2/3] 재빌드 + 재시작 (prod) =="
bash compose_runner.sh prod up -d --build

echo ""
echo "== [3/3] 컨테이너 상태 =="
bash compose_runner.sh prod ps

echo ""
echo ">> 업데이트 완료."
echo ">> 참고: db/*.sql 을 '새로' 추가한 경우엔 기존 DB 볼륨에 자동 적용되지 않으므로"
echo ">>       수동 적용이 필요합니다(스키마 변경 시에만 해당)."
