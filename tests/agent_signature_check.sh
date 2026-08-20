#!/usr/bin/env bash
# 에이전트 서명 일치 검사 — docker 없이 openssl 만으로 0.1초 안에 끝난다(실측 130ms).
#
# 왜 있나: agent/vuln-inventory-agent.sh 를 고치면서 agent/vuln-inventory-agent.sh.sig 를
# 재생성하지 않는 사고가 #735·#738 로 두 번 났다. #738 은 SCRIPT_VERSION 을 3.15 로 올리면서
# 재서명을 빠뜨려 2026-08-20 23:32~23:38 운영 장애가 됐다:
#   서버는 3.13 < 3.15 로 보고 매 폴링(10초)마다 업데이트를 제안하고, 노드는 148KB 를 받아
#   sha256 은 통과하지만(서버가 같은 파일에서 즉석 계산) Ed25519 서명에서 실패한다.
#   실패 버전을 기록하지 않아 10초 뒤 그대로 반복 — tb_activity_log 에 signature_invalid
#   411건 / 6분 20초(분당 65건). 방치하면 하루 약 9.5만 행으로 감사로그가 디스크를 채운다.
# #735 는 버전을 안 올려 서버가 업데이트를 제안하지 않았을 뿐, 서명은 똑같이 깨져 있었다.
# 사람 규칙(agent_sign.sh 를 잊지 말 것)으로 이미 두 번 실패했으므로 push 단계에서 막는다.
#
# 무엇을 하나: 지금 트리의 .sh 가 .pub 로 .sig 검증을 통과하는지만 본다. 조건 없이 항상
# 검증한다 — agent/ 를 안 건드린 push 에서도 130ms 라 조건 분기가 이득이 없고, "직전 커밋이
# 깨뜨린 서명"이 다음 push 에서도 그대로 걸려야 한다.
#
# 한계(의도적): **서명을 만들지 않는다.** 개인키는 유지보수자 로컬에만 있고, 서명 생성은
# deploy/agent_sign.sh 의 일이다(웹·CI 가 서명할 수 있으면 이 체계 자체가 무의미해진다).
#
# exit 0 = 통과 또는 스킵 / exit 1 = 서명 불일치.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

script='agent/vuln-inventory-agent.sh'
sig="$script.sig"
pub='agent/vuln-inventory-agent.pub'

ok()   { printf 'agent signature: ok (%s)\n' "$1"; exit 0; }
skip() { printf 'agent signature: 스킵 — %s (중앙 central 게이트에서 다시 검사됩니다)\n' "$1"; exit 0; }

# 검증 도구가 없다고 push 를 막지는 않는다 — 개발 머신 사정일 뿐이고, 같은 검사가 중앙
# 프로파일에서 다시 돈다. 단 스킵했다는 사실은 반드시 남긴다.
command -v openssl >/dev/null 2>&1 || skip 'openssl 이 없습니다'

# openssl pkeyutl -rawin(원본 메시지 Ed25519 검증)은 OpenSSL 3.0+ 전용이다.
# agent/install-agent.sh 가 노드에서 같은 이유로 분기한다(거기 주석 참고).
# LibreSSL 은 버전 번호가 3.x 라도 -rawin 을 지원하지 않으므로 이름까지 본다.
ssl_name="$(openssl version 2>/dev/null | awk '{print $1}')"
ssl_ver="$(openssl version 2>/dev/null | awk '{print $2}')"
case "$ssl_name:$ssl_ver" in
  OpenSSL:[3-9]*|OpenSSL:[1-9][0-9]*) ;;
  *) skip "${ssl_name:-openssl} ${ssl_ver:-버전미상} 은 pkeyutl -rawin 을 지원하지 않습니다(OpenSSL 3.0+ 필요)" ;;
esac

for f in "$script" "$pub" "$sig"; do
  [ -f "$root/$f" ] || {
    printf 'agent signature: 서명 자산이 없습니다 — %s\n' "$f" >&2
    printf '  세 파일(%s · %s · %s)은 항상 같이 있어야 합니다.\n' "$script" "$pub" "$sig" >&2
    exit 1
  }
done

if openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$script" -sigfile "$sig" >/dev/null 2>&1; then
  ver="$(grep -m1 -E '^SCRIPT_VERSION=' "$script" | cut -d= -f2- | tr -d '"'"'" || true)"
  ok "${ver:+v$ver }$script"
fi

{
  printf 'agent signature: 서명 불일치 — %s 가 %s 로 검증되지 않습니다\n' "$script" "$sig"
  printf '  스크립트를 고치고 재서명하지 않았을 때 생깁니다. 같은 커밋에 .sig 를 넣으세요:\n'
  printf '    bash deploy/agent_sign.sh <개인키경로>   (예: bash deploy/agent_sign.sh ~/agent-signing.key)\n'
  printf '    git add %s %s\n' "$script" "$sig"
  printf '  이대로 배포되면: 노드가 10초마다 148KB 를 받아 서명 검증에 실패하고 무한 재시도합니다.\n'
  printf '  (2026-08-20 실측 — signature_invalid 411건/6분 20초, 분당 65건. 감사로그가 디스크를 채웁니다.)\n'
  printf '  서명을 못 만드는 환경이면 .sh 변경을 되돌리세요 — 서명 없는 버전업이 곧 장애입니다.\n'
} >&2
exit 1
