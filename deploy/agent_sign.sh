#!/usr/bin/env bash
# =============================================================================
# agent_sign.sh — vuln-inventory-agent.sh 를 Ed25519 개인키로 서명한다 (로컬 전용).
# =============================================================================
# 왜 필요한가:
#   agent-poll.php 가 내려주는 sha256 은 배포 파일과 같은 웹 프로세스가 즉석 계산한 값이라,
#   웹 티어가 뚫리면 공격자가 악성 스크립트의 해시를 그대로 실어 "검증 통과"로 만들 수 있다
#   (agent/README.md "보안 한계" 참고). 이 스크립트는 그 방어선을 커밋 시점으로 옮긴다 —
#   유지보수자가 로컬에서만 갖는 개인키로 서명하고, .sig 를 스크립트와 함께 커밋한다.
#   PHP 는 이 파일을 읽기만 할 뿐 절대 서명을 만들지 않는다.
#
# 무엇을 하나:
#   openssl pkeyutl 로 agent/vuln-inventory-agent.sh 를 서명해 agent/vuln-inventory-agent.sh.sig
#   (64바이트, raw Ed25519 서명)를 만든다. .sig 는 스크립트와 함께 커밋한다.
#
# 개인키는 이 스크립트에 담기지 않는다 — 경로만 인자로 받는다. 키 자체는:
#   - 커밋하지 않는다.
#   - Docker Secrets 로 서버에 두지 않는다(웹 컨테이너가 마운트해서 읽는 secrets/*.txt 는
#     런타임 시크릿용이라 이 용도에 맞지 않는다 — 서명키가 거기 들어가면 웹 티어 침해로
#     서명까지 위조 가능해져 이 체계 전체가 무의미해진다).
#   - 유지보수자의 로컬 머신에만 존재한다.
#
# 최초 1회 키쌍 생성(이미 있으면 건너뛴다):
#   openssl genpkey -algorithm ed25519 -out agent-signing.key
#   openssl pkey -in agent-signing.key -pubout -out agent/vuln-inventory-agent.pub
#   (공개키는 비밀이 아니다 — agent/vuln-inventory-agent.pub 는 커밋해도 된다)
#
# 사용:
#   bash deploy/agent_sign.sh ~/agent-signing.key
#
# 이후 절차: agent/vuln-inventory-agent.sh 를 고칠 때마다 커밋 전에 이 스크립트로 서명하고,
#   바뀐 .sh 와 갱신된 .sig 를 같은 커밋에 넣는다 — 잊으면 agent-poll.php 가 서명 없음으로
#   응답해 에이전트가 자동 업데이트를 건너뛴다(README.md 체크리스트 참고).
# =============================================================================
set -euo pipefail

if [ $# -ne 1 ]; then
  grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi
KEY="$1"
[ -f "$KEY" ] || { echo "개인키를 찾을 수 없습니다: $KEY" >&2; exit 1; }

# 개인키가 이 저장소 안에 있으면 거부한다 — 실수로 저장소 내부에 키를 만들고 서명한 뒤
#   .gitignore 를 놓쳐 그대로 커밋되는 사고를 스크립트 단계에서 막는다. 저장소 루트는
#   이 스크립트(deploy/) 의 부모 디렉터리다.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_ABS="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"
case "$KEY_ABS" in
  "$REPO_ROOT"/*|"$REPO_ROOT")
    echo "개인키가 저장소 안에 있습니다: $KEY_ABS" >&2
    echo "  저장소 밖(예: ~/agent-signing.key)에 두고 다시 실행하세요." >&2
    exit 1
    ;;
esac

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../agent" && pwd)"
SCRIPT="$AGENT_DIR/vuln-inventory-agent.sh"
SIG="$SCRIPT.sig"

[ -f "$SCRIPT" ] || { echo "서명 대상을 찾을 수 없습니다: $SCRIPT" >&2; exit 1; }

openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$SCRIPT" -out "$SIG"

VER="$(grep -m1 -E '^SCRIPT_VERSION=' "$SCRIPT" | cut -d= -f2- | tr -d '"'"'" || true)"
echo "서명 완료: ${VER:-버전미상}"
echo "  $SIG"
echo ">> $SCRIPT 와 $SIG 를 같은 커밋에 넣으세요."
