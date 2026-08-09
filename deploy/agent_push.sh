#!/usr/bin/env bash
# =============================================================================
# agent_push.sh — 이미 설치된 노드들에 **에이전트 본체만** 밀어넣고 즉시 확인한다.
# =============================================================================
# 왜 필요한가:
#   에이전트는 자기를 갱신하지 않는다(중앙은 노드에 아무것도 내려보내지 않는다 — 노드가
#   밀어 올리기만 한다). 그래서 vuln-inventory-agent.sh 를 고치면 노드마다 다시 깔아야 했다.
#
# 무엇을 하나:
#   각 노드에 새 vuln-inventory-agent.sh 를 <prefix>/bin/ 으로 덮고, 즉시 1회 수집·전송해
#   결과(HTTP)를 확인한다. **토큰·URL·타이머는 건드리지 않는다** — 노드의 agent.env(600)에
#   이미 있으므로 재입력이 필요 없고, 토큰이 이 스크립트를 거쳐 가지도 않는다.
#
# 무엇을 안 하나:
#   - 신규 설치를 하지 않는다. 안 깔린 노드는 건너뛰고 알려준다(정석은 그 서버에 들어가
#     install-agent.sh 를 대화형으로 돌리는 것 — 토큰 발급이 사람 판단이라 그렇다).
#   - 설치기(install-agent.sh)가 바뀐 경우(타이머·유닛·preflight)는 대상이 아니다.
#     그건 노드에서 install-agent.sh 를 다시 돌려야 한다.
#
# 왜 웹이 아니라 CLI 인가:
#   웹에서 푸시하려면 PHP 컨테이너가 전 노드에 root 로 설치할 수 있는 SSH 키를 들어야 한다.
#   웹앱이 한 번 뚫리면 전 노드 root 장악으로 번진다. 사람의 SSH 키로 CLI 에서 돈다.
#
# 사용:
#   bash deploy/agent_push.sh 10.0.0.100 10.0.0.101 10.0.0.102
#   bash deploy/agent_push.sh user@10.0.0.100 deploy@10.0.0.200   # 계정을 섞어 쓸 때
#   AGENT_SSH_USER=pi bash deploy/agent_push.sh 10.0.0.103            # 기본 계정 바꾸기
#   AGENT_PREFIX=/apps/vulnagent bash deploy/agent_push.sh 10.0.0.200 # 설치 경로가 다를 때
# =============================================================================
set -euo pipefail

SSH_USER="${AGENT_SSH_USER:-worker}"
PREFIX="${AGENT_PREFIX:-/opt/vuln-agent}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../agent" && pwd)/vuln-inventory-agent.sh"

if [ $# -eq 0 ]; then
  grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi
[ -f "$SRC" ] || { echo "에이전트 본체를 찾을 수 없습니다: $SRC" >&2; exit 1; }

VER="$(grep -m1 -E '^SCRIPT_VERSION=' "$SRC" | cut -d= -f2- | tr -d '"'"'" || true)"
echo "== 에이전트 배포 : ${VER:-버전미상} =="
echo "   원본: $SRC"
echo

OK=(); FAIL=(); SKIP=()

for target in "$@"; do
  case "$target" in *@*) node="$target" ;; *) node="$SSH_USER@$target" ;; esac
  printf '%-28s ' "$node"

  # 1) 접근 가능한가 + 설치돼 있나. 이 둘을 **구분**한다 — 예전엔 SSH 연결 실패(노드 다운·sshd 죽음)를
  #    "미설치" 로 표시해 엉뚱한 안내(install-agent.sh)를 했다. 실측: rpi5-03 이 ping 은 되는데
  #    sshd 만 죽어(Connection reset) "미설치" 로 나왔다.
  #    ssh 는 연결 자체가 실패하면 255 를 준다. 원격 명령은 `… && echo INSTALLED || echo MISSING`
  #    라 항상 성공(echo)하므로, 종료코드로 "연결됨/안됨" 을, 출력으로 "설치됨/아님" 을 가른다.
  probe=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$node" \
            "sudo test -f '$PREFIX/etc/agent.env' && echo INSTALLED || echo MISSING" 2>/dev/null)
  if [ $? -eq 255 ] || [ -z "$probe" ]; then
    echo "건너뜀 (접근 불가 — SSH 연결 실패. 노드 다운이거나 sshd 문제: 'ssh $node' 로 직접 확인)"
    SKIP+=("$node"); continue
  fi
  if [ "$probe" != INSTALLED ]; then
    echo "건너뜀 (미설치 — 그 서버에서 install-agent.sh 를 먼저 돌리세요)"
    SKIP+=("$node"); continue
  fi

  # 2) 본체만 교체. 홈으로 올린 뒤 root 소유 경로로 install(권한 0755) → 홈의 사본은 지운다.
  if ! scp -q -o BatchMode=yes "$SRC" "$node:~/.vuln-agent-push.sh" 2>/dev/null; then
    echo "실패 (전송 불가 — SSH/scp 확인)"
    FAIL+=("$node"); continue
  fi
  if ! ssh -o BatchMode=yes "$node" \
        "sudo install -m 0755 ~/.vuln-agent-push.sh '$PREFIX/bin/vuln-inventory-agent.sh' && rm -f ~/.vuln-agent-push.sh" 2>/dev/null; then
    echo "실패 (설치 불가 — sudo 권한 확인)"
    ssh -o BatchMode=yes "$node" 'rm -f ~/.vuln-agent-push.sh' 2>/dev/null || true
    FAIL+=("$node"); continue
  fi

  # 3) 즉시 1회 수집·전송 — 새 에이전트는 전송을 못 하면 종료코드 1 이다(조용한 실패 방지).
  printf '교체됨 → 확인중… '
  if out="$(ssh -o BatchMode=yes "$node" "sudo '$PREFIX/bin/run.sh'" 2>&1)"; then
    echo "OK  $(printf '%s' "$out" | grep -m1 '전송 성공' || echo '전송 성공')"
    OK+=("$node")
  else
    echo "전송 실패"
    printf '%s\n' "$out" | grep -m1 -E '전송 (실패|생략)' | sed 's/^/    /' || true
    FAIL+=("$node")
  fi
done

echo
echo "== 결과: 성공 ${#OK[@]} · 실패 ${#FAIL[@]} · 건너뜀 ${#SKIP[@]} =="
[ ${#FAIL[@]} -eq 0 ] || { printf '   실패: %s\n' "${FAIL[*]}"; exit 1; }
