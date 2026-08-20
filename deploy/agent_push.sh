#!/usr/bin/env bash
# =============================================================================
# agent_push.sh — 이미 설치된 노드들에 **에이전트 본체만** 밀어넣고 즉시 확인한다.
# =============================================================================
# 왜 필요한가:
#   에이전트는 poll 응답으로 구버전을 감지하면 자동으로 갱신한다(다음 poll 주기 이내, 보통
#   10초~수십초) — 이 스크립트는 그 주기를 기다리지 않고 지금 즉시 밀어넣고 확인하고 싶을 때
#   쓴다. vuln-inventory-agent.sh 를 배포(agent-src/)에 반영하면 자동 업데이트도 같은 파일을
#   보므로, 이 스크립트는 "지금 당장" 용 지름길이지 유일한 갱신 경로가 아니다.
#
# 무엇을 하나:
#   각 노드에 새 vuln-inventory-agent.sh 를 <prefix>/bin/ 으로 덮고, 즉시 1회 수집·전송해
#   결과(HTTP)를 확인한다. **토큰·URL·타이머는 건드리지 않는다** — 노드의 agent.env(600)에
#   이미 있으므로 재입력이 필요 없고, 토큰이 이 스크립트를 거쳐 가지도 않는다.
#
# --with-runner (run.sh 도 같이 갱신):
#   run.sh 는 install-agent.sh 가 만드는 파일이라 자동 업데이트 대상이 아니다 — 그래서 예전엔
#   run.sh 가 바뀔 때마다 사람이 노드마다 들어가 설치기를 다시 돌려야 했다(실제로 그걸 안 해서,
#   중앙이 켠 무결성 검사가 노드에 영원히 도달하지 못한 사고가 있었다). 이 옵션은 설치기를
#   노드로 보내 `--runner-only` 로 돌린다 — run.sh 와 systemd 유닛만 다시 만들고
#   **토큰·서버주소·CA·공개키는 건드리지 않는다**(그 파일들을 읽지도 쓰지도 않는다).
#
# 무엇을 안 하나:
#   - 신규 설치를 하지 않는다. 안 깔린 노드는 건너뛰고 알려준다(정석은 그 서버에 들어가
#     install-agent.sh 를 대화형으로 돌리는 것 — 토큰 발급이 사람 판단이라 그렇다).
#   - 설치기(install-agent.sh)의 나머지 변경(preflight·CA·토큰 처리)은 여전히 대상이 아니다.
#     그건 노드에서 install-agent.sh 를 처음부터 다시 돌려야 한다.
#
# ⚠ 의도적 다운그레이드는 자동 업데이트가 즉시 되돌린다:
#   장애 대응으로 이 스크립트를 써서 **구버전**을 밀어넣어도, agent-poll.php 는 "배포된
#   agent-src/vuln-inventory-agent.sh 보다 낮으면 무조건 갱신 지시"만 한다(의도적 다운그레이드와
#   실수로 뒤처진 노드를 구분하지 못한다) — 그 노드의 run.sh 가 다음 poll(수십 초 이내)에서
#   agent-src 쪽 버전으로 다시 올려버린다. 정말로 구버전을 유지해야 하면(예: 새 버전에 버그가
#   있어 롤백 검증 중) 순서를 반대로 한다: 1) agent-src/vuln-inventory-agent.sh 자체를 원하는
#   구버전으로 되돌려 배포(그래야 agent-poll.php 가 그 버전을 "최신"으로 보고 갱신 지시를
#   멈춘다), 2) 그다음에 이 스크립트로 노드에 밀어넣는다. agent-src 를 안 되돌리고 노드만
#   구버전으로 밀어넣는 조합은 쓰지 않는다.
#
# 왜 웹이 아니라 CLI 인가:
#   웹에서 푸시하려면 PHP 컨테이너가 전 노드에 root 로 설치할 수 있는 SSH 키를 들어야 한다.
#   웹앱이 한 번 뚫리면 전 노드 root 장악으로 번진다. 사람의 SSH 키로 CLI 에서 돈다.
#
# 사용:
#   bash deploy/agent_push.sh 10.0.0.100 10.0.0.101 10.0.0.102
#   bash deploy/agent_push.sh --with-runner 10.0.0.100            # run.sh 도 같이 갱신
#   bash deploy/agent_push.sh user@10.0.0.100 deploy@10.0.0.200   # 계정을 섞어 쓸 때
#   AGENT_SSH_USER=pi bash deploy/agent_push.sh 10.0.0.103            # 기본 계정 바꾸기
#   AGENT_PREFIX=/apps/vulnagent bash deploy/agent_push.sh 10.0.0.200 # 설치 경로가 다를 때
# =============================================================================
set -euo pipefail

SSH_USER="${AGENT_SSH_USER:-worker}"
PREFIX="${AGENT_PREFIX:-/opt/vuln-agent}"
AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../agent" && pwd)"
SRC="$AGENT_DIR/vuln-inventory-agent.sh"
INSTALLER="$AGENT_DIR/install-agent.sh"

WITH_RUNNER=0
NODES=()
for a in "$@"; do
  case "$a" in
    --with-runner) WITH_RUNNER=1 ;;
    -h|--help)     grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)            echo "알 수 없는 옵션: $a" >&2; exit 1 ;;
    *)             NODES+=("$a") ;;
  esac
done

if [ ${#NODES[@]} -eq 0 ]; then
  grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi
[ -f "$SRC" ] || { echo "에이전트 본체를 찾을 수 없습니다: $SRC" >&2; exit 1; }
if [ "$WITH_RUNNER" = 1 ] && [ ! -f "$INSTALLER" ]; then
  echo "설치기를 찾을 수 없습니다: $INSTALLER" >&2; exit 1
fi

VER="$(grep -m1 -E '^SCRIPT_VERSION=' "$SRC" | cut -d= -f2- | tr -d '"'"'" || true)"
echo "== 에이전트 배포 : ${VER:-버전미상} =="
echo "   원본: $SRC"
[ "$WITH_RUNNER" = 1 ] && echo "   run.sh 도 갱신합니다(--with-runner) — 토큰·주소는 건드리지 않습니다."
echo

OK=(); FAIL=(); SKIP=()

for target in "${NODES[@]}"; do
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

  # 3) (선택) run.sh 갱신 — 설치기를 보내 --runner-only 로 돌린다. agent.env 는 안 건드린다.
  if [ "$WITH_RUNNER" = 1 ]; then
    if ! scp -q -o BatchMode=yes "$INSTALLER" "$node:~/.vuln-agent-installer.sh" 2>/dev/null; then
      echo "실패 (설치기 전송 불가 — SSH/scp 확인)"
      FAIL+=("$node"); continue
    fi
    if ! ssh -o BatchMode=yes "$node" "sudo bash ~/.vuln-agent-installer.sh --runner-only --prefix '$PREFIX' >/dev/null && rm -f ~/.vuln-agent-installer.sh" 2>/dev/null; then
      echo "실패 (run.sh 갱신 불가 — sudo 권한/설치 상태 확인)"
      ssh -o BatchMode=yes "$node" 'rm -f ~/.vuln-agent-installer.sh' 2>/dev/null || true
      FAIL+=("$node"); continue
    fi
    printf 'run.sh 갱신됨 → '
  fi

  # 4) 즉시 1회 수집·전송 — 새 에이전트는 전송을 못 하면 종료코드 1 이다(조용한 실패 방지).
  #    run.sh 를 부르지 않는다: 그건 데몬(무한 while 루프)이라 이 ssh 가 영원히 안 끝나고
  #    (예전엔 그렇게 불러 확인 단계에서 매달렸다), `--once` 를 줘도 정기수집 만기가
  #    아니면 아무것도 안 돈다. install-agent.sh 의 마지막 확인과 같은 방식으로
  #    본체를 직접 부른다 — agent.env 를 그 자리에서만 읽어 env 로 넘긴다(토큰은 argv 에 안 남는다).
  printf '교체됨 → 확인중… '
  verify_cmd="set -a; . '$PREFIX/etc/agent.env'; set +a; exec '$PREFIX/bin/vuln-inventory-agent.sh' -o '$PREFIX/logs/last.json'"
  if out="$(ssh -o BatchMode=yes "$node" "sudo bash -c \"$verify_cmd\"" 2>&1)"; then
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
