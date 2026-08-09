#!/usr/bin/env bash
# 저장소의 최신 에이전트를 중앙 서버와 원격 노드에 전송한 뒤 설치·재시작·버전 확인한다.
# 사용: bash deploy/install_staged_agents.sh                     # deploy/agent_nodes.txt 의 목록
#       bash deploy/install_staged_agents.sh 10.0.0.105 user@10.0.0.201   # 대상 직접 지정
set -uo pipefail

PREFIX="${AGENT_PREFIX:-/opt/vuln-agent}"
SSH_USER="${AGENT_SSH_USER:-worker}"
STAGED=".vuln-agent-push.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$SCRIPT_DIR/../agent" && pwd)/vuln-inventory-agent.sh"
# 배포 대상 노드는 저장소에 두지 않는다 — 내부망 인벤토리가 그대로 공개되기 때문이다.
# 형식은 deploy/agent_nodes.txt.template 참고(한 줄에 하나, '#' 주석·빈 줄 허용).
NODES_FILE="${AGENT_NODES_FILE:-$SCRIPT_DIR/agent_nodes.txt}"

if [ $# -gt 0 ]; then
  TARGETS=("$@")
else
  if [ ! -f "$NODES_FILE" ]; then
    echo "노드 목록 파일이 없습니다: $NODES_FILE" >&2
    echo "deploy/agent_nodes.txt.template 을 복사해 대상 노드를 적으세요." >&2
    exit 1
  fi
  TARGETS=()
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && TARGETS+=("$line")
  done < "$NODES_FILE"
  if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "노드 목록이 비어 있습니다: $NODES_FILE" >&2
    echo "deploy/agent_nodes.txt.template 을 참고해 대상 노드를 적으세요." >&2
    exit 1
  fi
fi

[ -f "$SRC" ] || { echo "에이전트 원본이 없습니다: $SRC" >&2; exit 1; }
expected_version="$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)"/\1/p' "$SRC" | head -1)"

echo "== 에이전트 일괄 설치${expected_version:+ : $expected_version} =="
echo "   원본: $SRC"
echo "   설치 경로: $PREFIX/bin/vuln-inventory-agent.sh"
echo

ok=0; fail=0; skip=0

printf '%-28s ' "local"
if ! install -m0600 "$SRC" "$HOME/$STAGED"; then
  echo "실패 (로컬 staging 실패)"
  fail=$((fail + 1))
elif sudo install -m0755 "$HOME/$STAGED" "$PREFIX/bin/vuln-inventory-agent.sh"; then
  rm -f "$HOME/$STAGED"
  sudo systemctl try-restart vuln-agent.service 2>/dev/null || true
  installed="$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)"/\1/p' "$PREFIX/bin/vuln-inventory-agent.sh" | head -1)"
  if [ -n "$expected_version" ] && [ "$installed" = "$expected_version" ]; then
    echo "OK  $installed"
    ok=$((ok + 1))
  else
    echo "실패 (버전 불일치: ${installed:-확인 불가})"
    fail=$((fail + 1))
  fi
else
  echo "실패 (sudo 설치 실패)"
  fail=$((fail + 1))
fi

for target in "${TARGETS[@]}"; do
  case "$target" in *@*) node="$target" ;; *) node="$SSH_USER@$target" ;; esac
  printf '%-28s ' "$node"

  # 저장소의 현재 원본을 먼저 전송한다. 이전 실행이 남긴 staged 파일을 믿지 않으므로
  # 구버전을 실수로 설치할 수 없다. -t 로 각 노드의 sudo 암호 입력을 받는다.
  if ! scp -q -o ConnectTimeout=8 "$SRC" "$node:~/$STAGED"; then
    echo "실패 (전송 실패)"
    fail=$((fail + 1))
    continue
  fi
  if ssh -t -o ConnectTimeout=8 "$node" \
    "sudo install -m0755 \"\$HOME/$STAGED\" '$PREFIX/bin/vuln-inventory-agent.sh' && rm -f \"\$HOME/$STAGED\" && { sudo systemctl try-restart vuln-agent.service 2>/dev/null || true; } && installed=\$(sed -n 's/^SCRIPT_VERSION=\"\\([^\"]*\\)\"/\\1/p' '$PREFIX/bin/vuln-inventory-agent.sh' | head -1) && test \"\$installed\" = '$expected_version' && echo \"OK  \$installed\""
  then
    ok=$((ok + 1))
  else
    echo "실패 (설치·버전 확인 실패)"
    fail=$((fail + 1))
  fi
done

echo
echo "== 결과: 성공 $ok  실패 $fail  건너뜀 $skip =="
[ "$fail" -eq 0 ]
