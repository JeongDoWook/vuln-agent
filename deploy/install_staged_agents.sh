#!/usr/bin/env bash
# 중앙 서버와 원격 노드에 미리 전송된 ~/.vuln-agent-push.sh 를 설치하고 버전을 확인한다.
# 사용: bash deploy/install_staged_agents.sh
#       bash deploy/install_staged_agents.sh 10.3.142.105 worker@10.3.142.201
set -uo pipefail

PREFIX="${AGENT_PREFIX:-/opt/vuln-agent}"
SSH_USER="${AGENT_SSH_USER:-worker}"
STAGED=".vuln-agent-push.sh"
DEFAULT_TARGETS=(
  10.3.142.100 10.3.142.101 10.3.142.102
  10.3.142.103 10.3.142.104 10.3.142.105
  10.3.142.106 10.3.142.107 10.3.142.108
  10.3.142.201
)

if [ $# -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

expected_version=""
if [ -f "$HOME/$STAGED" ]; then
  expected_version="$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)"/\1/p' "$HOME/$STAGED" | head -1)"
fi

echo "== staged 에이전트 설치${expected_version:+ : $expected_version} =="
echo "   설치 경로: $PREFIX/bin/vuln-inventory-agent.sh"
echo

ok=0; fail=0; skip=0

printf '%-28s ' "local"
if [ ! -f "$HOME/$STAGED" ]; then
  echo "건너뜀 (없음: $HOME/$STAGED)"
  skip=$((skip + 1))
elif sudo install -m0755 "$HOME/$STAGED" "$PREFIX/bin/vuln-inventory-agent.sh"; then
  rm -f "$HOME/$STAGED"
  installed="$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)"/\1/p' "$PREFIX/bin/vuln-inventory-agent.sh" | head -1)"
  echo "OK  ${installed:-버전 확인 실패}"
  ok=$((ok + 1))
else
  echo "실패 (sudo 설치 실패)"
  fail=$((fail + 1))
fi

for target in "${TARGETS[@]}"; do
  case "$target" in *@*) node="$target" ;; *) node="$SSH_USER@$target" ;; esac
  printf '%-28s ' "$node"

  # -t 로 각 노드의 sudo 암호 입력을 받을 수 있게 한다. 명령은 한 줄로 유지해 경로가 잘리지 않는다.
  if ssh -t -o ConnectTimeout=8 "$node" \
    "test -f \"\$HOME/$STAGED\" || { echo '건너뜀 (staged 파일 없음)'; exit 3; }; sudo install -m0755 \"\$HOME/$STAGED\" '$PREFIX/bin/vuln-inventory-agent.sh' && rm -f \"\$HOME/$STAGED\" && sed -n 's/^SCRIPT_VERSION=\"\\([^\"]*\\)\"/OK  \\1/p' '$PREFIX/bin/vuln-inventory-agent.sh' | head -1"
  then
    ok=$((ok + 1))
  else
    rc=$?
    if [ "$rc" -eq 3 ]; then skip=$((skip + 1)); else fail=$((fail + 1)); fi
  fi
done

echo
echo "== 결과: 성공 $ok  실패 $fail  건너뜀 $skip =="
[ "$fail" -eq 0 ]
