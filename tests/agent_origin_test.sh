#!/usr/bin/env bash
# =============================================================================
# agent_origin_test.sh — 에이전트의 패키지 출처 판정(collect_pkg_origins).
# =============================================================================
# 왜 필요한가: 출처를 잘못 찍으면 중앙이 그 패키지를 **서드파티**로 보고 "자동 판정 불가" 로
#   남긴다 — 억제도, 조치 가능 여부도 못 붙는다. 실제로 이렇게 당했다:
#
#     curl:  *** 8.14.1-2+deb13u3 100 → /var/lib/dpkg/status   ← 설치본(보안 업데이트에 뒤처짐)
#                8.14.1-2+deb13u4 500 → deb.debian.org trixie  ← 저장소가 지금 주는 것
#
#   설치본 줄만 보면 저장소가 dpkg/status 뿐이라 LOCAL(수동 설치)로 읽힌다. 그런데 이건
#   **데비안 패키지가 낡은 것**이고, 하필 "지금 apt 로 고칠 수 있는" 것들이다
#   (실측 raspberrypi5-00: 이렇게 잘못 찍힌 패키지가 findings 237건).
#
# 실행: bash tests/agent_origin_test.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT/agent/vuln-inventory-agent.sh"

# 함수만 떼어 온다 — 에이전트를 통째로 실행하면 수집이 돌아버린다.
eval "$(sed -n '/^collect_pkg_origins() {/,/^}/p' "$AGENT")"
if ! declare -f collect_pkg_origins >/dev/null; then
  echo "  ✗ 에이전트에서 collect_pkg_origins 를 못 찾았습니다(함수명이 바뀌었나?)" >&2
  exit 1
fi

# collect_pkg_origins() 는 에이전트 본문이 만들어 두는 값들을 그대로 쓴다. 함수만 떼어 오면
#   그것들이 없어서 `set -u` 에 걸려 죽는데, 예전엔 그 실패가 "출처 판정이 틀렸다"로 보였다
#   (실제 증상: `MAX_BYTES: unbound variable` · `progress_heartbeat: command not found` 뒤에
#    기대 줄 4개가 전부 없다고 나옴). 함수가 요구하는 환경을 여기서 명시적으로 세운다.
#   일부러 최소한만 정의한다 — 함수가 새 전역을 요구하기 시작하면 이 테스트가 즉시 터져야 한다.
CMD_TIMEOUT=5
MAX_BYTES=524288                      # 에이전트 기본값과 동일(섹션당 512KB 상한)
# TMP 는 반드시 우리가 만든다. git-bash 는 윈도 환경변수 TMP(C:\Users\…\Temp)를 물려주는데,
#   그 값이 그대로 쓰이면 함수가 만드는 경로가 `C:\Users\…\Temp/.pkg-origins-raw.txt` 가 되어
#   awk 가 그 파일을 못 연다(실측 실패 원인). mktemp -d 는 POSIX 경로를 준다.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ORIGINS_PID=""
progress_heartbeat() { :; }            # 수집 진행률 보고는 이 테스트의 관심사가 아니다
have()    { return 0; }
# timeout 스텁 — 옵션을 건너뛰고 뒤의 명령만 그대로 실행한다.
#   예전엔 `shift` 하나였는데, 에이전트가 `timeout -k 2 <초> …` 로 바뀌자 `-k` 만 벗겨져
#   `2` 를 명령으로 실행하려 했다(= 아무것도 안 나옴). 옵션 형태가 또 바뀌어도 안 깨지게 한다.
timeout() {
  while [ "${1:-}" = "-k" ] || [ "${1:-}" = "-s" ]; do shift 2; done
  shift                                  # 남은 첫 인자 = 제한시간
  "$@"
}
dpkg-query() { printf 'curl\ndocker-ce-cli\nzoom\nvim\n'; }

# apt-cache 는 두 번 불린다: (1) policy — 저장소 목록, (2) policy <패키지들> — 패키지별 버전표.
apt-cache() {
  if [ "$#" -eq 1 ]; then
    cat <<'EOF'
Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://deb.debian.org/debian trixie/main arm64 Packages
     release v=13.1,o=Debian,a=stable,n=trixie,l=Debian,c=main,b=arm64
 500 https://download.docker.com/linux/debian trixie/stable arm64 Packages
     release o=Docker,a=stable,n=trixie,l=Docker CE,c=stable,b=arm64
EOF
    return 0
  fi
  cat <<'EOF'
curl:
  Installed: 8.14.1-2+deb13u3
  Candidate: 8.14.1-2+deb13u4
  Version table:
     8.14.1-2+deb13u4 500
        500 http://deb.debian.org/debian trixie/main arm64 Packages
 *** 8.14.1-2+deb13u3 100
        100 /var/lib/dpkg/status
docker-ce-cli:
  Installed: 5:27.0.3-1~debian.13~trixie
  Candidate: 5:27.0.3-1~debian.13~trixie
  Version table:
 *** 5:27.0.3-1~debian.13~trixie 500
        500 https://download.docker.com/linux/debian trixie/stable arm64 Packages
        100 /var/lib/dpkg/status
zoom:
  Installed: 6.0.2
  Candidate: 6.0.2
  Version table:
 *** 6.0.2 100
        100 /var/lib/dpkg/status
vim:
  Installed: 2:9.1.0861-1
  Candidate: 2:9.1.0861-1
  Version table:
 *** 2:9.1.0861-1 500
        500 http://deb.debian.org/debian trixie/main arm64 Packages
        100 /var/lib/dpkg/status
EOF
}

got="$(collect_pkg_origins)"
fail=0
check() {   # check <라벨> <기대 줄>
  # smoke.sh 와 같은 이유로 파이프를 쓰지 않는다 — pipefail + `grep -q` 조기종료 조합은
  #   입력이 파이프 버퍼보다 커지는 순간 SIGPIPE(141)로 오판한다. 여기 입력은 지금은 작아
  #   무해하지만, 판정 헬퍼가 입력 크기에 따라 뒤집히는 형태를 저장소에 남기지 않는다.
  if ! grep -qxF "$2" <<< "$got"; then
    printf '  ✗ [%s] 기대한 줄이 없습니다: %s\n' "$1" "$2" >&2
    fail=$((fail + 1))
  fi
}

# 핵심: 설치본이 인덱스에 없어도(보안 업데이트에 뒤처짐) 출처는 **데비안**이다.
check "뒤처진 데비안 패키지" "$(printf 'curl\tDebian')"
# 서드파티는 그대로 서드파티여야 한다 — 이걸 데비안으로 읽으면 진짜 취약점을 숨긴다(미탐).
check "서드파티 저장소"     "$(printf 'docker-ce-cli\tDocker')"
# 어느 저장소도 팔지 않는 것만 LOCAL(수동 .deb 설치).
check "수동 설치"           "$(printf 'zoom\tLOCAL')"
check "평범한 배포판 패키지" "$(printf 'vim\tDebian')"

# ── 저장소를 하나도 모르는 시스템(도커 이미지·폐쇄망) ──────────────────────
# apt 인덱스가 비어 있으면 모든 패키지의 소스가 dpkg/status 뿐이다. 그걸 LOCAL(수동 설치)로 읽으면
# 시스템 전체가 서드파티가 되고 벤더 판정이 통째로 꺼진다(실측 ubuntu:24.04: 억제 0건).
# 모르는 것은 모른다고 해야 한다 → 아무것도 출력하지 않는다(중앙은 "정보 없음 → 배포판" 으로 본다).
apt-cache() {
  if [ "$#" -eq 1 ]; then
    printf 'Package files:\n 100 /var/lib/dpkg/status\n     release a=now\n'
    return 0
  fi
  cat <<'EOF'
curl:
  Installed: 8.5.0-2ubuntu10.6
  Candidate: 8.5.0-2ubuntu10.6
  Version table:
 *** 8.5.0-2ubuntu10.6 100
        100 /var/lib/dpkg/status
EOF
}
empty="$(collect_pkg_origins)"
if [ -n "$empty" ]; then
  printf '  ✗ [저장소를 모르면 출처를 말하지 않는다] 출력이 있음: %s\n' "$empty" >&2
  fail=$((fail + 1))
fi

if [ "$fail" -eq 0 ]; then
  echo "agent_origin: 통과"
  exit 0
fi
printf 'agent_origin: %d건 실패\n실제 출력:\n%s\n' "$fail" "$got" >&2
exit 1
