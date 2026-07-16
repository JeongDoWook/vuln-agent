#!/usr/bin/env bash
# 이 폴더의 *.puml 을 SVG 로 다시 뽑는다. 어느 디렉터리에서 호출해도 자기 위치를 기준으로 동작한다.
set -euo pipefail

d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Windows git-bash 는 컨테이너 절대경로를 멋대로 바꾼다 → MSYS_NO_PATHCONV=1 로 막는다.
# 마운트 경로도 git-bash 에선 윈도 형식(pwd -W)이어야 한다.
if command -v cygpath >/dev/null 2>&1; then
    mount_src="$(cygpath -w "$d")"
else
    mount_src="$d"
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "${mount_src}:/d" -w /d plantuml/plantuml \
    -tsvg -charset UTF-8 "*.puml"   # -charset UTF-8 없으면 한글 라벨이 깨진다
