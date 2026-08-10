#!/usr/bin/env bash
# collect_project_deps_installed() 의 Ruby 소스 2종(Gemfile.lock / vendored gemspec) 검증.
# 에이전트 스크립트에서 함수 정의만 뽑아 eval 하므로 실제 배포되는 코드를 그대로 검사한다.
set -uo pipefail
cd "$(dirname "$0")/.."
AGENT=agent/vuln-inventory-agent.sh
export LC_ALL=C          # sort -u 결과 순서를 로케일과 무관하게 고정

have() { command -v "$1" >/dev/null 2>&1; }
eval "$(sed -n '/^emit_gemfile_lock() {$/,/^}$/p' "$AGENT")"
eval "$(sed -n '/^emit_gemspec_name() {$/,/^}$/p' "$AGENT")"
eval "$(sed -n '/^collect_project_deps_installed() {$/,/^}$/p' "$AGENT")"
SCAN_MAX_FILES=3000; SCAN_MAX_DEPTH=12

FIX=$(mktemp -d "tests/.fixtures.XXXXXX") || exit 1
trap 'rm -rf "$FIX"' EXIT
mkdir -p "$FIX/app1" "$FIX/app2" "$FIX/app3/vendor/bundle/ruby/3.1.0/specifications"

# 1) 정상 Gemfile.lock — 4칸(패키지)과 6칸(의존성 선언)이 섞여 있다.
cat > "$FIX/app1/Gemfile.lock" <<'EOF'
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
      activesupport (= 7.0.4)
      rack (~> 2.0, >= 2.2.0)
    nokogiri (1.13.8-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.4)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)

BUNDLED WITH
   2.3.26
EOF

# 2) PATH(로컬)·GIT(git 소스) 섹션이 섞인 Gemfile.lock — GEM 것만 나와야 한다.
cat > "$FIX/app2/Gemfile.lock" <<'EOF'
GIT
  remote: https://github.com/rails/rails.git
  revision: abc123def456
  specs:
    rails (7.1.0.alpha)
      activesupport (= 7.1.0.alpha)

PATH
  remote: vendor/mygem
  specs:
    mygem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    puma (5.6.5)

PLATFORMS
  ruby
EOF

# 3) vendored gemspec — 파일명에서 이름·버전을 가른다(플랫폼 접미사 포함).
SPECDIR="$FIX/app3/vendor/bundle/ruby/3.1.0/specifications"
: > "$SPECDIR/rack-2.2.4.gemspec"
: > "$SPECDIR/nokogiri-1.13.8-x86_64-linux.gemspec"
: > "$SPECDIR/rails-html-sanitizer-1.4.3.gemspec"
: > "$SPECDIR/libv8-node-18.13.0.0-x86_64-linux.gemspec"
: > "$SPECDIR/weird.gemspec"                    # 버전을 못 가른다 → 버려야 한다

PROJECT_SCAN_ROOTS="$FIX"
GOT=$(collect_project_deps_installed)
WANT='gem|actionpack|7.0.4
gem|libv8-node|18.13.0.0
gem|nokogiri|1.13.8
gem|puma|5.6.5
gem|rack|2.2.4
gem|rails-html-sanitizer|1.4.3'

rc=0
if [ "$GOT" != "$WANT" ]; then
  echo "FAIL ruby_deps_parser: 기대와 다름"
  diff <(printf '%s\n' "$WANT") <(printf '%s\n' "$GOT")
  rc=1
fi

# 오탐 확인 — 6칸 의존성 선언의 제약 표현이 버전으로 새어나오면 안 된다.
if printf '%s\n' "$GOT" | grep -qE '\(|=|~>|,'; then
  echo "FAIL ruby_deps_parser: 제약 표현이 버전으로 유출됨"
  printf '%s\n' "$GOT" | grep -E '\(|=|~>|,'
  rc=1
fi

[ "$rc" -eq 0 ] && echo "OK  ruby_deps_parser: 6건 일치 + 제약 표현 유출 없음"
exit "$rc"
