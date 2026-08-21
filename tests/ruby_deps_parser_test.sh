#!/usr/bin/env bash
# collect_project_deps_installed() 의 Ruby 소스 2종(Gemfile.lock / vendored gemspec) 검증.
# 에이전트 스크립트에서 함수 정의만 뽑아 eval 하므로 실제 배포되는 코드를 그대로 검사한다.
set -uo pipefail
cd "$(dirname "$0")/.."
AGENT=agent/vuln-inventory-agent.sh
export LC_ALL=C          # sort -u 결과 순서를 로케일과 무관하게 고정

have() { command -v "$1" >/dev/null 2>&1; }
eval "$(sed -n '/^emit_gemfile_lock() {$/,/^}$/p' "$AGENT")"
eval "$(sed -n '/^gemspec_license() {$/,/^}$/p' "$AGENT")"
eval "$(sed -n '/^emit_gemspec_name() {$/,/^}$/p' "$AGENT")"
eval "$(sed -n '/^collect_project_deps_installed() {$/,/^}$/p' "$AGENT")"
SCAN_MAX_FILES=3000; SCAN_MAX_DEPTH=12

FIX=$(mktemp -d "tests/.fixtures.XXXXXX") || exit 1
LIC=$(mktemp "tests/.lic-ruby.XXXXXX") || exit 1
trap 'rm -rf "$FIX" "$LIC"' EXIT
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

# 3) vendored gemspec — 이름·버전은 파일명에서, 라이선스는 본문(fd 3)에서 읽는다.
#    본문은 ruby:3.2-slim 의 specifications/*.gemspec 실측 형식을 그대로 쓴다.
SPECDIR="$FIX/app3/vendor/bundle/ruby/3.1.0/specifications"

# 3-a) 단수(`s.license = "..."`) — 값 하나.
cat > "$SPECDIR/rack-2.2.4.gemspec" <<'EOF'
# -*- encoding: utf-8 -*-
# stub: rack 2.2.4 ruby lib

Gem::Specification.new do |s|
  s.name = "rack".freeze
  s.version = "2.2.4"
  s.homepage = "https://github.com/rack/rack".freeze
  s.license = "MIT".freeze
  s.summary = "a modular Ruby webserver interface".freeze
end
EOF

# 3-b) 복수(`s.licenses = [...]`) — 값 하나. 변수명이 `s.` 가 아닌 경우도 함께 본다.
cat > "$SPECDIR/nokogiri-1.13.8-x86_64-linux.gemspec" <<'EOF'
# -*- encoding: utf-8 -*-
# stub: nokogiri 1.13.8 x86_64-linux lib

Gem::Specification.new do |spec|
  spec.name = "nokogiri".freeze
  spec.version = "1.13.8"
  spec.licenses = ["MIT".freeze]
  spec.summary = "Nokogiri parses and searches XML/HTML".freeze
end
EOF

# 3-c) 복수 — 값이 여럿이면 composer 분기와 같은 관례로 " OR " 로 잇는다.
cat > "$SPECDIR/rails-html-sanitizer-1.4.3.gemspec" <<'EOF'
# -*- encoding: utf-8 -*-
# stub: rails-html-sanitizer 1.4.3 ruby lib

Gem::Specification.new do |s|
  s.name = "rails-html-sanitizer".freeze
  s.version = "1.4.3"
  s.licenses = ["Ruby".freeze, "BSD-2-Clause".freeze]
  s.summary = "HTML sanitization for Rails applications".freeze
end
EOF

# 3-d) 라이선스 없음 — fd 3 으로 아무것도 나오면 안 된다(빈 문자열 금지).
#      `s.description` 안의 "license" 문자열이 라이선스로 새지 않는지도 같이 본다.
cat > "$SPECDIR/libv8-node-18.13.0.0-x86_64-linux.gemspec" <<'EOF'
# -*- encoding: utf-8 -*-
# stub: libv8-node 18.13.0.0 x86_64-linux lib

Gem::Specification.new do |s|
  s.name = "libv8-node".freeze
  s.version = "18.13.0.0"
  s.description = "Distributes the libv8 binary; upstream says license = MIT for the wrapper".freeze
  s.summary = "Distribution of the V8 JavaScript engine".freeze
end
EOF

# 3-e) 파일명에서 버전을 못 가른다 → stdout 도 fd 3 도 아무것도 내지 않는다.
cat > "$SPECDIR/weird.gemspec" <<'EOF'
Gem::Specification.new do |s|
  s.name = "weird".freeze
  s.licenses = ["MIT".freeze]
end
EOF

# 3-f) 값이 리터럴이 아니다(변수) → 확신할 수 없으니 라이선스를 내지 않는다.
cat > "$SPECDIR/dyngem-0.3.1.gemspec" <<'EOF'
Gem::Specification.new do |gem|
  gem.name = "dyngem".freeze
  gem.version = "0.3.1"
  gem.licenses = LICENSES
end
EOF

# 3-g) 빈 배열 → 라이선스 없음과 같다.
cat > "$SPECDIR/emptylic-1.0.0.gemspec" <<'EOF'
Gem::Specification.new do |s|
  s.name = "emptylic".freeze
  s.version = "1.0.0"
  s.licenses = []
end
EOF

PROJECT_SCAN_ROOTS="$FIX"
GOT=$(collect_project_deps_installed 3>>"$LIC")
WANT='gem|actionpack|7.0.4
gem|dyngem|0.3.1
gem|emptylic|1.0.0
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

# 라이선스 fd 3 — 단수/복수/여러 값 세 경우가 4필드로 나와야 한다.
for want in 'gem|rack|2.2.4|MIT' \
            'gem|nokogiri|1.13.8|MIT' \
            'gem|rails-html-sanitizer|1.4.3|Ruby OR BSD-2-Clause'; do
  if ! grep -qxF "$want" "$LIC"; then
    echo "FAIL ruby_deps_parser: 라이선스 fd 3 에 '$want' 없음"
    cat "$LIC"
    rc=1
  fi
done
# 라이선스가 없는 경우(없음·리터럴 아님·빈 배열·버전 못 가름)는 fd 3 에 한 줄도 없어야 한다.
#   빈 문자열(`gem|이름|버전|`)이 새는 것도, description 안의 `license = ...` 문자열이 값으로
#   새는 것도(libv8-node 픽스처) 여기서 잡힌다.
if grep -qE '^gem\|(libv8-node|dyngem|emptylic|weird)\|' "$LIC"; then
  echo "FAIL ruby_deps_parser: 라이선스 없는 gem 이 fd 3 으로 유출됨"
  grep -E '^gem\|(libv8-node|dyngem|emptylic|weird)\|' "$LIC"
  rc=1
fi
if grep -qE '\|$' "$LIC"; then
  echo "FAIL ruby_deps_parser: 빈 라이선스가 fd 3 으로 유출됨"
  rc=1
fi
# gemspec 본문의 다른 필드(description 등)가 라이선스로 새면 안 된다.
if grep -qE 'Distributes|LICENSES|Nokogiri|webserver|MIT for' "$LIC"; then
  echo "FAIL ruby_deps_parser: 본문의 다른 필드가 라이선스로 유출됨"
  grep -E 'Distributes|LICENSES|Nokogiri|webserver' "$LIC"
  rc=1
fi

[ "$rc" -eq 0 ] && echo "OK  ruby_deps_parser: 8건 일치 + 제약 표현 유출 없음 + 라이선스 fd3(단수/복수/여러값/없음)"
exit "$rc"
