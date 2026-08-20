#!/usr/bin/env bash
# 에이전트 서브셸 export 계약 검사 — agent/vuln-inventory-agent.sh 를 정적으로 읽기만 한다
# (실행하지 않는다. 실행하면 수집이 시작된다). docker 불필요, 실측 0.35초.
#
# 왜 있나: 수집 함수들은 `timeout ... bash -c` **서브셸**에서 돈다. 서브셸이 볼 수 있는 함수는
# `export -f` 로 내보낸 것뿐인데, 헬퍼를 새로 뽑으면서 export 를 빠뜨리는 사고가 두 번 났다
# (둘 다 PR #749 에서 한꺼번에 발견·수정):
#   · #735(3.15) pip_meta_license  → pip 라이선스가 34.8% → 6.1% 로 떨어짐(운영 실측)
#   · #559(3.13) emit_gemfile_lock·emit_gemspec_name·emit_yarn_lock·emit_pnpm_lock·emit_poetry_lock
#                → gem 이 운영 인벤토리에 0건. yarn/pnpm/poetry 도 마찬가지
# 왜 아무도 못 봤나: 호출부가 stderr 를 2>/dev/null 로 버려 `command not found` 가 안 보이고,
# 그 소스만 조용히 0건이 된다. 그리고 **단위 테스트는 함수를 같은 셸에서 부르므로 이 버그를
# 구조적으로 못 잡는다** — #735 는 테스트를 통과하고 운영에서 깨졌다.
#
# 무엇을 하나: `export -f` 로 내보낸 함수에서 **전이적으로 도달 가능한** 호출 중, 이 스크립트가
# 정의한 함수인데 export 목록에 없는 것이 있으면 실패한다. 한 단계만 보면 "내보낸 함수 → 내보낸
# 헬퍼 → 안 내보낸 헬퍼" 를 놓치므로 도달 가능한 전부를 본다.
#
# 한계(의도적): 셸 함수 정의는 **열 0 에서 시작하는 것만** 본다(이 스크립트의 관례이자, awk/jq
# 프로그램 안의 `function foo() {` 를 셸 함수로 오인하지 않는 유일하게 값싼 경계다).
# 외부 명령(sed·awk·jq·grep)과 셸 빌트인은 애초에 대상이 아니다 — 이 스크립트가 정의한 함수
# 이름만 본다. 오탐이 한 번 나면 검사가 무시당하므로 범위를 좁게 잡았다.
#
# exit 0 = 통과 / exit 1 = export 누락(또는 검사 대상 부재).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

script='agent/vuln-inventory-agent.sh'

[ -f "$script" ] || {
  printf 'agent export contract: 검사 대상이 없습니다 — %s\n' "$script" >&2
  exit 1
}
err=$(mktemp)
trap 'rm -f "$err"' EXIT

awk '
# ── 원문 보관 (본문 범위를 나중에 잘라야 하므로 전체를 들고 간다) ─────────────
{ line[NR] = $0 }

# ① export -f 로 내보낸 이름
/^[ \t]*export[ \t]+-f[ \t]/ {
  s = $0
  sub(/^[ \t]*export[ \t]+-f[ \t]+/, "", s)
  sub(/[ \t]*#.*$/, "", s)
  n = split(s, a, /[ \t]+/)
  for (i = 1; i <= n; i++)
    if (a[i] ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
      if (!(a[i] in exported)) nexport++
      exported[a[i]] = 1
      if (!(a[i] in expline)) expline[a[i]] = NR
    }
}

# ② 이 스크립트가 정의한 함수 이름 (열 0 에서 시작하는 것만 — 위 "한계" 주석 참고)
/^[A-Za-z_][A-Za-z0-9_]*[ \t]*\(\)[ \t]*\{/ {
  nm = $0; sub(/[ \t]*\(\).*$/, "", nm); remember(nm, NR)
}
/^function[ \t]+[A-Za-z_][A-Za-z0-9_]*([ \t]*\(\))?[ \t]*\{/ {
  nm = $0
  sub(/^function[ \t]+/, "", nm)
  sub(/[ \t]*(\(\))?[ \t]*\{.*$/, "", nm)
  remember(nm, NR)
}

function remember(nm, ln) {
  if (nm in defline) return          # 재정의는 첫 정의만 본다
  defline[nm] = ln
  names[++ndef] = nm
}

END {
  # ── ③ 각 함수 본문 범위를 정하고, 줄마다 "누구의 본문인가" 를 새긴다 ────────
  for (i = 1; i <= ndef; i++) {
    s = defline[names[i]]
    nextstart = (i < ndef) ? defline[names[i + 1]] : NR + 1
    # 한 줄짜리 정의(have() { ...; })인지는 그 줄의 중괄호 짝으로 본다. "끝이 } 인가" 로 보면
    # `foo() {  # ${x}` 같은 헤더를 한 줄짜리로 오인해 본문을 통째로 놓친다.
    o = line[s]; c = line[s]
    if (gsub(/\{/, "{", o) == gsub(/\}/, "}", c)) {
      e = s
    } else {
      e = nextstart - 1                     # 닫는 } 를 못 찾으면 다음 정의 직전까지
      for (j = s + 1; j < nextstart; j++)
        if (line[j] ~ /^\}/) { e = j; break }
    }
    for (j = s; j <= e; j++) owner[j] = names[i]
  }

  # ── ④ 본문 안에서 호출되는 "정의된 함수 이름" 을 모아 호출 그래프를 만든다 ──
  for (j = 1; j <= NR; j++) {
    if (!(j in owner)) continue
    l = line[j]
    if (l ~ /^[ \t]*#/) continue                                   # 통째 주석 줄
    sub(/^[A-Za-z_][A-Za-z0-9_]*[ \t]*\(\)[ \t]*\{/, "", l)        # 정의 헤더 제거
    sub(/^function[ \t]+[A-Za-z_][A-Za-z0-9_]*([ \t]*\(\))?[ \t]*\{/, "", l)
    # 이름을 하나씩 정규식으로 대조하면 줄마다 정규식이 재컴파일돼 느리다(실측 5초).
    # 식별자 토큰으로 쪼개 해시로 조회한다 — 같은 결과에 0.2초.
    nt = split(l, tok, /[^A-Za-z0-9_]+/)
    for (t = 1; t <= nt; t++) {
      m = tok[t]
      if (!(m in defline)) continue
      if (!((owner[j] SUBSEP m) in calls)) {
        calls[owner[j] SUBSEP m] = 1
        callline[owner[j] SUBSEP m] = j
      }
    }
  }

  bad = 0

  # ── export 했는데 정의가 없는 이름 (서브셸에서 곧바로 command not found) ────
  for (nm in exported)
    if (!(nm in defline)) {
      bad++
      printf "  export -f %s (%s:%d) — 이 스크립트에 %s 정의가 없습니다\n",
             nm, FILENAME, expline[nm], nm > "/dev/stderr"
    }

  # ── ⑤ 내보낸 함수에서 전이적으로 도달 가능한 전부를 훑는다 ─────────────────
  qn = 0
  for (i = 1; i <= ndef; i++)
    if (exported[names[i]]) { queue[++qn] = names[i]; seen[names[i]] = 1; origin[names[i]] = names[i] }

  head = 0
  while (head < qn) {
    x = queue[++head]
    for (i = 1; i <= ndef; i++) {
      m = names[i]
      if (m == x) continue
      if (!((x SUBSEP m) in calls)) continue
      if (!exported[m]) {
        k = x SUBSEP m
        if (!(k in reported)) {
          reported[k] = 1
          bad++
          if (origin[x] == x)
            printf "  %s (export 됨) → %s (미export) — %s:%d\n",
                   x, m, FILENAME, callline[k] > "/dev/stderr"
          else
            printf "  %s (export 됨) → … → %s → %s (미export) — %s:%d\n",
                   origin[x], x, m, FILENAME, callline[k] > "/dev/stderr"
        }
      }
      if (!(m in seen)) { seen[m] = 1; origin[m] = origin[x]; queue[++qn] = m }
    }
  }

  if (bad == 0) {
    printf "agent export contract: ok (정의 %d개 · export %d개 검사)\n", ndef, nexport
    exit 0
  }
  exit 1
}
' "$script" 2> "$err" || {
  {
    printf 'agent export contract: 서브셸에서 못 보는 헬퍼가 있습니다 — %s\n' "$script"
    cat "$err"
    printf '  수집 함수는 `timeout ... bash -c` 서브셸에서 돕니다. 서브셸이 볼 수 있는 함수는\n'
    printf '  `export -f` 로 내보낸 것뿐이라, 위 헬퍼는 서브셸에서 `command not found` 가 됩니다.\n'
    printf '  호출부가 stderr 를 2>/dev/null 로 버리므로 오류는 안 보이고 **그 소스만 조용히 0건**이 됩니다.\n'
    printf '  실제로 두 번 났습니다: #735 는 pip 라이선스가 34.8%% → 6.1%% 로 떨어졌고,\n'
    printf '  #559 는 gem 이 운영 인벤토리에 0건이었습니다(둘 다 PR #749 에서 발견).\n'
    printf '  고치는 법: 해당 헬퍼 이름을 %s 의 `export -f` 줄에 추가하세요.\n' "$script"
    printf '  (단위 테스트는 함수를 같은 셸에서 부르므로 이 버그를 구조적으로 못 잡습니다.)\n'
  } >&2
  exit 1
}
