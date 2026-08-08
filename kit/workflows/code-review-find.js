export const meta = {
  name: 'code-review-find',
  description: 'code-review Step 2~3 집행 — N관점 적대적 병렬 리뷰 → 최소 제출 건수 강제 → critic 판정 → dropped 재확인 → review.json 조립',
  phases: [
    { title: 'Find', detail: '관점별 적대적 리뷰 (병렬)' },
    { title: 'Backfill', detail: '최소 제출 건수 미달 관점만 1회 재호출' },
    { title: 'Verify', detail: 'critic 이 auto_fix / human_review / dropped 판정' },
    { title: 'Confirm-Drop', detail: 'dropped 항목마다 코드 근거 재확인 — 근거 없으면 human_review 로 강등' },
    { title: 'Assemble', detail: 'review.json + verdict 파일 기록' },
  ],
}

// ── 이 스크립트가 집행하는 알고리즘 ────────────────────────────────
// SSOT: kit/skills/code-review/SKILL.md Step 2~3 · kit/workflow/code-review-algorithm.md
//   「Critic 판정 기준」(auto_fix / human_review / dropped 의 dropped 강화 기준)
// 이 스크립트는 그 절차를 집행할 뿐 새 방법론을 만들지 않는다. 문서와 어긋나면 문서가 맞다.
//
// ── args 계약 (호출자가 주입) ──────────────────────────────────────
// {
//   cwd:             string,  // 리뷰 대상 작업 디렉터리 (절대경로, 필수)
//   reviewJsonPath:  string,  // review.json 기록 위치 (절대경로, 필수)
//   verdictPath:     string,  // critic verdict 기록 위치 (절대경로, 필수)
//   title:           string,  // review.json 의 title
//   date:            string,  // "YYYY-MM-DD"
//   context:         string,  // "{branch} | {commit}"
//   kitRoot:         string,  // kit 디렉터리 경로 (기본 "kit") — 알고리즘 문서를 여기서 읽는다
//   agentsRoot:      string,  // 역할 브리핑 경로 (기본 ".claude/agents") — Claude Code 가 훑는 곳
//   diffBase:        string,  // 없으면 adapter.git.diffBase
//   adapter:         object,  // .review-kit.json 을 파싱한 객체 (Workflow 스크립트는 파일을 읽지 못한다)
// }
// 반환: { reviewJsonPath, verdictPath, counts, failedPerspectives, shortfall,
//         autoFixCount, humanReviewCount, droppedCount, demotedFromDropped }

const MIN_FINDINGS = 2 // SKILL.md Step 2 「발견 0개는 허용되지 않는다」의 기계적 하한

const DEFAULT_PERSPECTIVES = [
  { key: 'Quality', brief: 'quality-reviewer.md' },
  { key: 'Security', brief: 'security-reviewer.md' },
  { key: 'Regression', brief: 'regression-reviewer.md' },
  { key: 'CodeAudit', brief: 'code-auditor.md' },
  { key: 'RuntimeTrap', brief: 'runtime-trap-hunter.md' },
]

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['info', 'items'],
  properties: {
    info: { type: 'integer' },
    items: {
      type: 'array',
      items: {
        type: 'object',
        required: ['sev', 'imp', 'title', 'loc', 'problem', 'fix', 'auto'],
        properties: {
          sev: { type: 'string', enum: ['critical', 'warning'] },
          imp: { type: 'string', enum: ['High', 'Medium', 'Low'] },
          title: { type: 'string' },
          loc: { type: 'string' },
          problem: { type: 'string' },
          fix: { type: 'string' },
          patch: { type: 'string' },
          auto: { type: 'boolean' },
        },
      },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  required: ['auto_fix', 'human_review', 'dropped'],
  properties: {
    auto_fix: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'file', 'severity', 'title', 'solution_code'],
        properties: {
          id: { type: 'string' }, file: { type: 'string' }, severity: { type: 'string' },
          title: { type: 'string' }, solution_code: { type: 'string' },
        },
      },
    },
    human_review: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'severity', 'title', 'reason'],
        properties: {
          id: { type: 'string' }, severity: { type: 'string' },
          title: { type: 'string' }, reason: { type: 'string' },
        },
      },
    },
    dropped: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'reason'],
        properties: { id: { type: 'string' }, reason: { type: 'string' } },
      },
    },
  },
}

const DROP_CONFIRM_SCHEMA = {
  type: 'object',
  required: ['confirmed', 'evidence'],
  properties: {
    confirmed: { type: 'boolean' },
    evidence: { type: 'string' },
  },
}

const ASSEMBLE_RESULT_SCHEMA = {
  type: 'object',
  required: ['written', 'itemCount'],
  properties: { written: { type: 'boolean' }, itemCount: { type: 'integer' } },
}

// ── 어댑터 조회 — 없으면 안전한 기본값으로 떨어지고 그 사실을 log 한다 ──
function fromAdapter(ad, path, fallback, note) {
  const v = path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), ad)
  const empty = v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)
  if (empty) {
    log(`어댑터에 ${path} 없음 — 기본값 사용: ${note || JSON.stringify(fallback)}`)
    return fallback
  }
  return v
}

const SCOPE = (A) => `작업 디렉터리: ${A.cwd}
리뷰 범위: \`git diff ${A.diffBase}...HEAD\` 의 변경분 + 변경 파일 전체 내용.
diff 만으로 부족한 맥락은 변경 파일을 직접 Read해 보완한다.
Regression·RuntimeTrap 관점은 마이그레이션 파일과 관련 테스트 파일도 함께 Read한다.
코드를 수정하지 말 것 — 리뷰 전용이다.`

const SUBMIT_RULES = `제출 규칙:
- **최소 ${MIN_FINDINGS}건.** 정말 결함이 없다고 판단되면 "왜 이 코드가 이 관점에서 안전한가"를
  sev:'critical' 항목으로 근거와 함께 방어해 제출한다. 빈 제출은 허용되지 않는다.
- loc = "path/file:line" (파일과 라인을 반드시 지목한다)
- patch = unified diff (\`-\` 제거 / \`+\` 추가). 제안할 변경이 없으면 생략한다.
- auto = 단일 파일·비로직 변경만으로 완결되면 true`

function findPrompt(A, p, extra) {
  const lines = [
    `역할 브리핑: \`${A.agentsRoot}/${p.brief}\` 를 Read하고 그 문서가 지시하는 역할·판정 기준을 그대로 수행한다.`,
    `(브리핑 본문은 여기서 반복하지 않는다 — 그 파일이 SSOT다.)`,
    '',
    SCOPE(A),
    '',
  ]
  if (p.key === 'RuntimeTrap' && A.taxonomy.length) {
    lines.push('스캔할 함정 분류표(어댑터 `runtimeTrapTaxonomy`):', ...A.taxonomy.map((t) => `- ${t}`), '')
  }
  if (p.key === 'Quality' && A.guardTags) {
    lines.push(
      `Decision-traceability 체크: 의도적 비표준 코드에 \`${A.guardTags.nonStandardTag}\` 또는 ` +
      `\`${A.guardTags.ssotTag}\` 태그가 없으면 warning. 자명한 코드는 지적하지 않는다.`, '')
  }
  lines.push(SUBMIT_RULES)
  if (extra) lines.push('', extra)
  lines.push('', '구조화 결과로 반환한다.')
  return lines.join('\n')
}

// 동일 loc|title 중복 제거 — id 는 dedup 후 순번 부여
function dedupeFindings(found) {
  const seen = new Map()
  let n = 0
  for (const f of found) {
    for (const it of f.items) {
      const fp = `${it.loc}|${it.title}`
      if (seen.has(fp)) continue
      n += 1
      seen.set(fp, { id: String(n), perspective: f.key, ...it })
    }
  }
  return [...seen.values()]
}

const CRITIC_PROMPT = (A, items) => `역할 브리핑: \`${A.agentsRoot}/review-critic.md\` 를 Read하고 그 판정 기준을 그대로 적용한다.
너는 이 코드를 쓰지 않았다 — 저자의 정당화를 물려받지 않는다. 코드를 수정하지 말 것.

작업 디렉터리: ${A.cwd}

아래 발견 항목 **전부**를 auto_fix | human_review | dropped 중 하나로 분류한다.
- auto_fix: solution_code 가 완전하고, 단일 파일 변경으로 완결되고, 로직 의미 변경이 없고, 아키텍처·도메인 판단이 불필요할 때만.
- human_review: 위 조건 중 하나라도 어긋나면. 한 줄 reason 을 붙인다.
- dropped: **해당 파일·라인을 직접 Read해 반증 근거를 확인한 경우만.** "이미 방어됨" 또는
  "그 패턴이 실제로 존재하지 않음"을 코드 증거(파일:라인)로 reason 에 명시한다.
  단순히 "해당 없어 보임"이라는 판단만으로는 dropped 로 보내지 않고 human_review 로 처리한다.

발견 항목 JSON:
${JSON.stringify(items, null, 2)}

구조화 결과로 반환한다.`

const DROP_CONFIRM_PROMPT = (A, item, drop) => `작업 디렉터리: ${A.cwd}

다른 검증자가 아래 리뷰 항목을 **false positive 로 판정(dropped)** 했다. 그 판정이 옳은지 코드로 확인하라.

리뷰 항목:
${JSON.stringify(item, null, 2)}

dropped 사유: ${drop.reason}

해야 할 일: \`${item.loc}\` 파일을 직접 Read해서
- 지적된 패턴이 실제로 존재하지 않거나 이미 방어되어 있으면 confirmed=true,
  evidence 에 그 근거를 "파일:라인 — 무엇이 방어하고 있는지" 형태로 적는다.
- 코드를 읽어도 반증 근거를 못 찾았거나, 판단이 문맥 추정에 기대고 있으면 confirmed=false.
  **의심스러우면 confirmed=false 가 기본값이다.**

코드를 수정하지 말 것. 구조화 결과로 반환한다.`

const ASSEMBLE_PROMPT = (A, items, verdict) => `Write 도구로 파일 두 개를 기록한다. 구조화 결과 외에는 아무것도 출력하지 않는다.

파일 1 — ${A.reviewJsonPath} — 아래 스키마와 정확히 일치하는 JSON (scripts/gen-review.js 가 소비한다):
{
  "title": ${JSON.stringify(A.title)},
  "date": ${JSON.stringify(A.date)},
  "context": ${JSON.stringify(A.context)},
  "items": [ /* 아래 발견 항목마다 하나씩 */ {
    "id": "<정렬 후 재부여할 순번 문자열>",
    "severity": "critical|warning",          // sev
    "perspective": "<입력 항목의 perspective 그대로>",
    "impact": "High|Medium|Low",             // imp
    "title": "...",
    "subtitle": "<basename(file)>:<line>",   // Security 항목이면 problem 에서 OWASP 분류를 파싱해 ' | OWASP: <분류>' 를 덧붙인다
    "file": "<loc 의 ':' 앞부분>",
    "line": <loc 의 ':' 뒤 정수, 없으면 0>,
    "problem": "...",
    "current_code": "<patch 의 '-' 라인에서 기호를 뗀 것, 없으면 null>",
    "solution": "<fix>",
    "solution_code": "<patch 의 '+' 라인에서 기호를 뗀 것, 없으면 null>",
    "auto_fixable": <auto>
  }]
}
정렬: critical 먼저, 그다음 impact High→Medium→Low. **정렬 후** "id" 를 "1" 부터 순번으로 재부여한다.

파일 2 — ${A.verdictPath} — 아래 verdict 객체를 YAML 로 (키: auto_fix / human_review / dropped).

발견 항목(중복 제거 완료, 정렬 전 id):
${JSON.stringify(items, null, 2)}

VERDICT:
${JSON.stringify(verdict, null, 2)}

{ "written": true, "itemCount": <기록한 항목 수> } 를 반환한다.`

// ── args 정규화 + fail-loud (임의 경로 기록 방지) ──
const A = (typeof args === 'string') ? JSON.parse(args) : args
if (!A || !A.cwd || !A.reviewJsonPath || !A.verdictPath) {
  throw new Error('code-review-find: 필수 args 누락 (cwd / reviewJsonPath / verdictPath). 받은 값: ' + JSON.stringify(A))
}
const AD = A.adapter || {}
if (!A.adapter) log('⚠️ args.adapter 없음 — 모든 프로젝트 고유 값이 기본값으로 떨어진다. 호출자가 .review-kit.json 을 파싱해 주입해야 한다.')

A.kitRoot = A.kitRoot || 'kit'
A.agentsRoot = A.agentsRoot || '.claude/agents'
A.diffBase = A.diffBase || fromAdapter(AD, 'git.diffBase', 'HEAD~1', 'HEAD~1 (직전 커밋 대비)')
A.taxonomy = fromAdapter(AD, 'runtimeTrapTaxonomy', [], '(빈 목록 — RuntimeTrap 이 일반 함정만 본다)')
const nonStandardTag = fromAdapter(AD, 'codingGuard.nonStandardTag', null, '(태그 없음 — decision-traceability 체크 skip)')
const ssotTag = fromAdapter(AD, 'codingGuard.ssotTag', null, '(태그 없음)')
A.guardTags = (nonStandardTag && ssotTag) ? { nonStandardTag, ssotTag } : null
A.title = A.title || 'Code Review'
A.date = A.date || ''
A.context = A.context || ''

const PERSPECTIVES = fromAdapter(AD, 'perspectives', DEFAULT_PERSPECTIVES,
  '킷 기본 5관점 (Quality/Security/Regression/CodeAudit/RuntimeTrap)')

log(`code-review-find: ${PERSPECTIVES.length}관점 @ ${A.diffBase}...HEAD (cwd=${A.cwd})`)

// ── Find — 관점별 적대적 리뷰 (병렬) ──
phase('Find')
const foundRaw = await parallel(PERSPECTIVES.map((p) => () =>
  agent(findPrompt(A, p), { label: `review:${p.key}`, phase: 'Find', schema: FINDINGS_SCHEMA })
    .then((r) => ({ key: p.key, brief: p.brief, items: r.items || [], info: r.info || 0 }))
))
let found = foundRaw.filter(Boolean)
const failedPerspectives = PERSPECTIVES.filter((p) => !found.some((f) => f.key === p.key)).map((p) => p.key)
if (failedPerspectives.length) log(`⚠️ 실패한 관점 (에이전트 오류): ${failedPerspectives.join(', ')}`)

// ── Backfill — 최소 제출 건수 미달 관점만 1회 재호출 ──
phase('Backfill')
const under = found.filter((f) => f.items.length < MIN_FINDINGS)
if (!under.length) {
  log(`최소 제출 건수(${MIN_FINDINGS}) 전 관점 충족 — 재호출 없음`)
} else {
  log(`⚠️ 최소 제출 건수 미달: ${under.map((f) => `${f.key}(${f.items.length})`).join(', ')} — 1회 재호출`)
  const extraOf = (f) => `이전 패스에서 이 관점은 ${f.items.length}건만 제출했다. 하한은 ${MIN_FINDINGS}건이다.
이미 제출한 항목:
${JSON.stringify(f.items.map((i) => ({ loc: i.loc, title: i.title })), null, 2)}
위와 **중복되지 않는** 항목을 채워 다시 제출한다. 정말 더 없다면 "왜 안전한가"를 sev:'critical' 로
코드 근거와 함께 방어해 채운다.`
  const refills = await parallel(under.map((f) => () =>
    agent(findPrompt(A, PERSPECTIVES.find((p) => p.key === f.key), extraOf(f)),
      { label: `backfill:${f.key}`, phase: 'Backfill', schema: FINDINGS_SCHEMA })
      .then((r) => ({ key: f.key, items: r.items || [] }))
  ))
  for (const r of refills.filter(Boolean)) {
    const t = found.find((f) => f.key === r.key)
    const have = new Set(t.items.map((i) => `${i.loc}|${i.title}`))
    for (const it of r.items) if (!have.has(`${it.loc}|${it.title}`)) t.items.push(it)
  }
}
const shortfall = found.filter((f) => f.items.length < MIN_FINDINGS).map((f) => ({ perspective: f.key, count: f.items.length }))
if (shortfall.length) {
  log(`⛔ 재호출 후에도 하한 미달: ${shortfall.map((s) => `${s.perspective}(${s.count})`).join(', ')} — 반환값 shortfall 에 기록. 호출자가 사람에게 보고한다.`)
}

// ── Verify — critic 판정 ──
phase('Verify')
const merged = dedupeFindings(found)
log(`중복 제거 후 ${merged.length}건 → critic 판정`)
const verdict = await agent(CRITIC_PROMPT(A, merged), { label: 'critic', phase: 'Verify', schema: VERDICT_SCHEMA })

// ── Confirm-Drop — dropped 는 코드 근거로 재확인, 없으면 human_review 로 강등 ──
phase('Confirm-Drop')
const drops = verdict.dropped || []
const demoted = []
if (!drops.length) {
  log('dropped 항목 없음 — 재확인 생략')
} else {
  log(`dropped ${drops.length}건 — 항목마다 코드 근거 재확인`)
  const byId = new Map(merged.map((i) => [String(i.id), i]))
  const checks = await parallel(drops.map((d) => () => {
    const item = byId.get(String(d.id))
    if (!item) return Promise.resolve({ id: d.id, confirmed: false, evidence: '원본 항목을 찾지 못했다 — 판정 근거 확인 불가' })
    return agent(DROP_CONFIRM_PROMPT(A, item, d), {
      label: `drop-check:${d.id}`, phase: 'Confirm-Drop', schema: DROP_CONFIRM_SCHEMA,
    }).then((v) => ({ id: d.id, confirmed: !!v.confirmed, evidence: v.evidence || '' }))
  }))
  const verdictById = new Map(checks.filter(Boolean).map((c) => [String(c.id), c]))
  const kept = []
  for (const d of drops) {
    const c = verdictById.get(String(d.id))
    // 확인 에이전트가 죽었으면 확인되지 않은 것으로 본다 — 기본값은 강등이다
    if (c && c.confirmed) {
      kept.push({ ...d, reason: `${d.reason} (재확인: ${c.evidence})` })
      continue
    }
    const item = byId.get(String(d.id))
    demoted.push({ id: d.id, title: item ? item.title : '(unknown)', reason: c ? c.evidence : '재확인 에이전트 실패' })
    verdict.human_review = verdict.human_review || []
    verdict.human_review.push({
      id: String(d.id),
      severity: item ? item.sev : 'warning',
      title: item ? item.title : '(unknown)',
      reason: `dropped 판정이 코드 근거로 확인되지 않아 강등 — ${c ? c.evidence : '재확인 실패'}`,
    })
  }
  verdict.dropped = kept
  if (demoted.length) log(`⚠️ 근거 없는 dropped ${demoted.length}건 → human_review 로 강등`)
}

// ── Assemble ──
phase('Assemble')
const asm = await agent(ASSEMBLE_PROMPT(A, merged, verdict), {
  label: 'assembler', phase: 'Assemble', schema: ASSEMBLE_RESULT_SCHEMA,
})

const counts = {
  critical: merged.filter((i) => i.sev === 'critical').length,
  warning: merged.filter((i) => i.sev === 'warning').length,
  total: merged.length,
}
log(`review.json 기록: ${asm.itemCount}건 (C${counts.critical}/W${counts.warning}) · auto_fix ${(verdict.auto_fix || []).length} / human_review ${(verdict.human_review || []).length} / dropped ${(verdict.dropped || []).length}`)

return {
  reviewJsonPath: A.reviewJsonPath,
  verdictPath: A.verdictPath,
  counts,
  failedPerspectives,
  shortfall,
  autoFixCount: (verdict.auto_fix || []).length,
  humanReviewCount: (verdict.human_review || []).length,
  droppedCount: (verdict.dropped || []).length,
  demotedFromDropped: demoted,
}
