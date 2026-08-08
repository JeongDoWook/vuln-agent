export const meta = {
  name: 'spec-analyze',
  description: 'spec Step 2 + design-review 팀 토론 집행 — 구현 방향 발산(2~3안) → 3관점 라운드1 → 반박 라운드2 → 미합의 쟁점·spec_updates 산출',
  phases: [
    { title: 'Options', detail: '구현 방향 2~3안 발산 — 단기 vs 장기 축 강제' },
    { title: 'Round1', detail: 'devil-advocate / regression-analyst / runtime-trap 독립 분석 (병렬)' },
    { title: 'Round2', detail: '반박 교차 — 합의/open 판정' },
    { title: 'Merge', detail: 'spec_updates + 미합의 쟁점 취합' },
  ],
}

// ── 이 스크립트가 집행하는 알고리즘 ────────────────────────────────
// SSOT: kit/skills/spec/SKILL.md Step 2 (구현 방향 발산)
//     · kit/skills/design-review/SKILL.md Step 2 (팀 토론 경로)
//     · kit/workflow/design-review-algorithm.md (Round 1 → Round 2 P2P 프로토콜)
// Workflow tool 에는 에이전트 간 P2P 메시지가 없으므로, 알고리즘의 라운드 구조를 **스크립트가
// 결정론적으로 중계**한다 — 라운드 수·교차 상대·open 판정 기준은 문서와 동일하다.
// 「Pragmatist 관점」은 Options 페이즈(구현 방향 발산 + 추천)가 담당한다. 문서와 어긋나면 문서가 맞다.
//
// ── args 계약 (호출자가 주입) ──────────────────────────────────────
// {
//   cwd:        string,   // 작업 디렉터리 (절대경로, 필수)
//   specPath:   string,   // 분석 대상 스펙 문서 (절대경로, 필수)
//   codePath:   string,   // 코드 맥락 경로 (선택, 기본 cwd)
//   complexity: string,   // simple | normal | complex (선택) — simple 이면 Options 를 건너뛴다
//   kitRoot:    string,   // 기본 "kit"
//   agentsRoot: string,   // 역할 브리핑 경로 (기본 ".claude/agents")
//   adapter:    object,   // .review-kit.json 파싱 결과
// }
// 반환: { options, debate:{devilAdvocate,regression,runtimeTrap}, openIssues, specUpdates, shortfall }

const MIN_FINDINGS = 2   // design-devil-advocate.md 「최소 2개」의 기계적 하한
const MIN_OPTIONS = 2    // spec/SKILL.md Step 2 「2~3개」의 하한

const OPTIONS_SCHEMA = {
  type: 'object',
  required: ['options', 'recommendation', 'recommendation_reason'],
  properties: {
    options: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'name', 'approach', 'cost_now', 'cost_to_change_later', 'forecloses', 'reversibility', 'recommend_when'],
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          approach: { type: 'string' },
          cost_now: { type: 'string' },
          cost_to_change_later: { type: 'string' },
          forecloses: { type: 'string' },
          reversibility: { type: 'string' },
          recommend_when: { type: 'string' },
        },
      },
    },
    recommendation: { type: 'string' },
    recommendation_reason: { type: 'string' },
  },
}

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'title', 'evidence', 'severity'],
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          evidence: { type: 'string' },   // 파일:라인 또는 스펙 인용
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          affected: { type: 'string' },
        },
      },
    },
  },
}

const JUDGE_SCHEMA = {
  type: 'object',
  required: ['judgements'],
  properties: {
    judgements: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'status', 'note'],
        properties: {
          id: { type: 'string' },
          status: { type: 'string', enum: ['agreed', 'open'] },
          note: { type: 'string' },
        },
      },
    },
    additional: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'title', 'evidence', 'severity'],
        properties: {
          id: { type: 'string' }, title: { type: 'string' },
          evidence: { type: 'string' }, severity: { type: 'string' },
        },
      },
    },
  },
}

const MERGE_SCHEMA = {
  type: 'object',
  required: ['spec_updates', 'open_issues'],
  properties: {
    spec_updates: {
      type: 'array',
      items: {
        type: 'object',
        required: ['field', 'action', 'value'],
        properties: { field: { type: 'string' }, action: { type: 'string' }, value: { type: 'string' } },
      },
    },
    open_issues: {
      type: 'array',
      items: {
        type: 'object',
        required: ['title', 'why_open'],
        properties: { title: { type: 'string' }, why_open: { type: 'string' }, severity: { type: 'string' } },
      },
    },
  },
}

function fromAdapter(ad, path, fallback, note) {
  const v = path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), ad)
  const empty = v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)
  if (empty) {
    log(`어댑터에 ${path} 없음 — 기본값 사용: ${note || JSON.stringify(fallback)}`)
    return fallback
  }
  return v
}

const CONTEXT = (A) => `작업 디렉터리: ${A.cwd}
스펙 문서: ${A.specPath}
코드 맥락: ${A.codePath}
스펙과 코드를 직접 Read한 뒤 답한다. **코드를 수정하지 말 것** — 설계 단계에서 코드를 고치는
검증자는 검증자가 아니라 두 번째 저자다.`

const OPTIONS_PROMPT = (A) => `${CONTEXT(A)}

이 변경을 구현하는 서로 다른 방향 ${MIN_OPTIONS}~3개를 도출한다(최소 패치 ~ 정석 구조화 ~ 추상화/미래대비 스펙트럼).
곧장 수렴하면 최소 패치 쪽으로 구조적 편향이 생긴다 — 발산이 먼저다.

각 방향마다 **단기 vs 장기** 축을 전부 채운다:
- cost_now: 지금 드는 비용 (low/medium/high)
- cost_to_change_later: 나중에 바꿀 때 드는 비용
- forecloses: 이 선택이 **막아버리는** 미래 선택지
- reversibility: easy / medium / hard
- recommend_when: 이 방향이 맞는 조건 한 줄

추천 1개(recommendation = 그 option 의 id)와 그 근거(recommendation_reason)를 함께 낸다.
구조화 결과로 반환한다.`

function roundOnePrompt(A, r) {
  const lines = [
    `역할 브리핑: \`${A.agentsRoot}/${r.brief}\` 를 Read하고 그 문서가 지시하는 역할을 [Round 1] 로 수행한다.`,
    '(브리핑 본문은 여기서 반복하지 않는다 — 그 파일이 SSOT다.)',
    '',
    CONTEXT(A),
  ]
  if (A.selected) lines.push('', `확정 구현 방향: ${A.selected}`)
  if (r.key === 'runtimeTrap' && A.taxonomy.length) {
    lines.push('', '스캔할 함정 분류표(어댑터 `runtimeTrapTaxonomy`):', ...A.taxonomy.map((t) => `- ${t}`))
  }
  lines.push('',
    `**최소 ${MIN_FINDINGS}건.** "문제없음" 결론은 허용되지 않는다.`,
    'findings[] 의 각 항목에 id(f1, f2 …), title, evidence(파일:라인 또는 스펙 인용), severity 를 채운다.',
    '구조화 결과로 반환한다.')
  return lines.join('\n')
}

// ── args 정규화 + fail-loud ──
const A = (typeof args === 'string') ? JSON.parse(args) : args
if (!A || !A.cwd || !A.specPath) {
  throw new Error('spec-analyze: 필수 args 누락 (cwd / specPath). 받은 값: ' + JSON.stringify(A))
}
const AD = A.adapter || {}
if (!A.adapter) log('⚠️ args.adapter 없음 — 프로젝트 고유 값이 기본값으로 떨어진다.')
A.kitRoot = A.kitRoot || 'kit'
A.agentsRoot = A.agentsRoot || '.claude/agents'
A.codePath = A.codePath || A.cwd
A.taxonomy = fromAdapter(AD, 'runtimeTrapTaxonomy', [], '(빈 목록 — runtime-trap 이 일반 함정만 본다)')
A.selected = null

const ROLES = [
  { key: 'devilAdvocate', label: 'devil-advocate', brief: 'design-devil-advocate.md' },
  { key: 'regression', label: 'regression-analyst', brief: 'design-regression-analyst.md' },
  { key: 'runtimeTrap', label: 'runtime-trap', brief: 'design-runtime-trap.md' },
]

log(`spec-analyze: spec=${A.specPath} complexity=${A.complexity || '(미지정)'}`)

// ── Options — 구현 방향 발산 ──
phase('Options')
let options = null
if (A.complexity === 'simple' || A.complexity === 'trivial') {
  log(`complexity=${A.complexity} — Options 페이즈 skip (SKILL.md Step 2: Simple 이하는 방향이 하나뿐이다)`)
} else {
  options = await agent(OPTIONS_PROMPT(A), { label: 'options-divergent', phase: 'Options', schema: OPTIONS_SCHEMA })
  if ((options.options || []).length < MIN_OPTIONS) {
    log(`⚠️ 도출된 방향 ${(options.options || []).length}개 — 하한 ${MIN_OPTIONS} 미달, 1회 재호출`)
    const retry = await agent(
      `${OPTIONS_PROMPT(A)}

이전 패스는 ${(options.options || []).length}개만 냈다. 이미 낸 방향:
${JSON.stringify((options.options || []).map((o) => ({ id: o.id, name: o.name })), null, 2)}
**서로 다른** 방향을 ${MIN_OPTIONS}개 이상으로 채워 다시 낸다.`,
      { label: 'options-retry', phase: 'Options', schema: OPTIONS_SCHEMA })
    if ((retry.options || []).length > (options.options || []).length) options = retry
  }
  A.selected = options.recommendation || null
  log(`구현 방향 ${(options.options || []).length}개 — 추천: ${A.selected || '?'}`)
}
const optionShortfall = options && (options.options || []).length < MIN_OPTIONS
  ? [{ stage: 'options', count: (options.options || []).length }] : []
if (optionShortfall.length) log('⛔ 재호출 후에도 방향 하한 미달 — 반환값 shortfall 에 기록')

// ── Round1 — 3관점 독립 분석 ──
phase('Round1')
const r1Raw = await parallel(ROLES.map((r) => () =>
  agent(roundOnePrompt(A, r), { label: `r1:${r.label}`, phase: 'Round1', schema: FINDINGS_SCHEMA })
    .then((res) => ({ key: r.key, findings: res.findings || [] }))
))
const r1 = r1Raw.filter(Boolean)
const failedRoles = ROLES.filter((r) => !r1.some((x) => x.key === r.key)).map((r) => r.label)
if (failedRoles.length) log(`⚠️ 실패한 관점: ${failedRoles.join(', ')}`)
const pick = (k) => (r1.find((x) => x.key === k) || { findings: [] }).findings
const findingShortfall = r1.filter((x) => x.findings.length < MIN_FINDINGS)
  .map((x) => ({ stage: x.key, count: x.findings.length }))
if (findingShortfall.length) {
  log(`⛔ 최소 제출 건수(${MIN_FINDINGS}) 미달: ${findingShortfall.map((s) => `${s.stage}(${s.count})`).join(', ')}`)
}

// ── Round2 — 반박 교차 (알고리즘의 P2P 를 스크립트가 결정론적으로 중계) ──
phase('Round2')
const daFindings = pick('devilAdvocate')
const regFindings = pick('regression')
const rtFindings = pick('runtimeTrap')

// regression-analyst → devil-advocate 반박
const rebuttal = daFindings.length
  ? await agent(`역할 브리핑: \`${A.agentsRoot}/design-regression-analyst.md\` [Round 2].

${CONTEXT(A)}

devil-advocate 가 낸 실패 시나리오다. 각 항목을 affected/severity 관점에서 판정한다.
- 동의하면 status='agreed', note 에 무엇이 실제로 위험한지 한 줄.
- 동의하지 않으면 status='open', note 에 반증 근거(파일:라인)를 적는다.
추가로 발견한 회귀 위험(계약·스키마·외부 인터페이스)은 additional[] 에 담는다.

devil-advocate findings:
${JSON.stringify(daFindings, null, 2)}

구조화 결과로 반환한다.`, { label: 'r2:rebuttal', phase: 'Round2', schema: JUDGE_SCHEMA })
  : (log('devil-advocate 발견 0건 — 반박 라운드 skip'), { judgements: [], additional: [] })

// devil-advocate 최종 판정 · runtime-trap 교차 검증 (동시)
const [daFinal, rtFinal] = await parallel([
  () => (rebuttal.judgements || []).length
    ? agent(`역할 브리핑: \`${A.agentsRoot}/design-devil-advocate.md\` [Round 2].

${CONTEXT(A)}

네가 낸 항목에 대한 regression-analyst 의 반박이다. 각 항목을 accept(status='agreed') 또는
reject(status='open') 로 판정한다. note 에 근거 한 줄. 반박을 받아들이지 못하면 open 이 정답이다 —
합의된 척 넘기지 않는다.

내 findings:
${JSON.stringify(daFindings, null, 2)}

REBUTTAL:
${JSON.stringify(rebuttal.judgements, null, 2)}

구조화 결과로 반환한다.`, { label: 'r2:da-final', phase: 'Round2', schema: JUDGE_SCHEMA })
    : Promise.resolve({ judgements: [], additional: [] }),
  () => agent(`역할 브리핑: \`${A.agentsRoot}/design-runtime-trap.md\` [Round 2].

${CONTEXT(A)}

devil-advocate 와 regression-analyst 의 결과다. 네가 Round 1 에서 찾은 함정과 교차 검증해
각 항목을 agreed / open 으로 판정한다. 어느 쪽에서도 해소되지 않은 항목은 open 으로 남긴다.

devil-advocate: ${JSON.stringify(daFindings, null, 2)}
regression risks: ${JSON.stringify([...regFindings, ...(rebuttal.additional || [])], null, 2)}
내 findings: ${JSON.stringify(rtFindings, null, 2)}

구조화 결과로 반환한다.`, { label: 'r2:rt-cross', phase: 'Round2', schema: JUDGE_SCHEMA }),
])

// ── Merge — spec_updates + 미합의 쟁점 ──
phase('Merge')
const allJudgements = [
  ...((rebuttal && rebuttal.judgements) || []),
  ...((daFinal && daFinal.judgements) || []),
  ...((rtFinal && rtFinal.judgements) || []),
]
// 한 항목이라도 open 으로 남으면 open — 합의는 만장일치일 때만이다
const statusById = new Map()
for (const j of allJudgements) {
  const prev = statusById.get(j.id)
  if (prev === 'open') continue
  statusById.set(j.id, j.status === 'open' ? 'open' : (prev || 'agreed'))
}
const openCount = [...statusById.values()].filter((s) => s === 'open').length
log(`판정 ${statusById.size}건 중 미합의(open) ${openCount}건`)

const merged = await agent(`${CONTEXT(A)}

아래는 3관점 분석과 라운드 2 판정 결과다. 이것을 스펙에 반영할 형태로 정리한다.
- spec_updates[]: {field, action, value} — 스펙 문서의 어느 항목을 어떻게 바꿀지. 없으면 빈 배열.
- open_issues[]: status='open' 으로 남은 항목만. **지우거나 합의된 것처럼 요약하지 않는다** —
  구현 중에 다시 부딪히는 지점이라 스펙에 그대로 남겨야 한다.

${options ? `확정 구현 방향(추천): ${A.selected}\n옵션:\n${JSON.stringify(options.options, null, 2)}\n` : ''}
Round1:
${JSON.stringify({ devilAdvocate: daFindings, regression: regFindings, runtimeTrap: rtFindings }, null, 2)}

Round2 판정:
${JSON.stringify(allJudgements, null, 2)}

구조화 결과로 반환한다. 파일을 쓰지 말 것 — 스펙 반영은 호출 스킬이 한다.`,
  { label: 'merge', phase: 'Merge', schema: MERGE_SCHEMA })

log(`spec_updates ${(merged.spec_updates || []).length}건 · 미합의 쟁점 ${(merged.open_issues || []).length}건`)

return {
  options,
  debate: {
    devilAdvocate: { findings: daFindings, final: (daFinal && daFinal.judgements) || [] },
    regression: { findings: regFindings, rebuttal: (rebuttal && rebuttal.judgements) || [], additional: (rebuttal && rebuttal.additional) || [] },
    runtimeTrap: { findings: rtFindings, cross: (rtFinal && rtFinal.judgements) || [] },
  },
  openIssues: merged.open_issues || [],
  specUpdates: merged.spec_updates || [],
  failedRoles,
  shortfall: [...optionShortfall, ...findingShortfall],
}
