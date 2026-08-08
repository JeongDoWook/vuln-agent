export const meta = {
  name: 'test-matrix',
  description: 'self-qa Step 3~4 의 검증 매트릭스 설계 — 카테고리별 병렬 설계 → AC 커버리지 산출 → 미커버 AC 를 반환값으로 노출',
  phases: [
    { title: 'Design', detail: '카테고리별 검증 케이스 설계 (병렬)' },
    { title: 'Merge', detail: 'AC 커버리지 매핑 + 매트릭스 파일 기록' },
  ],
}

// ── 이 스크립트가 집행하는 알고리즘 ────────────────────────────────
// SSOT: kit/skills/self-qa/SKILL.md Step 3(AC 검증 — 항목마다 코드 근거) · Step 4(스코프 한정 테스트)
//   자기 검증이 "구현했으니 통과"로 흐르지 않게, **AC → 케이스** 매핑을 먼저 문서로 고정한다.
//   이 스크립트는 케이스를 **설계만** 한다 — 실행·수정은 self-qa 스킬이 한다.
// 카테고리·관점은 스택마다 다르므로 전부 어댑터에서 읽는다.
//
// ── args 계약 (호출자가 주입) ──────────────────────────────────────
// {
//   cwd:         string,    // 작업 디렉터리 (절대경로, 필수)
//   specPath:    string,    // AC 원본 스펙 (절대경로, 필수)
//   outPath:     string,    // 매트릭스 기록 위치 (프로젝트 루트 하위 절대경로, 필수)
//   acIds:       string[],  // 커버돼야 하는 AC id 목록 (선택 — 주면 미커버를 스크립트가 판정한다)
//   targetFiles: string[],  // 주요 대상 파일 (선택)
//   track:       string,    // 어댑터 tests.categories 가 트랙별로 나뉜 경우의 선택자 (선택)
//   adapter:     object,    // .review-kit.json 파싱 결과
// }
// 반환: { outPath, counts:{total, byCategory}, uncoveredAc, failedCategories }

const DEFAULT_CATEGORIES = [
  { key: 'UT', label: 'unit — 단일 함수·모듈의 로직' },
  { key: 'IT', label: 'integration — 경계를 넘는 호출(저장소·외부 인터페이스)' },
  { key: 'SC', label: 'scenario — 2개 이상 구성요소가 엮인 흐름' },
  { key: 'RG', label: 'regression — 기존 동작이 깨지지 않는지' },
]

const DEFAULT_PERSPECTIVES = [
  '정상 흐름', '경계값', '예외·오류', '권한·보안',
  '비즈니스 규칙', '동시성·중복', '상태 전이', '회귀',
]

const CASE_SCHEMA = {
  type: 'object',
  required: ['cases'],
  properties: {
    cases: {
      type: 'array',
      items: {
        type: 'object',
        required: ['perspective', 'display', 'target', 'given', 'when', 'then', 'ac'],
        properties: {
          perspective: { type: 'string' },  // 관점 목록 중 하나
          display: { type: 'string' },      // 테스트 설명 한 줄
          target: { type: 'string' },       // 대상 함수·모듈·컴포넌트
          given: { type: 'string' },
          when: { type: 'string' },
          then: { type: 'string' },
          ac: { type: 'array', items: { type: 'string' } },  // 이 케이스가 덮는 AC id
        },
      },
    },
  },
}

const MERGE_SCHEMA = {
  type: 'object',
  required: ['written', 'total', 'coverage'],
  properties: {
    written: { type: 'boolean' },
    total: { type: 'integer' },
    coverage: {
      type: 'array',
      items: {
        type: 'object',
        required: ['ac', 'covered_by'],
        properties: {
          ac: { type: 'string' },
          desc: { type: 'string' },
          covered_by: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    uncovered: {
      type: 'array',
      items: {
        type: 'object',
        required: ['item', 'reason'],
        properties: { item: { type: 'string' }, reason: { type: 'string' } },
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

const DESIGN_PROMPT = (A, cat) => `작업 디렉터리: ${A.cwd}
스펙(AC 원본): ${A.specPath}
대상 파일: ${(A.targetFiles || []).join(', ') || '(스펙에서 파악)'}

스펙의 완료 조건(AC)을 Read한 뒤, **${cat.label}** 카테고리에 해당하는 검증 케이스만 설계한다.

관점 목록: ${A.perspectives.join(' / ')}
- 이 카테고리에 실제로 해당하는 관점만 다룬다 — 억지로 전 관점을 채우지 않는다.
- 각 케이스: perspective(위 목록의 문자열), display, target, given/when/then,
  ac(이 케이스가 덮는 AC id 배열 — 덮는 AC 가 없으면 빈 배열).
- **구현하지 않는다. 파일도 쓰지 않는다.** 설계만 한다.

구조화 결과로 반환한다.`

const MERGE_PROMPT = (A, byCat) => `Write 도구로 검증 매트릭스를 ${A.outPath} 에 YAML 로 기록한다.
구조화 결과 외에는 아무것도 출력하지 않는다.

아래는 카테고리별로 설계된 케이스다. 합쳐서 다음 형태의 YAML 을 쓴다:
- 케이스마다 카테고리별 순번 id 부여: ${A.categories.map((c) => `${c.key}-001`).join(', ')} …
- 카테고리 키마다 섹션: ${A.categories.map((c) => `${c.key}_CASES`).join(', ')}
  (각 항목: id, perspective, display, target, given, when, then, ac)
- AC_COVERAGE: ${A.specPath} 의 AC 항목마다 [{ac, desc, covered_by:[케이스 id…]}]
- UNCOVERED: 어떤 케이스로도 덮이지 않는 AC·관점 [{item, reason}]

카테고리별 설계 결과(JSON):
${JSON.stringify(byCat, null, 2)}

${A.specPath} 의 AC 절을 직접 Read해 AC_COVERAGE 를 정확히 매핑한다 — 추측으로 채우지 않는다.
반환값의 coverage/uncovered 는 기록한 YAML 과 동일해야 한다.`

// ── args 정규화 + fail-loud ──
const A = (typeof args === 'string') ? JSON.parse(args) : args
if (!A || !A.cwd || !A.specPath || !A.outPath) {
  throw new Error('test-matrix: 필수 args 누락 (cwd / specPath / outPath). 받은 값: ' + JSON.stringify(A))
}
// 임시 디렉터리는 샌드박스가 끝나면 사라진다 — 산출물을 거기 두면 조용히 없어진다
if (/^\/tmp\/|^\/private\/tmp\/|[\\/](Temp|tmp)[\\/]/i.test(A.outPath)) {
  throw new Error('test-matrix: outPath 는 프로젝트 루트 하위여야 한다(임시 디렉터리 금지). 받은 값: ' + A.outPath)
}
const AD = A.adapter || {}
if (!A.adapter) log('⚠️ args.adapter 없음 — 카테고리·관점이 기본값으로 떨어진다.')

const catSource = A.track
  ? fromAdapter(AD, `tests.categoriesByTrack.${A.track}`, null, '(트랙별 정의 없음 — 공통 정의로 떨어진다)')
  : null
A.categories = catSource || fromAdapter(AD, 'tests.categories', DEFAULT_CATEGORIES, '스택 중립 기본 4카테고리 (UT/IT/SC/RG)')
A.perspectives = fromAdapter(AD, 'tests.perspectives', DEFAULT_PERSPECTIVES, '기본 8관점')

log(`test-matrix: 카테고리=[${A.categories.map((c) => c.key).join(',')}] 관점 ${A.perspectives.length}개 → ${A.outPath}`)

// ── Design ──
phase('Design')
const designedRaw = await parallel(A.categories.map((cat) => () =>
  agent(DESIGN_PROMPT(A, cat), { label: `tm:${cat.key}`, phase: 'Design', schema: CASE_SCHEMA })
    .then((r) => ({ key: cat.key, cases: r.cases || [] }))
))
const designed = designedRaw.filter(Boolean)
const failedCategories = A.categories.filter((c) => !designed.some((d) => d.key === c.key)).map((c) => c.key)
if (failedCategories.length) log(`⚠️ 실패한 카테고리 (에이전트 오류): ${failedCategories.join(', ')}`)

const byCat = Object.fromEntries(designed.map((d) => [d.key, d.cases]))
const total = designed.reduce((n, d) => n + d.cases.length, 0)
if (!total) throw new Error('test-matrix: 설계된 케이스가 0건이다 — 매트릭스를 쓰지 않고 중단한다.')

// ── Merge ──
phase('Merge')
const merge = await agent(MERGE_PROMPT(A, byCat), { label: 'tm:merge', phase: 'Merge', schema: MERGE_SCHEMA })

// AC 미커버 판정은 스크립트가 한다 — LLM 의 "다 덮었습니다"를 믿지 않는다
const coveredAc = new Set()
for (const c of merge.coverage || []) if ((c.covered_by || []).length) coveredAc.add(String(c.ac))
for (const d of designed) for (const cs of d.cases) for (const a of (cs.ac || [])) coveredAc.add(String(a))

let uncoveredAc = []
if ((A.acIds || []).length) {
  uncoveredAc = A.acIds.filter((id) => !coveredAc.has(String(id)))
} else {
  log('args.acIds 미제공 — 미커버 판정을 merge 에이전트의 UNCOVERED 에 의존한다(약한 신호). AC id 목록을 넘기면 스크립트가 직접 판정한다.')
  uncoveredAc = (merge.uncovered || []).map((u) => u.item)
}

log(`매트릭스 기록: ${merge.total}건 (${designed.map((d) => `${d.key}:${d.cases.length}`).join(' ')})`)
if (uncoveredAc.length) {
  log(`⛔ 어떤 케이스로도 덮이지 않는 AC ${uncoveredAc.length}건: ${uncoveredAc.join(', ')} — self-qa 는 이 상태를 통과로 보고하지 않는다.`)
} else {
  log('AC 전 항목이 케이스로 덮였다')
}

return {
  outPath: A.outPath,
  counts: { total, byCategory: Object.fromEntries(designed.map((d) => [d.key, d.cases.length])) },
  coverage: merge.coverage || [],
  uncoveredAc,
  failedCategories,
}
