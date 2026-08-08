export const meta = {
  name: 'explore',
  description: '요구사항 관련 코드 탐색 팬아웃 — 대상 디렉터리마다 1 에이전트, 읽기 전용, 관련 파일·심볼·변경 범위를 구조화 반환',
  phases: [
    { title: 'Explore', detail: '대상별 병렬 탐색 (읽기 전용)' },
  ],
}

// ── 이 스크립트가 집행하는 알고리즘 ────────────────────────────────
// SSOT: kit/skills/spec/SKILL.md Step 3 「영향 파일 후보 — 작업 공간의 코드를 직접 읽어 채운다」
//       kit/workflow/guardrails.md §1 (분석 스킬은 코드를 고치지 않는다)
// 스테이트리스 팬아웃이라 산출 파일이 없다 — 결과는 호출 스킬이 스펙에 반영한다.
//
// ── args 계약 (호출자가 주입) ──────────────────────────────────────
// {
//   req:     string,   // 요구사항 상세 (필수)
//   hint:    string,   // 작업 단위 제목 등 힌트 (선택)
//   targets: [{ id: string, dir: string, hint?: string }],  // 탐색 대상. 없으면 args.cwd 한 개로 떨어진다
//   cwd:     string,   // targets 미지정 시의 단일 대상
//   adapter: object,   // .review-kit.json 파싱 결과 (explore.hints 로 대상별 힌트 지정 가능)
// }
// 반환: { results: { [id]: SA }, dropped: string[], relevantCount }
//   SA = { relevant:'yes'|'no', reason?, files:[{path,symbol,change}], scope? }

const SA_SCHEMA = {
  type: 'object',
  required: ['relevant', 'files'],
  properties: {
    relevant: { type: 'string', enum: ['yes', 'no'] },
    reason: { type: 'string' },   // relevant:'no' 일 때 필수
    files: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'symbol', 'change'],
        properties: {
          path: { type: 'string' },     // 대상 디렉터리 기준 상대 경로
          symbol: { type: 'string' },   // 함수·클래스·컴포넌트명
          change: { type: 'string' },   // 필요한 변경 한 줄
        },
      },
    },
    scope: { type: 'string' },      // relevant:'yes' 일 때 전체 변경 범위 한 줄
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

const EXPLORE_PROMPT = (t, A, extra) => `작업 디렉터리: ${t.dir}
요구사항: ${A.req}
힌트: ${A.hint || '(없음)'}

${t.hint || '이 디렉터리의 소스 트리에서 요구사항과 관련된 진입점·비즈니스 로직·데이터 접근·설정을 탐색한다.'}

요구사항과 관련된 코드를 찾아 구조화 결과로 반환한다.
- 관련이 없으면 relevant:'no' + reason 한 줄. **근거 없이 'no' 로 끝내지 않는다** —
  무엇을 찾아봤고 왜 없다고 판단했는지 적는다.
- 관련이 있으면 relevant:'yes' + files[](대상 디렉터리 기준 상대 path, symbol, 필요한 change 한 줄)
  + scope(전체 변경 범위 한 줄). files 가 비어 있는 'yes' 는 허용되지 않는다.

**파일을 수정하지 말 것 — 탐색·분석 전용이다.**${extra ? `\n\n${extra}` : ''}`

// ── args 정규화 + fail-loud ──
const A = (typeof args === 'string') ? JSON.parse(args) : args
if (!A || !A.req) {
  throw new Error('explore: 필수 args 누락 (req). 받은 값: ' + JSON.stringify(A))
}
const AD = A.adapter || {}
const hints = fromAdapter(AD, 'explore.hints', {}, '(대상별 힌트 없음 — 일반 탐색 지시로 떨어진다)')

let targets = A.targets
if (!targets || !targets.length) {
  if (!A.cwd) throw new Error('explore: targets 도 cwd 도 없다 — 탐색할 디렉터리를 알 수 없다.')
  log('args.targets 미지정 — cwd 한 개를 대상으로 삼는다')
  targets = [{ id: 'main', dir: A.cwd }]
}
targets = targets.filter((t) => t && t.dir).map((t) => ({ ...t, hint: t.hint || hints[t.id] }))
if (!targets.length) throw new Error('explore: dir 이 채워진 대상이 하나도 없다.')

log(`explore: req="${A.req.slice(0, 60)}" 대상 ${targets.length}개 [${targets.map((t) => t.id).join(', ')}]`)

phase('Explore')
const foundRaw = await parallel(targets.map((t) => () =>
  agent(EXPLORE_PROMPT(t, A), { label: `explore:${t.id}`, phase: 'Explore', schema: SA_SCHEMA })
    .then((sa) => ({ id: t.id, sa }))
))
let found = foundRaw.filter(Boolean)

// relevant:'yes' 인데 files 가 빈 결과는 정보가 없다 — 대상당 1회만 재호출한다
const empties = found.filter((f) => f.sa && f.sa.relevant === 'yes' && !(f.sa.files || []).length)
if (empties.length) {
  log(`⚠️ relevant:'yes' 인데 files 가 빈 대상: ${empties.map((e) => e.id).join(', ')} — 1회 재호출`)
  const retries = await parallel(empties.map((e) => () => {
    const t = targets.find((x) => x.id === e.id)
    return agent(EXPLORE_PROMPT(t, A, "이전 패스는 relevant:'yes' 를 냈으면서 files 를 비워 반환했다. 관련 파일을 실제로 지목하거나, 관련이 없다면 relevant:'no' + reason 으로 정정한다."),
      { label: `explore-retry:${e.id}`, phase: 'Explore', schema: SA_SCHEMA }).then((sa) => ({ id: e.id, sa }))
  }))
  for (const r of retries.filter(Boolean)) {
    const hit = found.find((f) => f.id === r.id)
    if (hit) hit.sa = r.sa
  }
}

const dropped = targets.filter((t) => !found.some((f) => f.id === t.id)).map((t) => t.id)
if (dropped.length) log(`⚠️ 탐색 실패한 대상 (에이전트 오류): ${dropped.join(', ')} — 호출자가 수동으로 채워야 한다`)

const results = Object.fromEntries(found.map((f) => [f.id, f.sa]))
const relevantCount = found.filter((f) => f.sa && f.sa.relevant === 'yes').length
const fileCount = found.reduce((n, f) => n + ((f.sa && f.sa.files) || []).length, 0)
log(`탐색 완료: 관련 대상 ${relevantCount}/${found.length} · 후보 파일 ${fileCount}개`)

return { results, dropped, relevantCount, fileCount }
