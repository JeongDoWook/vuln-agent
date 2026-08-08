export const meta = {
  name: 'impl-phases',
  description: 'implement Step 4 병렬 분해 집행 — Phase A/B/C 순차, 페이즈 안에서만 동시 실행, 대상 파일이 겹치는 작업은 자동 직렬화',
  phases: [
    { title: 'Phase A', detail: '하위 레이어 — 서로 의존하지 않는 작업 동시 실행' },
    { title: 'Phase B', detail: '상위 레이어 — Phase A 완료 후' },
    { title: 'Phase C', detail: '시나리오 단위 통합 — 마지막' },
  ],
}

// ── 이 스크립트가 집행하는 알고리즘 ────────────────────────────────
// SSOT: kit/skills/implement/SKILL.md Step 4 「병렬 분해」 · Step 5 「검사」
//   - 페이즈 경계는 의존 방향이다: A(하위) → B(A 에 의존하는 상위) → C(시나리오 통합)
//   - "Plan 의 단계들이 **파일 단위로 겹치지 않을 때만** 분해한다" → 겹치면 스크립트가 직렬화한다
//   - "전체 테스트 스위트는 여기서 돌리지 않는다" → 에이전트 프롬프트에서 금지, 검사는 페이즈 끝 1회
// 스택 명령을 직접 쓰지 않는다 — 외부 접점은 provider-contract 의 `node scripts/px.js` 동사뿐이다.
//
// ── args 계약 (호출자가 주입) ──────────────────────────────────────
// {
//   cwd:      string,   // 작업 디렉터리 (절대경로, 필수)
//   issueRef: string,   // 커밋 메시지에 넣을 작업 단위 ref (선택)
//   repo:     string,   // px run 의 --repo 값 (선택)
//   planPath: string,   // Plan 문서 경로 (선택, 있으면 에이전트가 Read)
//   specPath: string,   // 스펙 경로 (확정 구현 방향·미합의 쟁점의 출처, 선택)
//   kitRoot:  string,   // 기본 "kit"
//   phaseA / phaseB / phaseC: Task[],   // 최소 하나는 비어 있지 않아야 한다
//   adapter:  object,   // .review-kit.json 파싱 결과
// }
//   Task = { id, title, targetFiles: string[], tdd?: boolean, testFilter?: string, detail?: string }
// 반환: { phases: [{ id, total, ok, serializedGroups }], skippedChecks }

const PHASE_DEFS = [
  { id: 'A', title: 'Phase A', key: 'phaseA' },
  { id: 'B', title: 'Phase B', key: 'phaseB' },
  { id: 'C', title: 'Phase C', key: 'phaseC' },
]

function fromAdapter(ad, path, fallback, note) {
  const v = path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), ad)
  const empty = v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)
  if (empty) {
    log(`어댑터에 ${path} 없음 — 기본값 사용: ${note || JSON.stringify(fallback)}`)
    return fallback
  }
  return v
}

// 대상 파일이 겹치는 작업은 같은 그룹으로 묶어 **순차** 실행한다.
// 겹친 채 동시에 돌리면 분해 이득보다 충돌 비용이 크다(implement/SKILL.md Step 4).
function groupByFileOverlap(tasks) {
  const groups = []
  for (const t of tasks) {
    const files = new Set(t.targetFiles || [])
    const hit = groups.find((g) => [...files].some((f) => g.files.has(f)))
    if (hit) {
      hit.tasks.push(t)
      for (const f of files) hit.files.add(f)
    } else {
      groups.push({ tasks: [t], files })
    }
  }
  return groups
}

function implPrompt(A, task) {
  const lines = [
    `작업 디렉터리: ${A.cwd}`,
    A.specPath ? `스펙: ${A.specPath}` : null,
    A.planPath ? `Plan: ${A.planPath}` : null,
    A.issueRef ? `작업 단위 ref: ${A.issueRef}` : null,
    '',
    `담당 작업: ${task.title || task.id}`,
    `대상 파일: ${JSON.stringify(task.targetFiles || [])}`,
    task.detail ? `상세: ${task.detail}` : null,
    '',
    '수행 순서:',
  ]
  const steps = []
  if (task.tdd !== false) {
    steps.push('1. 실패하는 테스트를 먼저 쓴다(Red). 커밋: `test: ' + (task.title || task.id) + (A.issueRef ? ` (${A.issueRef})` : '') + '`')
    steps.push('2. 구현한다(Green). 커밋: `feat: ' + (task.title || task.id) + (A.issueRef ? ` (${A.issueRef})` : '') + '`')
  } else {
    steps.push('1. 구현한다. 커밋: `feat: ' + (task.title || task.id) + (A.issueRef ? ` (${A.issueRef})` : '') + '`')
  }
  lines.push(...steps, '',
    '지켜야 하는 것:',
    '- **대상 파일 밖을 고치지 않는다.** 다른 작업자가 같은 페이즈에서 동시에 일하고 있다.',
    '- 스펙의 **확정 구현 방향**을 벗어나는 판단이 필요해지면 임의로 바꾸지 말고 그 사실을 결과에 적고 멈춘다 —' +
    ' 방향은 설계 게이트에서 합의된 값이다.',
    '- 스펙의 **미합의 쟁점**에 해당하는 코드에 닿으면 어떻게 처리했는지 커밋 메시지에 남긴다.',
    '- **전체 테스트 스위트를 돌리지 않는다.** 방금 쓴 테스트만 좁혀 실행한다:',
    `  \`node scripts/px.js run test --filter ${task.testFilter || '{이 작업의 테스트 대상}'}${A.repoFlag}\``,
    '  (`exit 3` = 프로젝트에 그 명령 정의가 없음 → 건너뛰고 결과에 남긴다)',
    '- 포맷·lint 는 여기서 돌리지 않는다 — 페이즈 완료 후 한 번만 실행한다.',
    '',
    `완료 후 "DONE: ${task.id}" 와 변경 파일 목록을 출력한다.`)
  return lines.filter((l) => l !== null).join('\n')
}

const CHECK_PROMPT = (A, phaseTitle) => `작업 디렉터리: ${A.cwd}

${phaseTitle} 구현이 끝났다. 프로바이더 계약 동사로만 검사한다:

\`\`\`bash
node scripts/px.js run lint${A.repoFlag}
node scripts/px.js run build${A.repoFlag}
\`\`\`

- \`exit 3\` = 프로젝트에 그 명령 정의 없음 → 그 검사만 건너뛰고 **무엇을 건너뛰었는지 남긴다.**
- \`exit 1\` = 실패 → 여기서 고치고 \`chore: ${phaseTitle} 검사 수정${A.issueRef ? ` (${A.issueRef})` : ''}\` 로 커밋한다.
- **전체 테스트 스위트는 돌리지 않는다** — 검증 스테이지(self-qa)가 스코프를 한정해 한 번만 실행한다.

lint/build 각각의 결과(pass|fail|skip)와 수정 커밋 여부를 출력한다.`

// ── args 정규화 + fail-loud ──
const A = (typeof args === 'string') ? JSON.parse(args) : args
if (!A || !A.cwd) {
  throw new Error('impl-phases: 필수 args 누락 (cwd). 받은 값: ' + JSON.stringify(A))
}
const AD = A.adapter || {}
if (!A.adapter) log('⚠️ args.adapter 없음 — 프로젝트 고유 값이 기본값으로 떨어진다.')
A.kitRoot = A.kitRoot || 'kit'
A.specPath = A.specPath || fromAdapter(AD, 'paths.specFile', null, '(스펙 경로 미지정 — 에이전트가 스펙을 읽지 못한다)')
A.planPath = A.planPath || fromAdapter(AD, 'paths.planFile', null, '(Plan 경로 미지정)')
A.repoFlag = A.repo ? ` --repo ${A.repo}` : ''

const totalTasks = PHASE_DEFS.reduce((n, p) => n + ((A[p.key] || []).length), 0)
if (!totalTasks) {
  throw new Error('impl-phases: phaseA/phaseB/phaseC 가 모두 비어 있다 — 분해할 작업이 없으면 이 스크립트를 부르지 않는다(순차 구현이 기본값).')
}
log(`impl-phases: A=${(A.phaseA || []).length} B=${(A.phaseB || []).length} C=${(A.phaseC || []).length} (총 ${totalTasks}작업)`)

const results = []
const skippedChecks = []

for (const def of PHASE_DEFS) {
  phase(def.title)
  const tasks = A[def.key] || []
  if (!tasks.length) {
    log(`${def.title}: 작업 없음 — 건너뜀`)
    results.push({ id: def.id, total: 0, ok: 0, serializedGroups: 0 })
    continue
  }

  const groups = groupByFileOverlap(tasks)
  const serialized = groups.filter((g) => g.tasks.length > 1)
  if (serialized.length) {
    log(`⚠️ ${def.title}: 대상 파일이 겹치는 작업 발견 — ${serialized.map((g) => g.tasks.map((t) => t.id).join('+')).join(', ')} 를 순차 실행한다`)
  }
  log(`${def.title}: ${groups.length}개 그룹 동시 시작 (작업 ${tasks.length}개)`)

  // 그룹끼리는 동시, 그룹 안에서는 순차 — 파일 충돌을 코드가 막는다
  const groupResults = await parallel(groups.map((g) => async () => {
    const out = []
    for (const t of g.tasks) {
      const r = await agent(implPrompt(A, t), { label: `${def.id}:${t.id}`, phase: def.title })
      out.push(r)
    }
    return out
  }))
  const ok = groupResults.filter(Boolean).flat().filter(Boolean).length
  log(`${def.title} 완료: ${ok}/${tasks.length} 성공`)

  // 페이즈 끝에서 검사 1회 (에이전트마다 돌리면 빌드 프로세스가 서로 경쟁한다)
  const check = await agent(CHECK_PROMPT(A, def.title), { label: `check:${def.id}`, phase: def.title })
  if (!check) skippedChecks.push(def.title)

  results.push({ id: def.id, total: tasks.length, ok, serializedGroups: serialized.length })
}

if (skippedChecks.length) log(`⚠️ 검사 에이전트가 실패한 페이즈: ${skippedChecks.join(', ')} — 호출자가 lint/build 를 직접 확인해야 한다`)

const totalOk = results.reduce((n, r) => n + r.ok, 0)
log(`impl-phases 종료: ${totalOk}/${totalTasks} 작업 성공`)
if (totalOk < totalTasks) log('⛔ 전부 성공하지 않았다 — implement 스킬은 이 상태를 "완료"로 보고하지 않는다(SKILL.md Step 6).')

return { phases: results, skippedChecks, totalTasks, totalOk }
