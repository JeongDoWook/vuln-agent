'use strict';

/**
 * advance-plan.js — 관측 → 상태 전이 판정 (순수 함수, I/O 없음)
 *
 * `watch` 와 `advance` 가 공유한다. 관측값(워크스페이스 스테이지 + `px pr get --source` 로
 * 얻은 PR 상태)을 받아 **어떤 항목을 어디로 옮길지**만 계산하고, 조회도 저장도 하지 않는다.
 *
 * ## 왜 "반박 없음"으로 done 을 주면 안 되는가 (이 모듈의 핵심)
 *
 * 워크스페이스가 `DONE` 스테이지에 도달했다는 사실은 **병합됐다는 뜻이 아니다.** 세션이
 * 순서를 잘못 밟으면 아티팩트는 done 인데 PR 은 아직 열려 있거나 아예 못 찾은 상태가 실재한다.
 * 원본은 처음에 "반박하는 PR 이 없으면 done" 으로 좁혔는데, 그건 **"반박 없음"과 "근거 완비"를
 * 혼동**한 결함이었다 — 두 저장소 항목에서 한쪽만 merged 이고 나머지 PR 을 아예 못 찾은
 * 경우까지 done 으로 승격시켰다(슬롯이 조용히 풀린다). 지금 규칙:
 *
 *   - 모든 저장소의 PR 을 실제로 찾았고 **전부 merged** → `done`
 *   - 전부 찾았는데 하나라도 merged 가 아니다 → `pr_open` (모순 반박)
 *   - **근거 자체가 불충분**(일부 저장소의 PR 을 못 찾음) → 즉시 done 이 아니라 증거미스
 *
 * ## 증거미스를 1회로 blocked 처리하지 않는 이유
 *
 * 트래커 replica lag·일시적 API 오류 한 번으로도 "근거 불충분"이 재현된다. 매번 사람을
 * 부르면 노이즈가 커서 아무도 안 본다. 항목별 **연속** 미스 카운터를 세어 임계(기본 3)에
 * 도달해야 실제 blocked 로 간다. 근거가 완비된 라운드가 한 번이라도 오면 카운터는 즉시
 * 0으로 리셋된다 — "연속"이 깨지면 처음부터 다시 센다.
 *
 * 조회 실패(Err)와 그냥 못 찾음(빈 결과)은 **같게** 취급한다. 둘 다 "이번 라운드에 이
 * 저장소의 근거를 못 얻었다"는 같은 뜻인데, 예전엔 전자가 조용한 무한 재시도, 후자가 즉시
 * blocked 로 갈려 비대칭이었다. 사유 문구만 구분한다.
 *
 * ## blocked 는 자동 복귀하지 않는다
 *
 * blocked 항목은 슬롯은 계속 점유하되(state.ACTIVE_STATUSES) **관측 대상에서는 빠진다**
 * (`observable`). 자동 복귀를 허용하면 원인이 그대로인 채 상태만 오가는 thrash 가 된다.
 * 복귀는 사람이 원인을 해결하고 `blockedFrom` 으로 직접 되돌릴 때만 일어난다.
 */

const { TRANSITIONS, applyTransition } = require('./state');
const { branchesFor } = require('./dispatch-plan');

// 진행 순서 — "역행" 판정의 유일한 기준이다.
const STATUS_ORDER = Object.freeze([
  'queued', 'ready', 'specced', 'dispatched', 'impl', 'qa_ok', 'pr_open', 'merged', 'done',
]);

const orderOf = (status) => STATUS_ORDER.indexOf(status);

// 워크스페이스 스테이지(`px ws stage` 의 STAGE 값) → 마일스톤 상태.
// REVIEW 는 QA 통과 후 PR 생성 전이라 qa_ok 와 같은 자리다.
const STAGE_TO_STATUS = Object.freeze({
  SPEC: 'dispatched', IMPL: 'impl', QA: 'qa_ok', REVIEW: 'qa_ok', PR: 'pr_open', DONE: 'done',
});

const DEFAULT_EVIDENCE_MISS_LIMIT = 3;

const evidenceMissLimitOf = (raw) => (
  typeof raw === 'number' && Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_EVIDENCE_MISS_LIMIT
);

/**
 * 관측 1건이 가리키는 목표 상태.
 *
 * @param stage     아티팩트/워크스페이스가 가리키는 상태(STAGE_TO_STATUS 적용 후)
 * @param prStates  실제로 찾은 PR 의 상태 배열(찾지 못한 저장소는 아예 원소가 없다)
 * @param repoCount 이 항목이 걸친 저장소 수
 * @returns {status|'insufficient'|'unknown'}
 */
const observedStage = (stage, prStates = [], repoCount = 1) => {
  // 확인할 저장소 자체가 없다 — 정상 흐름에선 나올 수 없는 손편집 state.
  // "사람이 확인할 구체적 대상이 있다"는 뜻의 blocked 를 쓰면 오해를 부른다.
  if (!repoCount) return 'unknown';
  if (stage !== 'done') return stage;

  if (prStates.length !== repoCount) return 'insufficient';
  return prStates.every((s) => s === 'merged') ? 'done' : 'pr_open';
};

// 관측 입력에서 이 항목을 이번 라운드에 관측할 수 있는지 판정한다.
// {ok:true, branches} | {ok:false, reason}
const observability = (item, { branchPattern } = {}) => {
  const repos = Object.keys(item.refs || {});
  if (repos.length === 0) return { ok: false, reason: `${item.key}: refs 가 비어 관측 대상 저장소를 정할 수 없다` };

  const branches = branchesFor(item, branchPattern);
  const missing = repos.filter((r) => !branches[r]);
  if (missing.length) {
    return {
      ok: false,
      reason: `${item.key}: branches.${missing.join('/')} 가 없고 slug 도 무효해(${JSON.stringify(item.slug)}) `
        + '브랜치명을 정할 수 없다 — 이번 라운드 관측을 건너뛴다(blocked 로 승격시키지 않는다)',
    };
  }
  // item.branches 가 모든 저장소를 명시하고 있으면 slug 가 무효해도 관측할 수 있다 —
  // slug 는 브랜치명을 **추정할 때만** 필요하다.
  return { ok: true, branches };
};

// 현재 상태에서 목표까지 한 단계씩 걸어간다(다단계 전이). 한 스텝이라도 막히면 거부다.
// {ok:true, item, path} | {ok:false, error}
const walkTo = (item, target, { reason = '', at = null } = {}) => {
  let cur = item;
  const path = [];
  let guard = STATUS_ORDER.length + 1;

  while (cur.status !== target) {
    if (guard-- <= 0) return { ok: false, error: `전이 경로가 수렴하지 않는다: ${item.status} → ${target}` };

    let next;
    if (cur.status === 'blocked') {
      next = cur.blockedFrom;
      if (next !== target) return { ok: false, error: `blocked 복귀는 blockedFrom(${cur.blockedFrom})으로만 가능 — 요청: ${target}` };
    } else if (target === 'blocked') {
      next = 'blocked';
    } else {
      const allowed = (TRANSITIONS[cur.status] || []).filter((s) => s !== 'blocked');
      next = allowed.find((s) => orderOf(s) <= orderOf(target));
      if (!next) return { ok: false, error: `전이 경로 없음: ${cur.status} → ${target}` };
    }

    const step = applyTransition(cur, next, { reason, at });
    if (!step.ok) return step;
    cur = step.item;
    path.push(next);
  }
  return { ok: true, item: cur, path };
};

/**
 * 라운드 하나의 전이 계획.
 *
 * observations: { [key]: { stage, prStates:[], observedRepos:[], error?:string } }
 *   - stage         STAGE_TO_STATUS 적용 전/후 아무거나(문자열이 STAGE 키면 변환한다)
 *   - prStates      실제로 찾은 PR 상태만 담는다. 조회 실패도 "못 찾음"과 같게 원소를 넣지 않는다
 *   - error         조회 실패 사유(있으면 사유 문구에만 반영, 판정은 동일)
 *
 * @returns {transitions, rejected, held, unobservable, blockedItems, items, appliedCount}
 *   items 는 전이를 반영한 **새 배열**이다(입력을 변형하지 않는다).
 */
const planTransitions = ({ items, observations = {}, evidenceMissLimit, branchPattern, at = null }) => {
  const limit = evidenceMissLimitOf(evidenceMissLimit);
  const transitions = [];
  const rejected = [];
  const held = [];
  const unobservable = [];
  const blockedItems = [];

  const next = items.map((item) => {
    // blocked 는 슬롯은 점유하되 관측하지 않는다 — 자동 복귀 없음.
    if (item.status === 'blocked') {
      blockedItems.push({ key: item.key, blockedFrom: item.blockedFrom, reason: item.lastObservedReason || null });
      return item;
    }

    const obs = observations[item.key];
    if (!obs) return item;

    const view = observability(item, { branchPattern });
    if (!view.ok) { unobservable.push({ key: item.key, reason: view.reason }); return item; }

    const repoCount = Object.keys(item.refs || {}).length;
    const stage = STAGE_TO_STATUS[obs.stage] || obs.stage;

    // 스테이지를 아예 못 읽은 라운드(워크스페이스 조회 미지원·워크스페이스 없음)를
    // "역행 관측"으로 흘리면 사람이 보는 사유와 실제 원인이 어긋난다 — 관측 불가로 가른다.
    if (!stage || orderOf(stage) === -1) {
      unobservable.push({
        key: item.key,
        reason: `${item.key}: 워크스페이스 스테이지를 관측하지 못했다(관측값: ${JSON.stringify(obs.stage)}) — `
          + '이번 라운드를 건너뛴다. 워크스페이스가 살아 있는지, 프로바이더가 ws list 를 지원하는지 확인할 것',
      });
      return item;
    }

    const target = observedStage(stage, obs.prStates || [], repoCount);

    if (target === 'unknown') {
      unobservable.push({ key: item.key, reason: `${item.key}: 관측 대상 저장소가 없다(refs 확인 필요)` });
      return item;
    }

    if (target === 'insufficient') {
      const count = (item.evidenceMissCount || 0) + 1;
      const found = (obs.prStates || []).length;
      const why = obs.error
        ? `PR 조회 실패 — ${obs.error}`
        : `PR 근거 불충분 — ${repoCount}개 저장소 중 ${found}건만 확인됨(브랜치명 컨벤션 불일치 여부부터 확인할 것)`;

      if (count < limit) {
        held.push({ key: item.key, missCount: count, limit, reason: why });
        return { ...item, evidenceMissCount: count };
      }
      const walked = walkTo({ ...item, evidenceMissCount: count }, 'blocked', { reason: why, at });
      if (!walked.ok) { rejected.push({ key: item.key, from: item.status, observed: 'blocked', reason: walked.error }); return item; }
      transitions.push({ key: item.key, from: item.status, to: 'blocked', path: walked.path, reason: why });
      return walked.item;
    }

    // 근거가 완비된 라운드 — 연속이 깨졌으므로 카운터를 즉시 리셋한다.
    const reset = (item.evidenceMissCount || 0) === 0 ? item : { ...item, evidenceMissCount: 0 };

    if (target === reset.status) return reset;

    // 역행 거부 — 잘못된 아티팩트 잔존이나 state 수기 편집 오류일 수 있다. 강제하지 않는다.
    if (orderOf(target) < orderOf(reset.status)) {
      rejected.push({
        key: item.key, from: reset.status, observed: target,
        reason: `관측값이 현재 상태보다 뒤에 있다(역행) — 자동으로 되돌리지 않는다. 아티팩트 잔존/수기 편집 여부를 확인할 것`,
      });
      return reset;
    }

    const walked = walkTo(reset, target, { reason: `관측 전이(${reset.status} → ${target})`, at });
    if (!walked.ok) {
      rejected.push({ key: item.key, from: reset.status, observed: target, reason: walked.error });
      return reset;
    }
    transitions.push({ key: item.key, from: reset.status, to: target, path: walked.path, reason: null });
    return walked.item;
  });

  return {
    transitions, rejected, held, unobservable, blockedItems,
    items: next,
    appliedCount: transitions.length,
  };
};

// 이번 라운드에 done 으로 간 항목이 반납한 슬롯 수.
const reclaimedSlots = (transitions, itemsByKey) => transitions
  .filter((t) => t.to === 'done')
  .reduce((n, t) => n + Object.keys((itemsByKey.get(t.key) || {}).refs || {}).length, 0);

module.exports = {
  STATUS_ORDER, STAGE_TO_STATUS, DEFAULT_EVIDENCE_MISS_LIMIT,
  orderOf, evidenceMissLimitOf, observedStage, observability, walkTo, planTransitions, reclaimedSlots,
};
