'use strict';

/**
 * dispatch-plan.js — 착수 계획 조립 (순수 함수, I/O 없음)
 *
 * 마일스톤 층은 **직접 구현하지 않는다.** 여기서 만드는 것은 "이 항목을 착수시켜라"는
 * 명령 목록뿐이고, 실제 작업은 워크스페이스마다 `pipeline`(이슈 1건 주기)이 한다.
 * 외부 시스템에 닿는 유일한 문은 `node scripts/px.js <동사>` 다 — 이 모듈은 그 문자열을
 * 조립만 하고 실행하지 않는다(실행은 scripts/ms.js).
 *
 * ## slug 게이트가 왜 dispatch 보다 먼저인가
 *
 * `slug` 는 트래커가 주지 않는다 — 사람이 착수 직전에 손으로 채운다(mergeItems 는 신규
 * 항목을 항상 `slug: null` 로 만든다). 채우는 걸 잊으면 `ws create null` 이 그대로 나가
 * `null` 이라는 이름의 워크스페이스가 생긴다. 실측된 실패는 falsy 만이 아니다 — 사람이
 * JSON 을 손으로 고치다 진짜 `null` 대신 **문자열 `"null"`** 을 남기면 falsy 검사를 그냥
 * 통과한다. slug 는 워크스페이스 디렉터리명과 브랜치명 양쪽에 그대로 쓰이므로 공백·
 * 경로 구분자(`/`, `..`)·셸 메타문자가 섞인 값도 같은 이유로 막는다. 화이트리스트 정규식
 * 하나로 이 전부를 커버한다.
 *
 * 이 게이트는 dispatch 만의 것이 아니다 — `advance`(관측)도 `branches` 가 비어 있으면
 * 브랜치명을 slug 로 추정하므로 같은 판정을 재사용한다. 무효한 slug 로 추정한 브랜치는
 * 항상 빈 결과를 내고, 그게 "근거 없음 → blocked" 로 잘못 승격되면 사람이 보는 사유
 * (브랜치 컨벤션 불일치)와 실제 원인(slug 가 없다)이 어긋난다.
 */

const { msError } = require('./errors');

// 영숫자·하이픈·언더스코어만, 시작/끝은 반드시 영숫자.
const SLUG_PATTERN = /^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$/i;

// falsy 로는 안 걸리는 "리터럴 문자열" 실수.
const RESERVED_SLUGS = new Set(['null', 'undefined']);

const DEFAULT_BRANCH_PATTERN = 'feature/issue-{id}-{slug}';

const isValidSlug = (slug) => {
  if (typeof slug !== 'string') return false;                 // null/undefined/숫자 등
  if (slug.trim() !== slug) return false;                     // 앞뒤 공백
  if (slug === '') return false;
  if (RESERVED_SLUGS.has(slug.toLowerCase())) return false;   // 리터럴 "null"/"undefined"
  return SLUG_PATTERN.test(slug);
};

// {ready, blocked:[{key, reason}]}
const slugGate = (candidates, statePath = '.review-kit-milestone.json') => {
  const ready = [];
  const blocked = [];
  candidates.forEach((c) => {
    if (isValidSlug(c.slug)) ready.push(c);
    else {
      blocked.push({
        key: c.key,
        reason: `slug 미확정(현재: ${JSON.stringify(c.slug)}) — ${statePath} 의 items[key=${c.key}].slug 를 `
          + '유효한 값으로 채운 뒤 다시 실행할 것(공백·경로 구분자·셸 메타문자·리터럴 "null"/"undefined" 금지). '
          + '절대 손으로 slug 를 추측해 명령을 채워 넣지 않는다.',
      });
    }
  });
  return { ready, blocked };
};

// 브랜치명 추정 — `ws create` 가 실제 브랜치명을 돌려주면 그 값(item.branches)이 정본이고,
// 이건 그게 아직 없을 때만 쓰는 폴백이다. slug 가 무효하면 추정 자체를 하지 않는다.
const guessBranch = ({ repo, id, slug, pattern = DEFAULT_BRANCH_PATTERN }) => {
  if (!isValidSlug(slug)) return null;
  return String(pattern)
    .replace(/\{repo\}/g, repo)
    .replace(/\{id\}/g, String(id))
    .replace(/\{issue\}/g, String(id))
    .replace(/\{slug\}/g, slug);
};

// 항목의 저장소별 브랜치명 — item.branches 우선, 없으면 추정. 추정도 못 하면 null.
const branchesFor = (item, pattern = DEFAULT_BRANCH_PATTERN) => {
  const out = {};
  Object.entries(item.refs || {}).forEach(([repo, id]) => {
    const explicit = (item.branches || {})[repo];
    out[repo] = explicit || guessBranch({ repo, id, slug: item.slug, pattern });
  });
  return out;
};

// 항목 하나를 착수시키는 px 명령 목록. 실행하지 않는다 — 문자열만 만든다.
//
// 다중 저장소 항목은 `ws create` 를 한 번만 부르고 `--repo` 로 저장소를 나열한다.
// `--issue` 는 계약상 한 값만 받으므로 **정본 key 의 id** 를 넘긴다 — 저장소마다 이슈
// 번호가 다른 항목의 나머지 번호는 state 의 `refs` 가 보존한다(계약 확장 없이 쓸 수 있는
// 최선이고, 남은 부채는 워커 노트에 적어둔다).
const dispatchCommands = (item, { pxPath = 'scripts/px.js' } = {}) => {
  if (!isValidSlug(item.slug)) {
    throw msError('invalid_slug',
      `dispatchCommands: ${item.key} 의 slug 가 유효하지 않다(${JSON.stringify(item.slug)}) — slugGate 를 먼저 통과시킬 것`);
  }
  const repos = Object.keys(item.refs);
  const primaryRepo = item.key.split(':')[0];
  const primaryId = item.refs[primaryRepo] !== undefined ? item.refs[primaryRepo] : item.refs[repos[0]];

  return [
    `node ${pxPath} ws create ${item.slug} --issue ${primaryId} --repo ${repos.join(',')}`,
    `node ${pxPath} ws verify ${item.slug}`,
    `node ${pxPath} ws stage ${item.slug} SPEC`,
  ];
};

// 워크스페이스 세션에 넘길 지시문. 마일스톤 층이 직접 구현하지 않는다는 계약이
// 이 문장에 담긴다 — 이 워크스페이스는 `pipeline` 한 주기만 돈다.
const handoffMessage = (item, { base = null } = {}) => [
  `요구사항: ${item.title || '(제목 없음)'}`,
  `- 항목: ${item.key}${Object.keys(item.refs).length > 1 ? ` (${Object.entries(item.refs).map(([r, i]) => `${r}:${i}`).join(' + ')})` : ''}`,
  base ? `- base/PR target: ${base}` : null,
  item.notes ? `- 메모: ${item.notes}` : null,
  '',
  '`pipeline` 을 그대로 돌린다. 게이트에서 반드시 멈추고 승인을 기다린다.',
  'PR 병합은 사람 승인 없이 자동 실행 금지.',
].filter(Boolean).join('\n');

// {slots, dispatch:[{key, slug, refs, commands, handoff}], deferred, blocked, gate}
//
// 순서: slug 게이트 → preflight(드리프트·부하·의존·슬롯). slug 가 없는 항목이 슬롯을
// 차지한 것처럼 계산되면 안 되므로 게이트가 먼저다.
const buildDispatchPlan = ({ items, candidates, preflight, base = null, pxPath = 'scripts/px.js' }) => {
  const dispatch = (preflight.allowed || []).map((c) => ({
    key: c.key,
    slug: c.slug,
    refs: c.refs,
    title: c.title,
    commands: dispatchCommands(c, { pxPath }),
    handoff: handoffMessage(c, { base }),
  }));
  return {
    slots: preflight.slots,
    gate: preflight.gate || null,
    dispatch,
    deferred: preflight.deferred || [],
    total: (items || []).length,
    candidates: (candidates || []).length,
  };
};

module.exports = {
  SLUG_PATTERN, RESERVED_SLUGS, DEFAULT_BRANCH_PATTERN,
  isValidSlug, slugGate, guessBranch, branchesFor, dispatchCommands, handoffMessage, buildDispatchPlan,
};
