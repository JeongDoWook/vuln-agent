'use strict';

/**
 * plan-merge.js — `plan` 의 state 재조정 정책 전부 (순수 함수, I/O 없음)
 *
 * 트래커가 소유하는 값(title·priority·refHints)과 사람이 소유하는 값(dependsOn·status·
 * slug·workspace·branches·prs·specVerified·gate·blockedFrom·notes)을 분리해 병합한다.
 * `lastObservedAt`/`lastObservedReason`/`evidenceMissCount` 는 셋 중 어디도 아닌 세 번째
 * 부류다 — 트래커가 주는 값도 사람이 쓰는 값도 아닌 **watch 의 기계 관측 기록**이다.
 * 그래도 재계획 때마다 증발하면 안 되므로 notes 와 동일하게 "있으면 그대로 이어간다".
 *
 * 이 모듈이 고정하는 규칙은 전부 원본 운용에서 실제로 사고가 난 지점이다:
 *
 *  (a) **오펀 보존** — 기존 items 에 있던 항목이 이번 수집 결과에 없으면(닫힘·라벨 변경·
 *      selector 이탈) 버리지 않는다. 버리면 status·workspace·branches·prs 가 통째로
 *      증발한다. 항목이 `done` 에 도달하는 바로 그 순간(이슈를 닫는 순간)이 가장 위험한
 *      지점이다 — 그 시점에 수집에서 사라지기 때문이다. 있는 그대로 보존하고 key 목록을
 *      호출자에게 돌려줘 경고하게 한다.
 *      (부수 효과: 살아있는 다른 항목이 이 오펀을 dependsOn 으로 참조하고 있었다면,
 *      지웠을 때 topoLevels 가 "존재하지 않는 선행 참조"로 실패했을 상황도 막아준다.)
 *
 *  (b) **다중 저장소 refs 보존** — 사람이 FE+BE 이슈를 손으로 한 항목에 합쳤다면
 *      (guard.slotsOf 가 2슬롯으로 센다) refs 를 이번에 수집된 단일 저장소 값으로 통째로
 *      교체하면 안 된다. 새로 온 ref 를 기존 refs 에 **병합**한다.
 *
 *  (c) **흡수 판정의 결정성** — (b)로 합쳐도 selector 는 매번 두 저장소를 전부 재조회한다.
 *      "이 key 를 이미 다른 항목이 refs 로 소유하고 있는가"를 가려 소유자가 자기 자신이
 *      아니면 버린다. 이 판정을 prevItems 순회 순서로 하면(last-write-wins) 결과가 배열의
 *      우연한 순서에 좌우된다. resolveClaims 는 **key 오름차순으로 정렬한 뒤** 순회해
 *      입력 순서에서 완전히 독립적으로 만들고 다음 규칙으로 결정한다:
 *        ① self-claim(항목이 자기 key 와 같은 ref 를 보유 — 모든 항목이 트리비얼하게 성립)
 *           보다 foreign-claim(다른 key 의 항목이 그 ref 를 보유 = 사람이 합친 결과)이 이긴다.
 *           후자가 더 신뢰할 수 있는 신호이고, 전자는 병합 전 상태의 화석일 뿐이다.
 *        ② 서로 다른 두 항목이 **둘 다 foreign** 으로 같은 ref 를 보유하면 정상적인 병합이
 *           아니라 손 편집 실수다. key 오름차순으로 먼저 오는 쪽을 소유자로 확정하고
 *           나머지에서 그 ref 만 제거한다(항목 전체는 지우지 않는다 — 다른 ref 는 유효하다).
 *           그러지 않으면 같은 ref 를 둘이 중복으로 세어 슬롯 합계가 부풀려진다.
 *           이 충돌은 `warnings` 로 반드시 알린다.
 *
 *  (d) **명시적 제외 ≠ 오펀** — (a)는 "사람 의도가 아니라 트래커 사정으로 이번엔 안 보인다"를
 *      전제로 한다. 그런데 excludeRefs/titleExclude 로 사람이 **의도적으로** 뺀 항목도 수집
 *      결과에 없기는 마찬가지다. 구분하지 않으면 오펀 보존이 그 의도를 되살려, 스코핑
 *      도구가 첫 `--apply` 이후로 조용히 무력화된다. excludedKeys(classifyItems 가 "왜
 *      빠졌는지" 판정해 넘긴 값)를 받아 명시적 제외분만 실제로 버린다.
 *
 *  (e) **in-flight 삭제 거부** — (d)로 즉시 지우는 건 titleExclude 오탐일 때 특히 위험하다.
 *      삭제 대상이 `queued`(아직 아무 작업도 안 한 순수 백로그)가 아니면 workspace·branches·
 *      prs 가 이 항목에만 남은 **유일한 기록**이라 조용히 지우면 복구할 수 없다. 그래서
 *      진행 중 항목은 매치돼도 `--force` 없이는 지우지 않는다 — items 에 그대로 남기고
 *      `excludedBlocked` 로 강하게 보고한다.
 *
 *  (f) **흡수된 leftover 의 최종 운명** — (c)로 흡수된 key 는 items 에서 빼되 그 사실을
 *      `absorbed` 로 돌려준다. 조용히 지우지도, 중복인 채로 남기지도 않는다. 그 key 가 과거
 *      자기만의 status/workspace/prs 를 갖고 있었을 수 있고 그 값이 소유 항목 쪽에 옮겨졌는지
 *      이 함수는 알 도리가 없기 때문이다 — 자동 이전(추측 병합)도 그냥 버리기(유실 은폐)도
 *      안전하지 않으므로 "확인하고 필요하면 직접 지워라"라고 소리 내어 보고한다.
 */

const { msError } = require('./errors');
const { parseRef, formatRef } = require('./ref');

const REJECT = Object.freeze({ REF: 'excluded_ref', TITLE: 'excluded_title', NONE: null });

const isAlnum = (ch) => /[a-z0-9]/i.test(ch || '');

// titleExclude 항목이 제목 안에서 "토큰 경계"로 매치되는지 판정한다.
//
// 단순 substring 이면 "v3" 를 등록했을 때 "rev3"·"v30" 처럼 더 큰 토큰의 일부에도 매치된다.
// titleExclude 매치는 단순 필터링이 아니라 items 에서 **실제 삭제**까지 하므로, 무관한
// 항목이 오탐으로 지워지는 사고가 난다.
//
// 판정: 매치 위치의 앞/뒤 글자가 영숫자이고 term 자신의 그쪽 끝도 영숫자면 진짜 경계가
// 아니다(더 큰 토큰의 일부) — 버리고 다음 occurrence 를 찾는다. 반대로 term 의 그쪽 끝이
// 영숫자가 아니면(예: "[문서]" 는 '[' 로 시작해 ']' 로 끝) 그쪽 경계 검사는 애초에
// 무의미하므로 항상 통과시킨다 — 그래야 괄호로 감싼 실제 배제 대상이 계속 걸린다.
// 한글은 ASCII 영숫자가 아니므로 이미 경계로 취급된다(정규식 \b 와 같은 전제).
const includesAsToken = (titleLower, termLower) => {
  if (!termLower) return false;
  const startsAlnum = isAlnum(termLower[0]);
  const endsAlnum = isAlnum(termLower[termLower.length - 1]);

  let from = 0;
  for (;;) {
    const idx = titleLower.indexOf(termLower, from);
    if (idx === -1) return false;
    const before = idx > 0 ? titleLower[idx - 1] : '';
    const after = idx + termLower.length < titleLower.length ? titleLower[idx + termLower.length] : '';
    if ((!startsAlnum || !isAlnum(before)) && (!endsAlnum || !isAlnum(after))) return true;
    from = idx + 1;
  }
};

// selector.excludeRefs 전체를 정규화한다. 형식 위반은 여기서 즉시 던진다(ref.parseRef).
// **네트워크를 타기 전에** 부르는 것이 계약이다 — 오탈자가 "매치 안 됨"으로 조용히
// 통과하면 스코핑이 fail-open 한다.
const normalizeExcludeRefs = (list) => (list || []).map((r) => parseRef(r, 'selector.excludeRefs').key);

// 'excluded_ref' | 'excluded_title' | null
const classifyExclusion = (issue, selector = {}, excludeRefSet = null) => {
  const refs = excludeRefSet || new Set(normalizeExcludeRefs(selector.excludeRefs));
  if (refs.has(formatRef(issue.repo, issue.id))) return REJECT.REF;

  const titleLower = String(issue.title || '').toLowerCase();
  const terms = selector.titleExclude || [];
  if (terms.some((t) => includesAsToken(titleLower, String(t).toLowerCase()))) return REJECT.TITLE;

  return REJECT.NONE;
};

// 포함 조건. 트래커 쪽에서 이미 milestone/labels 로 걸러 왔으므로 제목 규칙이 하나도
// 없으면 전부 포함이다 — 제목 문자열을 다시 볼 이유가 없다. titlePrefix/titleContains 는
// 마일스톤 객체를 쓰지 않는 트래커를 위한 보조 수단이다.
const included = (issue, selector = {}) => {
  const hasTitleRule = Boolean(selector.titlePrefix || selector.titleContains);
  if (!hasTitleRule) return true;
  if (selector.titlePrefix && String(issue.title || '').startsWith(selector.titlePrefix)) return true;
  if (selector.titleContains && String(issue.title || '').includes(selector.titleContains)) return true;
  return false;
};

// 수집된 이슈 배열을 selector 로 분류한다.
//   items        — 포함 조건을 통과한 항목
//   excludedKeys — excludeRefs/titleExclude 로 **사람이 의도적으로 배제**한 항목의 key.
//                  단순히 포함 조건에 안 맞는 항목(selector 이탈)은 여기 들어가지 않는다 —
//                  mergeItems 가 그건 오펀으로 보존해야 하기 때문이다((a) vs (d)).
//
// 배제 판정이 상태(open/closed) 필터보다 **먼저**다. excludeRefs 는 "백로그에서 빼라"는
// 명시적 지시라 이슈 상태와 무관하게 존중돼야 한다 — 상태 필터를 먼저 적용하면 닫힌 이슈가
// 배제 판정을 타지 못해 excludedKeys 에 안 들어가고, mergeItems 가 그걸 오펀으로 보고
// state 에 영원히 보존한다(폐기한 이슈가 백로그에서 안 사라지는 사고).
const classifyItems = (rawIssues, selector = {}) => {
  const excludeRefSet = new Set(normalizeExcludeRefs(selector.excludeRefs));
  const items = [];
  const excludedKeys = [];

  (rawIssues || []).forEach((i) => {
    const r = parseRef(`${i.repo}:${i.id}`, '수집 항목 ref');
    if (classifyExclusion(i, selector, excludeRefSet) !== REJECT.NONE) {
      excludedKeys.push(r.key);
      return;
    }
    if (selector.state && i.state && i.state !== selector.state) return;
    if (!included(i, selector)) return;
    items.push({
      key: r.key,
      repo: r.repo,
      id: r.id,
      title: i.title || '',
      priority: i.priority === undefined ? null : i.priority,
      refHints: (i.refHints || []).filter((h) => h !== r.key),
    });
  });

  return { items, excludedKeys };
};

// {ownerOf: Map<key, {key, isSelf}>, warnings: string[]} — (c)
const resolveClaims = (prevItems) => {
  const sorted = [...prevItems].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const ownerOf = new Map();
  const warnings = [];

  sorted.forEach((p) => {
    Object.entries(p.refs || {}).forEach(([repo, id]) => {
      const composite = formatRef(repo, id);
      const isSelf = composite === p.key;
      const cur = ownerOf.get(composite);

      if (!cur) { ownerOf.set(composite, { key: p.key, isSelf }); return; }
      if (cur.key === p.key) return;                       // 같은 항목이 중복 기재 — 무시

      if (cur.isSelf && !isSelf) {
        ownerOf.set(composite, { key: p.key, isSelf });    // ① foreign 이 self 를 이긴다
      } else if (!cur.isSelf && isSelf) {
        // 기존 foreign 소유자 유지 — self 는 진다
      } else {
        // ② 둘 다 foreign — 손 편집 실수. 정렬돼 있으므로 cur 이 key 오름차순으로 먼저다.
        warnings.push(
          `중복 소유권 충돌: ${composite} 를 ${cur.key} 와 ${p.key} 가 모두 refs 로 보유 — `
          + `key 오름차순으로 ${cur.key} 를 우선하고 ${p.key} 에서는 이 ref 를 제거했다(손 편집 확인 필요)`
        );
      }
    });
  });

  return { ownerOf, warnings };
};

// {items, orphans, excluded, excludedBlocked, absorbed, warnings}
// prevItems/fetchedItems 를 변형하지 않는다.
//
// excludedKeys — classifyItems 가 "사람이 의도적으로 뺐다"고 판정한 key 목록. 생략하면
//                이번 수집에서 사라진 항목을 전부 오펀 취급한다.
// opts.force   — true 면 in-flight 배제 대상도 (e) 유예 없이 즉시 제거한다.
const mergeItems = (prevItems, fetchedItems, excludedKeys = [], opts = {}) => {
  const force = Boolean(opts.force);
  const backlogStatus = opts.backlogStatus || 'queued';
  const prev = new Map(prevItems.map((i) => [i.key, i]));
  const fetchedKeys = new Set(fetchedItems.map((i) => i.key));
  const excludedSet = new Set(excludedKeys);

  const { ownerOf, warnings } = resolveClaims(prevItems);
  const absorbedSet = new Set();

  // 소유권 판정에서 이 항목이 실제로 지킨 ref 만 남긴다 — 충돌에서 진 ref 는 여기서 빠진다.
  const resolvedRefs = (item) => {
    const out = {};
    Object.entries(item.refs || {}).forEach(([repo, id]) => {
      const owner = ownerOf.get(formatRef(repo, id));
      if (!owner || owner.key === item.key) out[repo] = String(id);
    });
    return out;
  };

  const items = fetchedItems
    .filter((i) => {
      const owner = ownerOf.get(i.key);
      const absorbed = Boolean(owner) && owner.key !== i.key;
      if (absorbed) absorbedSet.add(i.key);              // (c)/(f)
      return !absorbed;
    })
    .map((i) => {
      const p = prev.get(i.key);
      return {
        key: i.key,
        // (b) 기존 refs 에 병합 — 교체 금지
        refs: { ...(p ? resolvedRefs(p) : {}), [i.repo]: String(i.id) },
        title: i.title,
        priority: i.priority,
        dependsOn: p ? (p.dependsOn || []) : [],
        status: p ? p.status : backlogStatus,
        slug: p ? p.slug : null,
        workspace: p ? p.workspace : null,
        branches: p ? (p.branches || {}) : {},
        prs: p ? (p.prs || {}) : {},
        specVerified: p ? Boolean(p.specVerified) : false,
        gate: p ? (p.gate === undefined ? null : p.gate) : null,
        blockedFrom: p ? (p.blockedFrom === undefined ? null : p.blockedFrom) : null,
        notes: p ? (p.notes || '') : '',
        // 기계 관측 기록 — 여기 안 넣으면 `plan --apply` 한 번으로 관측 이력이 증발한다.
        lastObservedAt: p ? (p.lastObservedAt === undefined ? null : p.lastObservedAt) : null,
        lastObservedReason: p ? (p.lastObservedReason === undefined ? null : p.lastObservedReason) : null,
        // 이게 매 재계획마다 0으로 리셋되면 threshold 직전까지 쌓인 미스가 조용히 지워져
        // blocked 승격이 영원히 안 걸린다.
        evidenceMissCount: p ? (p.evidenceMissCount || 0) : 0,
        refHints: i.refHints || [],
      };
    });

  // (a)/(d)/(e) — 이번 수집에 없는 기존 항목을 "왜 없는지"로 가른다.
  const missing = prevItems.filter((i) => !fetchedKeys.has(i.key));
  const orphans = [];
  const excluded = [];
  const excludedBlocked = [];

  missing.forEach((o) => {
    const owner = ownerOf.get(o.key);
    if (owner && owner.key !== o.key) { absorbedSet.add(o.key); return; }   // (f)

    const resolved = { ...o, refs: resolvedRefs(o) };

    if (excludedSet.has(o.key)) {
      if (force || resolved.status === backlogStatus) {
        excluded.push(o.key);                                                // (d)
        return;
      }
      excludedBlocked.push(o.key);                                           // (e)
      items.push(resolved);
      return;
    }

    orphans.push(o.key);                                                     // (a)
    items.push(resolved);
  });

  return { items, orphans, excluded, excludedBlocked, absorbed: [...absorbedSet], warnings };
};

// Wave.approvedAt 재조정 정책 — 사람 소유 값이므로 매 --apply 마다 지우지 않는다.
//
// 규칙: Wave 의 items 구성(집합, 순서 무관)이 이전과 같으면 approvedAt 을 그대로 이어간다.
// 순서 무관인 이유 — Wave 내 실행 순서는 우선순위 재계산으로 바뀔 수 있지만 사람이 승인한
// 것은 "이 항목들의 묶음"이지 나열 순서가 아니다. 반대로 집합 자체가 바뀌면(추가·제거)
// 승인 당시 검토 대상과 달라진 것이므로 리셋한다 — 재승인 없이 예전 승인을 새 구성에
// 물려주면 감사가 깨진다(의도된 보수적 기본값).
const mergeWaves = (prevWaves, nextWaves) => {
  const prevById = new Map((prevWaves || []).map((w) => [w.id, w]));
  const sameSet = (a, b) => {
    if (a.length !== b.length) return false;
    const sa = new Set(a);
    return b.every((x) => sa.has(x));
  };

  return nextWaves.map((w) => {
    const p = prevById.get(w.id);
    const carry = p && sameSet(p.items || [], w.items);
    return { id: w.id, approvedAt: carry ? (p.approvedAt || null) : null, items: w.items };
  });
};

// dependsOn 이 items 에서 사라진 key 를 가리키면 topoLevels 가 통째로 실패한다 —
// 어느 항목이 원인인지 먼저 지목한다(경고만, 자동 수정하지 않는다).
const danglingDependencies = (items) => {
  const keys = new Set(items.map((i) => i.key));
  const out = [];
  items.forEach((i) => (i.dependsOn || []).forEach((d) => {
    if (!keys.has(d)) out.push({ key: i.key, dependsOn: d });
  }));
  return out;
};

const assertValidSelector = (selector = {}) => {
  normalizeExcludeRefs(selector.excludeRefs);
  (selector.titleExclude || []).forEach((t) => {
    if (typeof t !== 'string' || t === '') {
      throw msError('invalid_selector', `selector.titleExclude 항목이 비어있거나 문자열이 아니다: ${JSON.stringify(t)}`);
    }
  });
  return true;
};

module.exports = {
  REJECT, isAlnum, includesAsToken, normalizeExcludeRefs, classifyExclusion, included,
  classifyItems, resolveClaims, mergeItems, mergeWaves, danglingDependencies, assertValidSelector,
};
