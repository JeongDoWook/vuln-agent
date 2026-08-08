'use strict';

/**
 * ref.js — 항목 참조 식별자 `<repo>:<id>` 파싱 (순수 함수, I/O 없음)
 *
 * **정본은 저장소 한정 형식 하나뿐이다.** 저장소를 생략한 순수 숫자("908")는 받지 않는다 —
 * 다중 저장소에서 이슈 번호대가 겹치면(FE 884-889 / BE 902-908 처럼 둘 다 800~900대),
 * bare 숫자로 한쪽만 빼려는 조작이 **양쪽 저장소의 908 을 동시에** 건드린다. 원본 구현은
 * 하위호환 때문에 bare 숫자를 "모든 repo" 로 의미 고정해 계속 지원했지만, 이 킷에는
 * 이어받을 과거 state 가 없으므로 그 예외를 들여오지 않는다.
 *
 * **형식 위반은 조용히 무시하지 않고 즉시 에러다.** 실측된 실패 사례(`"be:"`·`"be:abc"`·
 * `":908"`·`"fe:908:x"`)는 전부 "매치 안 됨"으로 조용히 통과해 스코핑 도구를 fail-open
 * 시켰다 — 빼려던 항목이 계획에 그대로 남아 착수됐다. 스코핑에서 "빼려던 게 안 빠짐"은
 * "필요없는 게 잘못 빠짐"보다 훨씬 위험하다.
 *
 * 정규화: 앞뒤 공백 trim, repo 는 소문자 폴딩(`"BE:908"`·`" be:908"` 모두 `be:908`).
 */

const { msError } = require('./errors');

// repo — 영숫자로 시작, 이후 영숫자·하이픈·언더스코어. id — 숫자만.
const REF_RE = /^([A-Za-z0-9][A-Za-z0-9_-]*):([0-9]+)$/;

const normalize = (raw) => String(raw === null || raw === undefined ? '' : raw).trim();

const isRef = (raw) => REF_RE.test(normalize(raw));

// {repo, id, key} — 형식 위반이면 던진다. what 은 에러 메시지에 쓰이는 필드 이름.
const parseRef = (raw, what = 'ref') => {
  const s = normalize(raw);
  const m = REF_RE.exec(s);
  if (!m) {
    throw msError(
      'invalid_ref',
      `${what} 형식 오류: ${JSON.stringify(raw)} — "<repo>:<id>" 형식만 허용한다(예: "be:908"). ` +
      '저장소를 생략한 숫자("908")는 번호대가 겹치는 다중 저장소에서 양쪽을 동시에 건드리므로 거부한다.',
      { value: raw, field: what }
    );
  }
  return { repo: m[1].toLowerCase(), id: m[2], key: `${m[1].toLowerCase()}:${m[2]}` };
};

const formatRef = (repo, id) => parseRef(`${repo}:${id}`, 'ref').key;

const refRepo = (raw, what) => parseRef(raw, what).repo;
const refId = (raw, what) => parseRef(raw, what).id;
const numericId = (raw, what) => Number(parseRef(raw, what).id);

// string[] — 목록 전체를 정규화한다. 하나라도 형식이 틀리면 그 항목을 지목해 던진다.
const parseRefList = (list, what = 'refs') => (list || []).map((r) => parseRef(r, what).key);

// item.refs({repo: id}) → key 목록. 저장소 한정 형식으로만 만든다.
const refsToKeys = (refs, what = 'refs') =>
  Object.entries(refs || {}).map(([repo, id]) => formatRef(repo, id, what));

module.exports = { REF_RE, isRef, parseRef, formatRef, refRepo, refId, numericId, parseRefList, refsToKeys };
