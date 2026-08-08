'use strict';

/**
 * errors.js — 마일스톤 계층이 던지는 예외의 유일한 생성 지점.
 *
 * 프로바이더 계약 §4.2 와 같은 규약을 쓴다: 평범한 Error 에 code/exitCode/data 를
 * 얹어 던지고, 진입점(scripts/ms.js)이 그걸 그대로 봉투에 담는다. 계층이 진입점을
 * import 하지 않기 위한 규약이므로 여기서도 클래스를 만들지 않는다.
 *
 *   exitCode 1 — 사용법·설정·state 손상 (사람이 고치면 재시도 가능)
 *   exitCode 2 — 게이트 위반 (드리프트 초과, --force 없는 파괴적 삭제 등). 멈추고 보고한다
 *   exitCode 3 — 이 설치가 그 동사를 지원하지 않음
 */

const msError = (code, message, data, exitCode = 1) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (data !== undefined) e.data = data;
  return e;
};

module.exports = { msError };
