#!/usr/bin/env node
/**
 * gen-score.js — report.json의 점수·등급을 어댑터 감점표로 다시 계산한다.
 *
 * 이 저장소에서 유일하게 "에이전트가 낸 결론을 기계가 검산하는" 스크립트다.
 * gen-review/gen-report는 렌더러일 뿐이라, 점수를 LLM이 계산하면 같은 리뷰를 두 번 돌렸을 때
 * 다른 점수가 나올 수 있다 — 여기서 감점표를 직접 곱해 그 재현성을 회복한다.
 *
 * 사용법:
 *   node scripts/gen-score.js <report.json> [--adapter <.review-kit.json>] [--write]
 *
 *   --write   계산 결과를 report.json의 score/grade/cutline/deductions에 덮어쓴다.
 *             (없으면 검산만 하고 파일은 건드리지 않는다)
 *
 * 종료 코드:
 *   0  계산 완료 — report.json의 기존 값과 일치하거나, 값이 아직 없거나, --write로 갱신함
 *   1  사용법·파일·스키마 오류
 *   2  게이트 위반 — 진행하면 안 되는 상태. 두 경우다:
 *      (a) report.json에 적힌 점수/등급이 계산 결과와 다르다
 *      (b) summary.critical_open > 0 — Critical이 열려 있으면 점수 자체가 무효다
 *
 * 입력에서 읽는 것: repo_type · warning_results[] · summary.critical_open
 * 어댑터에서 읽는 것: tracks[repo_type].{cutlinePass,cutlineCaution,deductions,weightSecurityRegression}
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ── 인자 파싱 ────────────────────────────────────────────────
const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const adapterFlagIndex = argv.indexOf('--adapter');
// --adapter 의 값은 **위치로** 제외한다. 예전엔 "`.review-kit.json` 으로 끝나는 인자"를 걸러냈는데,
// 어댑터 파일명이 다르면(kit.json 등) 그 값이 positional[0] 이 되어 report 로 읽혔다.
// report.json 은 열리지도 않은 채 warning_results 0건 → 100점 PASS · exit 0.
// 유일한 기계적 게이트가 인자 순서 하나로 통과 도장을 찍는 구멍이었다(2026-08-07 실측).
const adapterValueIndex = adapterFlagIndex >= 0 ? adapterFlagIndex + 1 : -1;
const positional = argv.filter((a, i) => !a.startsWith('--') && i !== adapterValueIndex);
const WRITE = flags.has('--write');

if (!positional[0]) {
  console.error('Usage: node scripts/gen-score.js <report.json> [--adapter <.review-kit.json>] [--write]');
  process.exit(1);
}

const reportPath = path.resolve(positional[0]);
const adapterPath = adapterFlagIndex >= 0 && argv[adapterFlagIndex + 1]
  ? path.resolve(argv[adapterFlagIndex + 1])
  : findAdapter(path.dirname(reportPath));

function findAdapter(startDir) {
  // report.json 위치에서 위로 올라가며 .review-kit.json 을 찾되, **프로젝트 경계에서 멈춘다.**
  // 경계 검사가 없으면 홈/임시 디렉터리에 남은 옛 어댑터를 집어 엉뚱한 트랙의 컷라인으로
  // 채점하고도 조용히 성공한다(2026-08-07 실측: %TEMP%\.review-kit.json 을 집었다).
  let dir = startDir;
  for (let i = 0; i < 8; i += 1) {
    const candidate = path.join(dir, '.review-kit.json');
    if (fs.existsSync(candidate)) return candidate;
    // 이 디렉터리가 저장소 루트면 여기까지다 — 더 올라가면 다른 프로젝트의 어댑터다.
    if (fs.existsSync(path.join(dir, '.git'))) return null;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function readJson(p, label) {
  if (!p || !fs.existsSync(p)) {
    console.error(`❌ ${label} 없음: ${p || '(경로 미지정)'}`);
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    console.error(`❌ ${label} JSON 파싱 실패: ${e.message}`);
    process.exit(1);
  }
}

const report = readJson(reportPath, 'report.json');
const adapter = readJson(adapterPath, '.review-kit.json 어댑터');

// ── 트랙 해석 ────────────────────────────────────────────────
const tracks = adapter.tracks || {};
const repoType = report.repo_type || Object.keys(tracks).filter((k) => k !== '_' && k !== 'detect')[0];
const track = tracks[repoType];

if (!track) {
  console.error(`❌ 어댑터 tracks 에 '${repoType}' 가 없다. 사용 가능: ${Object.keys(tracks).filter((k) => k !== '_' && k !== 'detect').join(', ') || '(없음)'}`);
  process.exit(1);
}

const cutlinePass = track.cutlinePass ?? 80;
const cutlineCaution = track.cutlineCaution ?? 70;
const table = track.deductions || {};
const secRegWeight = track.weightSecurityRegression ?? 1;
const hasSecRegRows = Object.keys(table).some((k) => /SecReg$/.test(k));

// 가중치를 곱할지는 **실제로 매칭된 감점행 기준**으로 정한다.
// `warningHighSecReg` 처럼 SecReg 전용 행에 걸리면 그 값에 가중치가 이미 반영돼 있으므로
// 또 곱하면 이중 적용이다. 하지만 그 행이 없어 generic `warningHigh` 로 폴백했다면
// 폴백 행에는 가중치가 반영돼 있지 않으므로 곱해야 한다.
//
// 예전엔 이 판정이 **표 단위**였다 — SecReg 행이 하나라도 있으면 그 표의 모든 SecReg 감점이
// 가중치를 잃었다. example-adapter 의 BE 트랙에는 `warningLowSecReg` 가 없어서, Low Security
// 지적이 전부 가중치 없이 계산됐다(2026-08-07 실측: 20건이면 40점 vs 60점 — 등급이 갈린다).
function weightFor(matchedKey, perspective) {
  if (!SEC_REG.has(perspective)) return 1;
  return /SecReg$/.test(matchedKey || '') ? 1 : secRegWeight;
}

const SEC_REG = new Set(['Security', 'Regression']);
// report.json 은 snake_case(`mr_comment`), 어댑터 감점표는 camelCase(`mrComment`)를 쓴다.
// 양쪽 표기를 모두 받는다 — 어느 쪽으로 써도 계산이 조용히 0점이 되지 않게.
const RESULT_KEYS = {
  fix: ['fix'],
  mr_comment: ['mr_comment', 'mrComment'],
  mrComment: ['mr_comment', 'mrComment'],
  accept: ['accept'],
};
const RESULTS = new Set(Object.keys(RESULT_KEYS));

function lookupPoints(row, result) {
  for (const k of RESULT_KEYS[result] || [result]) {
    if (typeof row[k] === 'number') return row[k];
  }
  return null;
}

// ── 감점표 키 해석 ────────────────────────────────────────────
// 1) warning{Impact}{SecReg|Quality}  예: warningHighSecReg  (BE 트랙처럼 관점을 나눈 표)
// 2) warning{Impact}                  예: warningHigh        (FE 트랙처럼 뭉뚱그린 표)
function resolveRow(impact, perspective) {
  const imp = String(impact || 'Low');
  const category = SEC_REG.has(perspective) ? 'SecReg' : 'Quality';
  const keys = [`warning${imp}${category}`, `warning${imp}`];
  for (const k of keys) if (table[k]) return { key: k, row: table[k] };
  return { key: null, row: null };
}

// ── 계산 ─────────────────────────────────────────────────────
const warnings = Array.isArray(report.warning_results) ? report.warning_results : [];
const buckets = new Map();   // "perspective|result" → { perspective, result, count, points }
const problems = [];
let total = 0;

warnings.forEach((w, i) => {
  const at = `warning_results[${i}]${w.loc ? ` (${w.loc})` : ''}`;
  if (!RESULTS.has(w.result)) {
    problems.push(`${at}: result 가 fix|mr_comment|accept 가 아님 → '${w.result}'`);
    return;
  }
  const { key, row } = resolveRow(w.impact, w.perspective);
  if (!row) {
    problems.push(`${at}: 감점표에 impact='${w.impact}' 에 해당하는 행이 없음 (0점 처리)`);
    return;
  }
  const base = lookupPoints(row, w.result);
  if (base === null) {
    problems.push(`${at}: 감점표 ${key} 에 '${w.result}' 항목이 없음 (0점 처리)`);
    return;
  }
  const weighted = base * weightFor(key, w.perspective);
  // Math.round 는 음수 .5 를 0 쪽으로 올린다(-7.5 → -7). 가중치 1.5 를 곱하면 .5 가 흔해서
  // 감점이 늘 1점씩 덜 되는 방향으로만 치우친다. 절대값으로 반올림해 0에서 멀어지게 한다.
  const points = Math.sign(weighted) * Math.round(Math.abs(weighted));
  total += points;

  const bk = `${w.perspective}|${w.result}`;
  const b = buckets.get(bk) || { perspective: w.perspective, result: w.result, count: 0, points: 0 };
  b.count += 1;
  b.points += points;
  buckets.set(bk, b);
});

const score = 100 + total;   // 감점은 음수로 저장돼 있다
const grade = score >= cutlinePass ? 'PASS' : score >= cutlineCaution ? 'CAUTION' : 'BLOCKED';
const deductions = [...buckets.values()].sort((a, b) => a.points - b.points);

// ── 출력 ─────────────────────────────────────────────────────
console.log(`gen-score — ${path.basename(reportPath)}  (track: ${repoType}, 어댑터: ${path.relative(process.cwd(), adapterPath)})`);
if (secRegWeight !== 1) {
  console.log(hasSecRegRows
    ? `  · Security/Regression 가중치 ${secRegWeight} — SecReg 전용 행에 걸린 건은 미적용(이미 반영됨), generic 행으로 폴백한 건에만 적용`
    : `  · Security/Regression 감점에 가중치 ${secRegWeight} 적용`);
}
console.log('');
deductions.forEach((d) => {
  console.log(`  ${String(d.perspective).padEnd(12)} ${String(d.result).padEnd(11)} ${String(d.count).padStart(2)}건   ${String(d.points).padStart(5)}점`);
});
if (!deductions.length) console.log('  감점 없음');
console.log(`  ${''.padEnd(24)} ${'합계'.padStart(3)}   ${String(total).padStart(5)}점`);
console.log('');
console.log(`  점수 ${score}/100  [${grade}]   컷라인 PASS ${cutlinePass} / CAUTION ${cutlineCaution}`);

const criticalOpen = report.summary && typeof report.summary.critical_open === 'number' ? report.summary.critical_open : 0;

if (problems.length) {
  console.log('\n⚠️  스키마 경고:');
  problems.forEach((p) => console.log(`   · ${p}`));
}

// ── 검산 / 기록 ──────────────────────────────────────────────
// score 와 grade 를 **각각** 검산한다. 예전엔 score 가 숫자일 때만 검산해서,
// `grade: "PASS"` 만 있고 score 가 없는 report.json 은 등급이 계산과 정반대여도 exit 0 이었다
// (LLM 이 점수 없이 등급만 적는 것이 스키마상 가능하다).
const hadScore = typeof report.score === 'number';
const hadGrade = typeof report.grade === 'string' && report.grade.length > 0;
const mismatch = (hadScore && report.score !== score) || (hadGrade && report.grade !== grade);

if (WRITE) {
  report.score = score;
  report.grade = grade;
  report.cutline = cutlinePass;
  report.deductions = deductions;
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  console.log(`\n✅ report.json 갱신 — score/grade/cutline/deductions`);
  // 기록은 했지만 Critical 이 열려 있으면 통과 신호를 주면 안 된다 — 아래 게이트로 떨어진다.
} else if (mismatch) {
  console.error(`\n❌ 불일치 — report.json: ${hadScore ? report.score : '(없음)'}/${hadGrade ? report.grade : '(없음)'}  vs  계산: ${score}/${grade}`);
  console.error('   감점표 적용이 어긋났다. --write 로 계산값을 반영하거나, warning_results 를 고쳐라.');
  process.exit(2);
} else {
  console.log(hadScore || hadGrade
    ? '\n✅ report.json 의 점수·등급과 일치'
    : '\n✅ 계산 완료 (report.json 에 기존 점수 없음 — --write 로 기록 가능)');
}

// Critical 미해결은 점수와 무관하게 게이트를 막는다.
// "점수는 Critical = 0 일 때만 유효하다"고 스스로 말하면서 exit 0 을 주면, 그 문장을 읽지 않는
// 자동화(파이프라인·CI)에는 통과 도장과 구별되지 않는다.
if (criticalOpen > 0) {
  console.error(`\n⛔ Critical ${criticalOpen}건이 미해결이다 — 점수는 Critical = 0 일 때만 유효하다.`);
  console.error('   Critical 루프를 끝낸 뒤 다시 돌려라.');
  process.exit(2);
}
