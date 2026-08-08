#!/usr/bin/env node
/**
 * sync-styles.js — 정적 HTML 의 공통 스타일 블록을 CSS SSOT 와 동기화한다.
 *
 * 생성기(gen-*.js)는 빌드타임에 SSOT 를 readFileSync 하므로 항상 최신이다.
 * 반면 저장소에 체크인된 정적 HTML(템플릿·리포트·문서 번들)은 그 자체로 열리는
 * 파일이라 CSS 를 물리적으로 품고 있어야 한다. 이 스크립트가 그 블록을 갱신하고,
 * --check 로 드리프트를 exit 1 로 잡는다.
 *   (첫 번째 기계적 게이트는 gen-score.js 의 exit 2, 이건 두 번째다.)
 *
 * 대상은 하드코딩하지 않는다. 파일이 아래 마커를 품으면 스스로 대상이 된다:
 *
 *   <style>
 *     /* @sst:begin *\/
 *     ... 여기는 이 스크립트가 덮어쓴다. 직접 고치지 마라 ...
 *     /* @sst:end *\/
 *   </style>
 *
 * 사용법:
 *   node scripts/sync-styles.js                 # 마커 사이를 SSOT 로 덮어쓴다
 *   node scripts/sync-styles.js --check         # 검사만. 드리프트 있으면 exit 1
 *   node scripts/sync-styles.js a.html b.html   # 대상을 명시(있어야 하고 마커도 있어야 함)
 *   node scripts/sync-styles.js --root <dir>    # 탐색 기준 디렉터리 (기본: 저장소 루트)
 *   node scripts/sync-styles.js --ssot <file>   # CSS SSOT 경로 (기본: scripts/assets/report.css)
 *
 * exit: 0 = 일치/갱신 완료, 1 = 드리프트 또는 대상 처리 불가.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const BEGIN = '/* @sst:begin';
const END = '/* @sst:end */';

// 탐색에서 통째로 건너뛸 디렉터리 — 저장소마다 있을 법한 것만.
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out',
  'coverage', 'vendor', '.next', '.cache', '.venv', 'venv', '__pycache__',
]);
const SCAN_EXT = new Set(['.html', '.htm', '.css']);

// ── 인자 파싱 ────────────────────────────────────────────────
const argv = process.argv.slice(2);
const REPO_ROOT = path.resolve(__dirname, '..');

let checkOnly = false;
let root = REPO_ROOT;
let ssot = path.join(__dirname, 'assets', 'report.css');
const explicit = [];

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--check') checkOnly = true;
  else if (a === '--root') root = path.resolve(argv[++i] || '.');
  else if (a === '--ssot') ssot = path.resolve(argv[++i] || '');
  else if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
  else if (a.startsWith('-')) { console.error(`❌ 알 수 없는 옵션: ${a}`); process.exit(1); }
  else explicit.push(path.resolve(a));
}

function printHelp() {
  console.log([
    'sync-styles.js — 정적 HTML 의 @sst 블록을 CSS SSOT 와 동기화',
    '',
    '  node scripts/sync-styles.js [--check] [--root <dir>] [--ssot <file>] [파일...]',
    '',
    '  --check   쓰지 않고 검사만. 드리프트가 있으면 exit 1',
    '  --root    마커 탐색 기준 디렉터리 (기본: 저장소 루트)',
    '  --ssot    CSS 원본 (기본: scripts/assets/report.css)',
  ].join('\n'));
}

// ── SSOT 로드 ────────────────────────────────────────────────
if (!fs.existsSync(ssot)) {
  console.error(`❌ SSOT 없음: ${rel(ssot)}`);
  process.exit(1);
}
const css = fs.readFileSync(ssot, 'utf8').trimEnd();

function rel(p) {
  const r = path.relative(root, p);
  if (r === '') return '.';
  return !r.startsWith('..') ? r.split(path.sep).join('/') : p;
}

// ── 대상 수집 ────────────────────────────────────────────────
// 명시 인자가 있으면 그것만. 없으면 root 를 훑어 마커를 가진 파일을 찾는다.
function discover(dir, found = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return found; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) || e.name.startsWith('.')) continue;
      discover(full, found);
    } else if (e.isFile() && SCAN_EXT.has(path.extname(e.name).toLowerCase())) {
      if (full === ssot) continue;
      let src;
      try { src = fs.readFileSync(full, 'utf8'); } catch { continue; }
      if (src.includes(BEGIN)) found.push(full);
    }
  }
  return found;
}

const targets = explicit.length ? explicit : discover(root).sort();

if (!targets.length) {
  // 정적 템플릿이 하나도 없는 저장소는 정상이다 — 생성기는 SSOT 를 직접 읽는다.
  console.log(`ℹ️  @sst 마커를 가진 파일 없음 (${rel(root)}). 동기화할 대상이 없다.`);
  process.exit(0);
}

if (!checkOnly) {
  console.error(`⚠️  ${targets.length}개 파일의 @sst 블록을 ${rel(ssot)} 내용으로 덮어쓴다:`);
  for (const t of targets) console.error(`     - ${rel(t)}`);
}

// ── 동기화 / 검사 ────────────────────────────────────────────
let drifted = 0, synced = 0, broken = 0;

for (const file of targets) {
  if (!fs.existsSync(file)) {
    console.error(`❌ 대상 없음: ${rel(file)}`);
    broken++;
    continue;
  }

  const src = fs.readFileSync(file, 'utf8');
  const bi = src.indexOf(BEGIN);
  const ei = src.indexOf(END);

  if (bi === -1 || ei === -1 || ei < bi) {
    console.error(`❌ 마커 없음: ${rel(file)}`);
    console.error(`   "${BEGIN} */" 와 "${END}" 를 <style> 안에 추가할 것.`);
    broken++;
    continue;
  }

  // 마커 헤더 줄의 끝 = begin 코멘트를 닫는 */
  const headerEnd = src.indexOf('*/', bi) + 2;
  const current = src.slice(headerEnd, ei).trim();

  if (current === css) {
    console.log(`✓ 최신  ${rel(file)}`);
    continue;
  }

  if (checkOnly) {
    console.error(`✗ 드리프트  ${rel(file)}  (node scripts/sync-styles.js 로 갱신)`);
    drifted++;
    continue;
  }

  fs.writeFileSync(file, src.slice(0, headerEnd) + '\n' + css + '\n' + src.slice(ei));
  console.log(`↻ 갱신  ${rel(file)}`);
  synced++;
}

if (broken) {
  console.error(`\n❌ ${broken}개 대상 처리 불가`);
  process.exit(1);
}
if (drifted) {
  console.error(`\n❌ ${drifted}개 파일이 SSOT 와 다르다`);
  process.exit(1);
}
console.log(checkOnly
  ? `\n✅ ${targets.length}개 파일 모두 SSOT 와 일치`
  : `\n✅ 동기화 완료 (갱신 ${synced}개 / 대상 ${targets.length}개)`);
