#!/usr/bin/env node
/**
 * kit-manifest.js — 설치 매니페스트 생성 + 드리프트 검사
 *
 * 이 킷은 "복사해서 이식한다"가 전제다. 그래서 호스트 저장소는 시간이 지나면
 * 반드시 킷보다 뒤처지고, 그 사실을 아는 방법이 지금까지 사람의 기억밖에 없었다.
 * 이 스크립트가 그걸 기계 신호로 바꾼다.
 *   (첫 번째 기계적 게이트는 gen-score.js 의 exit 2, 두 번째는 sync-styles.js --check
 *    의 exit 1, 이건 세 번째다.)
 *
 * 소유 파일의 SSOT 는 kit/manifest.json 이다 — 이 스크립트에 경로를 하드코딩하지 않는다.
 *
 * 사용법:
 *   node scripts/kit-manifest.js build [--root <킷저장소>] [--out <파일>]
 *       킷 저장소에서 실행. 소유 파일의 해시 목록을 .review-kit-manifest.json 으로 낸다.
 *       이 파일을 설치물과 함께 호스트에 복사한다.
 *
 *   node scripts/kit-manifest.js check [--root <호스트>] [--manifest <파일>] [--require g1,g2]
 *       호스트 저장소에서 실행. 매니페스트와 실제 파일을 대조한다.
 *
 *   node scripts/kit-manifest.js check --against <킷저장소> [--root <호스트>]
 *       매니페스트 없이, 살아있는 킷 체크아웃과 직접 대조한다.
 *
 *   node scripts/kit-manifest.js list [--root <킷저장소>]
 *       그룹별 소유 파일 목록만 출력한다(해시 계산 없음).
 *
 * 공통 옵션: --json (기계 판독용 출력), --spec <kit/manifest.json 경로>
 *
 * exit: 0 = 이상 없음, 2 = 드리프트, 1 = 사용법/입출력 오류.
 *
 * 부분 설치는 드리프트가 아니다. 그룹이 통째로 비어 있으면 "미설치"로 보고만 하고,
 * 일부만 있으면 그때 드리프트다 — 검증 3단계만 설치한 프로젝트에서도 check 를 쓸 수 있어야 하기 때문이다.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_MANIFEST = '.review-kit-manifest.json';
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out',
  'coverage', 'vendor', '.next', '.cache', '.venv', 'venv', '__pycache__',
]);

// ── 인자 ──────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const cmd = (argv[0] && !argv[0].startsWith('-')) ? argv.shift() : 'check';

let root = process.cwd();
let specPath = null;
let manifestPath = null;
let outPath = null;
let against = null;
let requireGroups = [];
let asJson = false;

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--root') root = path.resolve(argv[++i] || '.');
  else if (a === '--spec') specPath = path.resolve(argv[++i] || '');
  else if (a === '--manifest') manifestPath = path.resolve(argv[++i] || '');
  else if (a === '--out') outPath = path.resolve(argv[++i] || '');
  else if (a === '--against') against = path.resolve(argv[++i] || '');
  else if (a === '--require') requireGroups = String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
  else if (a === '--json') asJson = true;
  else if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
  else { fail(`알 수 없는 인자: ${a}`); }
}

function printHelp() {
  console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0].replace(/^#![^\n]*\n/, ''));
}

function fail(msg) {
  console.error(`❌ ${msg}`);
  process.exit(1);
}

// ── glob (의존성 0, 이 스크립트가 쓰는 형태만) ──────────────────
// 지원: `*`(슬래시 제외 임의) · `**`(슬래시 포함 임의) · 그 외 리터럴.
function globToRegExp(pattern) {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        // `**/` 는 "0개 이상의 디렉터리"라서 슬래시까지 같이 삼킨다.
        if (pattern[i + 2] === '/') { re += '(?:.*/)?'; i += 2; }
        else { re += '.*'; i += 1; }
      } else {
        re += '[^/]*';
      }
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

function walk(dir, base, acc) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return acc; }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(path.join(dir, e.name), base, acc);
    } else if (e.isFile()) {
      acc.push(path.relative(base, path.join(dir, e.name)).split(path.sep).join('/'));
    }
  }
  return acc;
}

let _treeCache = new Map();
function treeOf(base) {
  if (!_treeCache.has(base)) _treeCache.set(base, walk(base, base, []));
  return _treeCache.get(base);
}

function expand(base, patterns) {
  const tree = treeOf(base);
  const hit = new Set();
  for (const p of patterns) {
    if (!/[*?]/.test(p)) {
      // 리터럴 경로 — 트리에 없어도 패턴 자체를 후보로 남긴다(누락을 보고해야 하므로).
      hit.add(p);
      continue;
    }
    const re = globToRegExp(p);
    for (const f of tree) if (re.test(f)) hit.add(f);
  }
  return [...hit].sort();
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function loadSpec() {
  const p = specPath || path.join(against || (cmd === 'check' ? REPO_ROOT : root), 'kit', 'manifest.json');
  const fallback = path.join(REPO_ROOT, 'kit', 'manifest.json');
  const use = fs.existsSync(p) ? p : fallback;
  if (!fs.existsSync(use)) fail(`매니페스트 명세를 찾지 못했다: ${p}`);
  try {
    return { spec: JSON.parse(stripBom(fs.readFileSync(use, 'utf8'))), path: use };
  } catch (e) {
    return fail(`매니페스트 명세 파싱 실패 (${use}): ${e.message}`);
  }
}

function stripBom(s) { return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s; }

function gitCommit(dir) {
  try {
    const r = require('child_process').spawnSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
    return (r.status === 0 && r.stdout) ? r.stdout.trim() : null;
  } catch (_) { return null; }
}

// 그룹이 설치 위치를 갈아끼우는 경우(스킬 → .claude/skills/)의 경로 변환.
function applyPrefix(prefix, rel) {
  if (!prefix || !prefix.from || !prefix.to) return rel;
  return rel.startsWith(prefix.from) ? prefix.to + rel.slice(prefix.from.length) : rel;
}

// ── build ────────────────────────────────────────────────────
// 킷 저장소의 소유 파일을 훑어 해시 목록을 만든다.
function buildManifest(base) {
  const { spec, path: sp } = loadSpec();
  const groups = {};
  const empty = [];

  // `_` 로 시작하는 키는 명세 안의 주석이다 — 그룹으로 세지 않는다.
  for (const [name, g] of Object.entries(spec.groups || {})) {
    if (name.startsWith('_') || typeof g !== 'object' || g === null) continue;
    const files = [];
    const sources = expand(base, g.include || []).concat(g.includeRenamed || []);
    for (const rel of sources) {
      const abs = path.join(base, rel);
      if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
      const installAs = (g.renames && g.renames[rel]) || applyPrefix(g.installPrefix, rel);
      files.push({ path: rel, installPath: installAs, sha256: sha256(abs), bytes: fs.statSync(abs).size });
    }
    if (!files.length) empty.push(name);
    groups[name] = {
      description: g.description || '',
      requires: g.requires || [],
      files: files.sort((a, b) => a.path.localeCompare(b.path)),
    };
  }

  return {
    manifest: {
      schema: 1,
      generatedAt: new Date().toISOString(),
      source: { root: path.basename(base), commit: gitCommit(base), spec: path.relative(base, sp).split(path.sep).join('/') },
      adapters: (spec.adapters && spec.adapters.files) || [],
      groups,
    },
    empty,
  };
}

// ── check ────────────────────────────────────────────────────
function checkAgainst(manifest, hostRoot) {
  const report = { drift: false, groups: [], adapters: [] };

  for (const [name, g] of Object.entries(manifest.groups || {})) {
    if (!g.files.length) continue;                      // 킷 쪽에 아직 없는 그룹 — 검사 대상 아님
    const present = [];
    const missing = [];
    const modified = [];

    for (const f of g.files) {
      const installed = f.installPath || f.path;
      let abs = path.join(hostRoot, installed);
      // 이름을 바꿔 설치하는 파일(AGENTS.md → AGENTS-review-kit.md)은 킷 저장소 자기검사에서는
      // 원본 이름으로만 존재한다. 원본이 해시까지 같으면 설치된 것으로 친다 — 아니면 킷이
      // 자기 자신을 검사할 때마다 항상 드리프트가 뜬다.
      if (!fs.existsSync(abs) && installed !== f.path && fs.existsSync(path.join(hostRoot, f.path))) {
        abs = path.join(hostRoot, f.path);
      }
      if (!fs.existsSync(abs)) { missing.push(installed); continue; }
      present.push(installed);
      if (sha256(abs) !== f.sha256) modified.push(installed);
    }

    let status;
    if (!present.length) status = requireGroups.includes(name) ? 'required-missing' : 'not-installed';
    else if (missing.length || modified.length) status = 'drift';
    else status = 'ok';

    if (status === 'drift' || status === 'required-missing') report.drift = true;
    report.groups.push({ name, status, total: g.files.length, present: present.length, missing, modified, requires: g.requires || [] });
  }

  // 의존 그룹 검사 — 설치된 그룹의 requires 가 미설치면 첫 호출에서 죽는다. 드리프트로 친다.
  const installed = new Set(report.groups.filter((g) => g.status !== 'not-installed').map((g) => g.name));
  for (const g of report.groups) {
    if (g.status === 'not-installed') continue;
    g.unmetRequires = (g.requires || []).filter((r) => !installed.has(r));
    if (g.unmetRequires.length) { g.status = 'unmet-requires'; report.drift = true; }
  }

  for (const a of manifest.adapters || []) {
    report.adapters.push({ path: a, present: fs.existsSync(path.join(hostRoot, a)) });
  }

  return report;
}

const STATUS_LABEL = {
  ok: '✅ 최신',
  drift: '⚠️  드리프트',
  'not-installed': '·  미설치',
  'required-missing': '❌ 필수인데 미설치',
  'unmet-requires': '❌ 의존 그룹 미설치',
};

function printReport(report, manifest) {
  const src = manifest.source || {};
  console.log(`매니페스트 기준: ${src.root || '?'}${src.commit ? ` @ ${src.commit.slice(0, 7)}` : ''} · 생성 ${manifest.generatedAt || '?'}`);
  console.log('');
  for (const g of report.groups) {
    console.log(`${STATUS_LABEL[g.status] || g.status}  ${g.name.padEnd(14)} ${String(g.present).padStart(3)}/${g.total}`);
    for (const m of g.missing) console.log(`      누락  ${m}`);
    for (const m of g.modified) console.log(`      변경  ${m}`);
    for (const r of g.unmetRequires || []) console.log(`      의존  ${r} 그룹이 없다`);
  }
  const adaptersMissing = report.adapters.filter((a) => !a.present).map((a) => a.path);
  if (report.adapters.length) {
    console.log('');
    console.log(`어댑터: ${report.adapters.filter((a) => a.present).map((a) => a.path).join(' · ') || '없음'}`
      + (adaptersMissing.length ? `   (없음: ${adaptersMissing.join(' · ')})` : ''));
    console.log('  어댑터는 해시 검사 대상이 아니다 — 프로젝트마다 값이 달라야 정상이다.');
  }
  console.log('');
  if (report.drift) {
    console.log('❌ 드리프트가 있다. 킷 쪽 파일로 덮어쓰거나, 호스트가 의도적으로 고친 것이면 그 사실을 기록하고 매니페스트를 다시 만든다.');
  } else {
    console.log('✅ 설치된 그룹은 전부 매니페스트와 일치한다.');
  }
}

// ── main ─────────────────────────────────────────────────────
if (cmd === 'build') {
  const base = path.resolve(root === process.cwd() && !fs.existsSync(path.join(root, 'kit', 'manifest.json')) ? REPO_ROOT : root);
  const { manifest, empty } = buildManifest(base);
  // `--out -` 은 파일을 만들지 않는다 — 다른 스크립트가 파이프로 받아 쓰는 경로.
  const toStdout = outPath && path.basename(outPath) === '-';
  const out = toStdout ? '-' : (outPath || path.join(base, DEFAULT_MANIFEST));
  if (!toStdout) fs.writeFileSync(out, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const total = Object.values(manifest.groups).reduce((n, g) => n + g.files.length, 0);
  if (asJson) { console.log(JSON.stringify(manifest)); }
  else {
    console.log(`✅ kit-manifest build 완료: ${out}`);
    console.log(`   그룹 ${Object.keys(manifest.groups).length}개 · 파일 ${total}개`);
    if (empty.length) console.log(`   ⚠️  파일이 하나도 없는 그룹: ${empty.join(' · ')} (아직 만들지 않았거나 명세의 경로가 틀렸다)`);
  }
  process.exit(0);
}

if (cmd === 'list') {
  const base = fs.existsSync(path.join(root, 'kit', 'manifest.json')) ? root : REPO_ROOT;
  const { spec } = loadSpec();
  // `_` 로 시작하는 키는 명세 안의 주석이다 — 그룹으로 세지 않는다.
  for (const [name, g] of Object.entries(spec.groups || {})) {
    if (name.startsWith('_') || typeof g !== 'object' || g === null) continue;
    const files = expand(base, g.include || []).concat(g.includeRenamed || [])
      .filter((f) => fs.existsSync(path.join(base, f)));
    console.log(`${name}  (${files.length})  — ${g.description || ''}`);
    for (const f of files) console.log(`   ${f}`);
  }
  process.exit(0);
}

if (cmd === 'check') {
  let manifest;
  if (against) {
    manifest = buildManifest(against).manifest;
  } else {
    const mp = manifestPath || path.join(root, DEFAULT_MANIFEST);
    if (!fs.existsSync(mp)) {
      fail(`매니페스트가 없다: ${mp}\n   킷 저장소에서 'node scripts/kit-manifest.js build' 로 만들어 함께 복사하거나,\n   '--against <킷저장소>' 로 살아있는 체크아웃과 직접 대조한다.`);
    }
    try { manifest = JSON.parse(stripBom(fs.readFileSync(mp, 'utf8'))); }
    catch (e) { fail(`매니페스트 파싱 실패 (${mp}): ${e.message}`); }
  }

  const report = checkAgainst(manifest, root);
  if (asJson) console.log(JSON.stringify({ ok: !report.drift, report }, null, 2));
  else printReport(report, manifest);
  process.exit(report.drift ? 2 : 0);
}

fail(`알 수 없는 명령: ${cmd} (build | check | list)`);
