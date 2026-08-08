#!/usr/bin/env node
/**
 * install-kit.js — 킷을 다른 저장소에 설치/갱신한다.
 *
 * 설치 목록의 SSOT 는 kit/manifest.json 하나다. 문서의 cp 나열은 안내일 뿐이고,
 * 실제로 무엇이 복사되는지는 여기서 결정된다 — 문서와 어긋나면 매니페스트가 맞다.
 * (설치 안내를 손으로 관리하던 시절, 새 파일을 만들 때마다 세 군데 cp 목록을
 *  같이 고쳐야 했고 실제로 한두 개씩 빠졌다.)
 *
 * 사용법:
 *   node scripts/install-kit.js <목적지> --profile review        # 검증 3단계만
 *   node scripts/install-kit.js <목적지> --profile full          # 전 주기
 *   node scripts/install-kit.js <목적지> --groups review,codex   # 그룹을 직접 고른다
 *   node scripts/install-kit.js --list                           # 그룹 목록
 *
 * 옵션:
 *   --src <킷루트>   기본: 이 스크립트가 속한 저장소
 *   --dry-run        무엇이 바뀔지만 보여준다 (기본적으로 먼저 이걸 돌린다)
 *   --force          호스트가 고친 킷 파일도 덮어쓴다
 *   --no-adapters    어댑터 예시(.review-kit.json / .pipeline.json)를 넣지 않는다
 *
 * exit: 0 = 완료(또는 dry-run), 1 = 사용법/입출력 오류, 2 = --force 없이는 진행할 수 없는 충돌.
 *
 * 이 스크립트는 **덮어쓰기 전에 반드시 판정한다.** 목적지 파일이 킷 것과 다르면,
 * 이전 매니페스트를 보고 "호스트가 손댄 것"인지 "킷이 앞서간 것"인지 가른다.
 * 호스트가 손댄 파일은 --force 없이는 건드리지 않는다 — 이식된 킷에서 가장 잃기 쉬운 것이
 * 호스트의 국소 수정이다.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const MANIFEST_NAME = '.review-kit-manifest.json';

const PROFILES = {
  review: ['agents', 'review', 'skills-review', 'codex', 'manifest'],
  orchestrated: ['agents', 'review', 'orchestration', 'skills-review', 'skills-pipeline', 'workflows', 'codex', 'manifest'],
  full: ['agents', 'review', 'orchestration', 'contract', 'skills-review', 'skills-pipeline', 'skills-lifecycle',
    'milestone', 'skills-milestone', 'workflows', 'codex', 'hooks', 'worker', 'manifest'],
};

// ── 인자 ──────────────────────────────────────────────────────
const argv = process.argv.slice(2);
let dst = null;
let src = REPO_ROOT;
let profile = null;
let groups = null;
let dryRun = false;
let force = false;
let withAdapters = true;
let listOnly = false;

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--src') src = path.resolve(argv[++i] || '.');
  else if (a === '--profile') profile = String(argv[++i] || '').trim();
  else if (a === '--groups') groups = String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
  else if (a === '--dry-run') dryRun = true;
  else if (a === '--force') force = true;
  else if (a === '--no-adapters') withAdapters = false;
  else if (a === '--list') listOnly = true;
  else if (a === '-h' || a === '--help') { help(); process.exit(0); }
  else if (a.startsWith('-')) fail(`알 수 없는 옵션: ${a}`);
  else dst = path.resolve(a);
}

function fail(msg) { console.error(`❌ ${msg}`); process.exit(1); }
function help() { console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0].replace(/^#![^\n]*\n/, '')); }
function stripBom(s) { return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s; }
function sha256(p) { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); }

// ── 매니페스트 ────────────────────────────────────────────────
function buildManifest(base) {
  const r = cp.spawnSync(process.execPath,
    [path.join(__dirname, 'kit-manifest.js'), 'build', '--root', base, '--out', '-', '--json'],
    { encoding: 'utf8' });
  if (r.status !== 0) fail(`매니페스트 생성 실패:\n${r.stderr || r.stdout}`);
  try { return JSON.parse(r.stdout); }
  catch (e) { return fail(`매니페스트 출력 파싱 실패: ${e.message}`); }
}

function resolveGroups(manifest, wanted) {
  const all = manifest.groups;
  const out = new Set();
  const stack = [...wanted];
  while (stack.length) {
    const g = stack.pop();
    if (out.has(g)) continue;
    if (!all[g]) fail(`없는 그룹: ${g}  (--list 로 목록 확인)`);
    out.add(g);
    for (const r of all[g].requires || []) stack.push(r);   // 의존 그룹은 자동으로 딸려 온다
  }
  return [...out].filter((g) => all[g].files.length);
}

// ── main ─────────────────────────────────────────────────────
const manifest = buildManifest(src);

if (listOnly) {
  console.log('그룹 (의존 그룹은 자동으로 함께 설치된다)\n');
  for (const [name, g] of Object.entries(manifest.groups)) {
    const req = (g.requires || []).length ? `  ← ${g.requires.join(' · ')}` : '';
    console.log(`  ${name.padEnd(18)} ${String(g.files.length).padStart(3)}개${req}`);
    console.log(`  ${' '.repeat(18)} ${g.description}`);
  }
  console.log('\n프로파일');
  for (const [name, gs] of Object.entries(PROFILES)) console.log(`  --profile ${name.padEnd(12)} ${gs.join(' · ')}`);
  process.exit(0);
}

if (!dst) fail('목적지 저장소 경로가 필요하다.  예: node scripts/install-kit.js ../my-project --profile review');
if (!fs.existsSync(dst) || !fs.statSync(dst).isDirectory()) fail(`목적지가 디렉터리가 아니다: ${dst}`);
if (path.resolve(dst) === path.resolve(src)) fail('목적지가 킷 저장소 자신이다. 다른 저장소를 지정한다.');
if (!profile && !groups) fail('--profile (review | orchestrated | full) 또는 --groups 가 필요하다.  --list 로 목록 확인.');
if (profile && !PROFILES[profile]) fail(`없는 프로파일: ${profile}  (${Object.keys(PROFILES).join(' | ')})`);

const selected = resolveGroups(manifest, groups || PROFILES[profile]);

// 이전 설치 기록 — "호스트가 고친 것"과 "킷이 앞서간 것"을 가르는 유일한 근거다.
let prev = null;
const prevPath = path.join(dst, MANIFEST_NAME);
if (fs.existsSync(prevPath)) {
  try { prev = JSON.parse(stripBom(fs.readFileSync(prevPath, 'utf8'))); } catch (_) { prev = null; }
}
const prevHash = new Map();
if (prev) {
  for (const g of Object.values(prev.groups || {})) {
    for (const f of g.files || []) prevHash.set(f.installPath || f.path, f.sha256);
  }
}

const plan = { create: [], update: [], same: [], conflict: [] };

for (const name of selected) {
  for (const f of manifest.groups[name].files) {
    const from = path.join(src, f.path);
    const to = path.join(dst, f.installPath || f.path);
    const item = { group: name, from, to, rel: f.installPath || f.path, sha: f.sha256 };
    if (!fs.existsSync(to)) { plan.create.push(item); continue; }
    const cur = sha256(to);
    if (cur === f.sha256) { plan.same.push(item); continue; }
    // 목적지가 다르다. 이전 매니페스트가 기록한 해시와 같으면 호스트는 손대지 않았다 → 갱신해도 안전.
    if (prevHash.get(item.rel) === cur) plan.update.push(item);
    else plan.conflict.push(item);
  }
}

const adapterPlan = [];
if (withAdapters) {
  for (const a of manifest.adapters || []) {
    // .pipeline.json 은 프로바이더 계약을 설치할 때만 의미가 있다. 계약 없이 깔아두면
    // "설정했으니 될 것"이라는 착각만 남는다.
    if (a === '.pipeline.json' && !selected.includes('contract')) continue;
    const from = path.join(src, 'example-adapter', a);
    const to = path.join(dst, a);
    if (!fs.existsSync(from)) continue;
    // 어댑터는 절대 덮어쓰지 않는다. 프로젝트 값이 들어 있는 유일한 파일이다.
    if (!fs.existsSync(to)) adapterPlan.push({ from, to, rel: a });
  }
}

// ── 출력 ─────────────────────────────────────────────────────
console.log(`킷: ${src}${manifest.source && manifest.source.commit ? ` @ ${manifest.source.commit.slice(0, 7)}` : ''}`);
console.log(`목적지: ${dst}`);
console.log(`그룹: ${selected.join(' · ')}`);
console.log('');
for (const i of plan.create) console.log(`  +  ${i.rel}`);
for (const i of plan.update) console.log(`  ~  ${i.rel}   (킷이 앞서감 — 갱신)`);
for (const i of plan.conflict) console.log(`  !  ${i.rel}   (호스트가 고친 파일 — ${force ? '--force 로 덮어쓴다' : '건너뛴다'})`);
for (const i of adapterPlan) console.log(`  +  ${i.rel}   (어댑터 예시 — 값을 반드시 채운다)`);
console.log('');
console.log(`신규 ${plan.create.length} · 갱신 ${plan.update.length} · 동일 ${plan.same.length} · 충돌 ${plan.conflict.length}`);

if (dryRun) {
  console.log('\n(--dry-run — 아무것도 쓰지 않았다)');
  process.exit(0);
}
if (plan.conflict.length && !force) {
  console.error('\n❌ 호스트가 고친 킷 파일이 있다. 각 파일을 확인한 뒤,');
  console.error('   그 수정을 버려도 되면 --force 로 다시 돌리고, 남겨야 하면 킷 쪽에 역수입한다.');
  process.exit(2);
}

// ── 쓰기 ─────────────────────────────────────────────────────
function copy(i) {
  fs.mkdirSync(path.dirname(i.to), { recursive: true });
  fs.copyFileSync(i.from, i.to);
}
for (const i of plan.create) copy(i);
for (const i of plan.update) copy(i);
if (force) for (const i of plan.conflict) copy(i);
for (const i of adapterPlan) copy(i);

// 설치한 그룹만 담은 매니페스트를 남긴다 — 호스트가 이후 스스로 드리프트를 검사할 근거다.
const installed = { schema: 1, generatedAt: new Date().toISOString(), source: manifest.source, adapters: manifest.adapters, groups: {} };
for (const name of selected) installed.groups[name] = manifest.groups[name];
fs.writeFileSync(path.join(dst, MANIFEST_NAME), `${JSON.stringify(installed, null, 2)}\n`, 'utf8');

console.log(`\n✅ 설치 완료. 기록: ${MANIFEST_NAME}`);
console.log('\n다음 순서:');
console.log('  1. .review-kit.json 을 프로젝트 값으로 채운다 (점수 컷라인 · 산출물 경로 · diffBase · 런타임 함정 목록)');
if (selected.includes('contract')) {
  console.log('  2. .pipeline.json 의 providers 를 고르고 토큰 환경변수를 설정한다');
  console.log('  3. node scripts/px.js doctor        ← 통과 전에는 라이프사이클 스킬을 신뢰하지 않는다');
}
console.log(`  ${selected.includes('contract') ? '4' : '2'}. node scripts/kit-manifest.js check   ← 이후 언제든 킷 대비 드리프트를 확인한다`);
