#!/usr/bin/env node
/**
 * px.js — 프로바이더 계약(kit/contract/provider-contract.md)의 유일한 진입점.
 *
 * 스킬은 "px issue get 123" 한 문장만 알고, 그걸 GitLab이 하는지 GitHub이 하는지는
 * .pipeline.json 이 정한다. 그래서 이 파일은 인자 파싱·응답 봉투·종료코드만 담당하고
 * API 호출은 한 줄도 하지 않는다.
 *
 * 사용법:
 *   node scripts/px.js <group> <verb> [args...] [--flag value] [--json]
 *   node scripts/px.js doctor
 *
 *   --json   봉투를 한 줄로 압축해서 출력한다(기본은 2칸 들여쓴 JSON).
 *
 * 출력 규약(계약 §1):
 *   stdout — 기계 판독용 JSON 봉투 한 덩어리만
 *   stderr — 사람이 읽을 진행/경고 메시지
 *
 * 종료 코드:
 *   0  성공
 *   1  사용법·설정·네트워크 오류 (재시도 가능)
 *   2  계약/게이트 위반 — 스킬은 멈추고 사용자에게 보고한다
 *   3  이 프로바이더가 해당 동사를 지원하지 않음 — 스킬은 폴백한다
 */

'use strict';

const provider = require('./lib/provider');
const { PxError } = provider;

// ── 인자 파싱 ────────────────────────────────────────────────
// --flag value / --flag=value / --flag(불리언). 키는 camelCase로 정규화한다
// (--add-labels → addLabels) — 계약의 플래그 이름은 kebab, JS 쪽은 camel이라
// 변환 지점을 여기 하나로 모아둔다.
function parseArgv(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--') { positional.push(...argv.slice(i + 1)); break; }
    if (!a.startsWith('--')) { positional.push(a); continue; }

    const eq = a.indexOf('=');
    let key;
    let value;
    if (eq > 2) {
      key = a.slice(2, eq);
      value = a.slice(eq + 1);
    } else {
      key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        value = true;
      } else {
        value = next;
        i += 1;
      }
    }
    flags[key.replace(/-([a-z0-9])/gi, (_, c) => c.toUpperCase())] = value;
  }
  return { positional, flags };
}

function emit(envelope, compact) {
  process.stdout.write(`${JSON.stringify(envelope, null, compact ? 0 : 2)}\n`);
}

const USAGE = `사용법: node scripts/px.js <group> <verb> [args...] [--flag value] [--json]

  issue   get <ref> | create --title | update <ref> | close <ref> --yes | list
  pr      create --source --target --title | get <ref>|--source | list | merge <ref> --yes
  branch  resolve-target | new <name> --base | sync | drift-check
  ws      create <slug> --issue | verify <slug> | stage <slug> <STAGE> | resolve | list | close <slug> --yes
  notify  send --event --text
  run     test | build | lint        env  up | down
  tab     open <label> | done <label> | kill <label>
  doctor

무엇이 이 동사를 수행하는지는 .pipeline.json 의 providers.* 가 정한다.
계약 전문: kit/contract/provider-contract.md`;

// ── doctor ───────────────────────────────────────────────────
async function runDoctor(compact) {
  const { rows, configPath } = await provider.diagnose(process.cwd());
  const mark = { ok: '✅', fail: '❌', missing: '➖' };

  process.stderr.write(`px doctor — ${configPath || provider.CONFIG_NAME + ' 없음'}\n\n`);
  rows.forEach((r) => {
    const left = `${r.kind}/${r.provider}`;
    process.stderr.write(`  ${mark[r.status] || '?'} ${left.padEnd(20)} ${String(r.name).padEnd(18)} ${r.detail || ''}\n`);
  });

  const failed = rows.filter((r) => r.status === 'fail');
  const missing = rows.filter((r) => r.status === 'missing');
  process.stderr.write('\n');
  if (missing.length) {
    // 미설치는 실패가 아니다 — 계약은 넷으로 나뉘어 구현되는 중이고,
    // tracker만 있어도 이슈 동사는 전부 돈다.
    process.stderr.write(`  ➖ 미설치 ${missing.length}건: ${missing.map((r) => `${r.kind}/${r.provider}`).join(', ')}\n`);
  }
  process.stderr.write(failed.length ? `  ❌ 실패 ${failed.length}건 — 위 항목을 고치기 전에는 스킬을 신뢰할 수 없다.\n` : '  ✅ 점검 통과\n');

  emit({
    ok: failed.length === 0,
    verb: 'doctor',
    provider: null,
    data: { configPath, checks: rows, failed: failed.length, missing: missing.length },
  }, compact);
  process.exit(failed.length ? 1 : 0);
}

// ── 프로바이더 에러 흡수 ─────────────────────────────────────
// 프로바이더 모듈은 PxError 를 import 하지 않는다(계약 §4 — 모듈은 서로를, 그리고
// 진입점을 몰라야 한다). 그래서 평범한 Error 에 code/exitCode/data 를 얹어 던진다.
// 여기서 그걸 그대로 받아들인다. 이 흡수가 없으면 프로바이더가 붙인 종료코드와
// 구조화 정보가 통째로 사라지고 전부 exit 1 'internal' 로 뭉개진다(2026-08-07 실측 —
// ws.close 가 --yes 없이도 exit 0 으로 통과했다).
function adoptError(e) {
  if (!e || typeof e !== 'object') return new PxError('internal', String(e));
  const code = typeof e.code === 'string' ? e.code : 'internal';
  // 메시지는 e.message 를 쓴다. e.stack 의 첫 줄은 "Error: " 접두사가 붙고
  // 여러 줄 메시지가 첫 줄에서 잘린다(삭제 대상 목록이 사라졌던 원인).
  const message = e.message || String(e);
  const px = new PxError(code, message);
  if (typeof e.exitCode === 'number') px.exitCode = e.exitCode;
  const extra = e.data !== undefined ? e.data : e.extra;
  if (extra !== undefined) px.extra = extra;
  if (typeof e.provider === 'string') px.provider = e.provider;
  if (e.stack) px.sourceStack = e.stack;
  return px;
}

// ── 본체 ─────────────────────────────────────────────────────
async function main() {
  const { positional, flags } = parseArgv(process.argv.slice(2));
  const compact = Boolean(flags.json);
  const group = positional[0];

  if (!group || group === 'help' || flags.help) {
    process.stderr.write(`${USAGE}\n`);
    process.exit(group ? 0 : 1);
  }

  if (group === 'doctor') {
    await runDoctor(compact);
    return;
  }

  const verb = positional[1];
  if (!verb) {
    process.stderr.write(`❌ '${group}' 뒤에 동사가 없다.\n\n${USAGE}\n`);
    emit({ ok: false, verb: `${group}.?`, provider: null, error: { code: 'usage', message: `'${group}' 뒤에 동사가 없다.` } }, compact);
    process.exit(1);
  }

  const verbKey = `${group}.${verb}`;
  let call = null;
  try {
    call = provider.resolveCall(group, verb, process.cwd());
    const data = await call.handler(call.ctx, positional.slice(2), flags);
    emit({ ok: true, verb: verbKey, provider: call.provider, data: data === undefined ? null : data }, compact);
    process.exit(0);
  } catch (e) {
    const px = e instanceof PxError ? e : adoptError(e);
    const error = { code: px.code, message: px.message };
    if (px.extra) error.data = px.extra;
    emit({ ok: false, verb: verbKey, provider: (call && call.provider) || px.provider || null, error }, compact);

    const icon = px.exitCode === 2 ? '⛔' : px.exitCode === 3 ? '➖' : '❌';
    process.stderr.write(`${icon} ${px.message}\n`);
    if (px.exitCode === 2 && px.extra) {
      process.stderr.write(`   대상: ${JSON.stringify(px.extra)}\n   실행하려면 --yes 를 붙여라.\n`);
    }
    // 스택은 '정말 예상 못 한 오류'일 때만 보여준다. 계약이 정의한 거부(exit 2/3)는
    // 정상 흐름이라 스택을 찍으면 실패처럼 보인다.
    if (px.code === 'internal' && px.exitCode === 1) {
      const stack = px.sourceStack || (e && e.stack);
      if (stack) process.stderr.write(`${stack}\n`);
    }
    process.exit(px.exitCode);
  }
}

main();
