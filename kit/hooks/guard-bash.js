#!/usr/bin/env node
/**
 * guard-bash.js — 어댑터가 선언한 금지 규칙을 셸 명령 실행 **전에** exit 2 로 막는다.
 *
 * `kit/workflow/guardrails.md` 는 "하지 마라"고 말만 한다. 프롬프트가 그 문장을 놓치면
 * 그대로 실행된다. 그중 **명령 문자열만 보고 판정할 수 있는 것**은 여기서 기계적으로 막는다.
 *
 * 호출 규약(Claude Code PreToolUse:Bash):
 *   stdin 으로 훅 페이로드 JSON 을 받는다. exit 2 = 차단(사유는 stderr), exit 0 = 통과.
 *   페이로드 모양은 버전에 따라 `{command}` 와 `{tool_input:{command}}` 두 가지가 관측된다 —
 *   둘 다 받는다.
 *
 * 규칙의 SSOT 는 저장소 루트 `.review-kit.json` 의 `guards` 절이다. 이 파일에
 * 브랜치 이름·금지 명령을 하드코딩하지 않는다:
 *
 *   "guards": {
 *     "protectedBranches": ["main", "master", "develop"],
 *     "blockForcePush": true,
 *     "blockedCommands": [
 *       { "pattern": "rm\\s+-rf\\s+/", "reason": "루트 삭제" }
 *     ]
 *   }
 *
 * `guards` 절이 없으면 **아무것도 막지 않는다**(exit 0). 훅을 설치했다는 사실만으로
 * 프로젝트가 모르는 규칙이 생기지 않게 하기 위해서다 — 규칙은 어댑터가 명시적으로 켠다.
 *
 * fail-open. 이 훅 자신의 버그(파싱 실패·설정 깨짐)로 사용자의 작업을 막지 않는다.
 * 대신 그 사실을 stderr 에 남긴다 — 조용히 무력화되는 것이 가장 나쁘다.
 */

'use strict';

const fs = require('fs');
const path = require('path');

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch (_) { return ''; }
}

function stripBom(s) { return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s; }

function findAdapter(startDir) {
  let dir = path.resolve(startDir);
  for (;;) {
    const p = path.join(dir, '.review-kit.json');
    if (fs.existsSync(p)) return p;
    const up = path.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

function loadGuards() {
  const p = findAdapter(process.env.CLAUDE_PROJECT_DIR || process.cwd());
  if (!p) return null;
  try {
    return JSON.parse(stripBom(fs.readFileSync(p, 'utf8'))).guards || null;
  } catch (e) {
    console.error(`[guard-bash] .review-kit.json 파싱 실패 — 가드가 꺼진 채로 통과시킨다: ${e.message}`);
    return null;
  }
}

function extractCommand(raw) {
  if (!raw.trim()) return '';
  let d;
  try { d = JSON.parse(stripBom(raw)); } catch (_) { return ''; }
  if (typeof d.command === 'string') return d.command;
  if (d.tool_input && typeof d.tool_input.command === 'string') return d.tool_input.command;
  return '';
}

function block(reason) {
  console.error(`BLOCKED: ${reason}  (.review-kit.json 의 guards 절)`);
  process.exit(2);
}

// ── 판정 ──────────────────────────────────────────────────────
// 대상은 push 계열 명령뿐이다. 명령 문자열에 브랜치 이름이 스쳐 지나가기만 해도 막으면
// (`git log main`, `grep develop`) 가드가 아니라 방해가 된다.
function checkPush(command, guards) {
  // `git push …` · `git -C <path> push …` · `git --no-pager push …` 를 잡는다.
  // 앞에 올 수 있는 것은 옵션(과 그 값)뿐이라, `git commit -m "push"` 같은 건 걸리지 않는다.
  if (!/^\s*git\s+(?:-\S+(?:\s+\S+)?\s+)*push\b/.test(command)) return;

  if (guards.blockForcePush !== false && /(^|\s)(--force(-with-lease)?|-f)(\s|=|$)/.test(command)) {
    block('force push 는 금지되어 있다');
  }

  const protectedBranches = Array.isArray(guards.protectedBranches) ? guards.protectedBranches : [];
  for (const b of protectedBranches) {
    // `origin/main` · `HEAD:main` · `main:main` 같은 형태를 전부 잡되, `feature/main-x` 는 잡지 않는다.
    const re = new RegExp(`(^|[\\s:/])${escapeRe(b)}(\\s|:|$)`);
    if (re.test(command)) block(`보호 브랜치 '${b}' 에 직접 push 는 금지되어 있다`);
  }
}

function checkBlocked(command, guards) {
  for (const rule of (guards.blockedCommands || [])) {
    if (!rule || !rule.pattern) continue;
    let re;
    try { re = new RegExp(rule.pattern); }
    catch (e) { console.error(`[guard-bash] blockedCommands 정규식이 잘못됐다(${rule.pattern}): ${e.message}`); continue; }
    if (re.test(command)) block(rule.reason || `금지 패턴에 걸렸다: ${rule.pattern}`);
  }
}

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ── main ─────────────────────────────────────────────────────
const command = extractCommand(readStdin());
if (!command) process.exit(0);

const guards = loadGuards();
if (!guards) process.exit(0);

checkBlocked(command, guards);
checkPush(command, guards);
process.exit(0);
