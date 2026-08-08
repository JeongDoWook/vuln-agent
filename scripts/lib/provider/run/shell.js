'use strict';

// run 프로바이더 — mode: "shell" (계약 §2.6)
//
// 이 모듈은 명령을 **고르지 않는다.** 무엇을 실행할지는 전부 .pipeline.json 의
// stacks.{stack}.{verb} 문자열이고, 어떤 스택인지는 repos[].stack 이 정한다.
// 여기 하드코딩된 명령이 한 줄이라도 생기면 "스택을 바꿔도 스킬은 안 바뀐다"는
// 계약의 전제가 깨진다.
//
// 두 가지 규약이 이 파일 전체를 지배한다.
//  1) stdout 은 봉투 전용이다. 자식 프로세스의 stdout 조차 **stderr 로 흘린다** —
//     자식이 stdout 에 한 글자라도 쓰면 스킬의 JSON 파싱이 깨진다.
//  2) 자식이 실패한 것과 px 가 실패한 것은 다르다. 테스트가 깨져도 우리는
//     "명령을 실행했고 결과를 정확히 보고했다" — px 자체는 exit 0 이고,
//     자식 종료코드는 data.exitCode 로 알린다. 스킬은 그 숫자로 분기한다.
//     px 가 exit 1 을 주는 경우는 명령 자체를 찾지 못했을 때뿐이다.
//
// 다른 프로바이더 모듈은 require 하지 않는다(계약 §4).

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

// 어느 레포를, 어느 디렉터리에서 돌릴지는 repo-dir.js 가 정한다. 이 모듈이 자체
// 해석을 갖고 있었기 때문에 **작업공간 clone 안에서 부른 run 이 프로젝트 루트에서
// 돌았다**(2026-08-07 실측 — 작업공간 격리가 통째로 무력해진다). 같은 판정을
// branch·release 도 해야 하므로 중립 모듈 한 곳에 모은다(가드레일 §4).
// 프로바이더 모듈이 아니라 http.js 와 같은 층이라 계약 §4에 걸리지 않는다.
const repoDir = require('../repo-dir');

// 계약 §4.2 — 평범한 Error 에 code/exitCode/data 를 얹어 던진다.
// index.js 의 PxError 를 쓰지 않는 이유: 종료코드를 code 이름으로 역산하는 그 표에는
// 여기서 필요한 조합(예: not_found + exit 1, unsupported + data)이 없다. 계약 §4.2 가
// 요구하는 건 필드 세 개지 특정 클래스가 아니다.
const fail = (code, message, exitCode, data) => {
  const e = new Error(message);
  e.code = code;
  e.exitCode = exitCode;
  if (data !== undefined) e.data = data;
  return e;
};

const log = (m) => process.stderr.write(`${m}\n`);

// "명령을 못 찾았다"와 "자식이 실패했다"는 다른 사건이다. 전자는 설정이 틀린 것이라
// px 자체가 exit 1 이고, 후자는 정상 보고(px exit 0 + data.exitCode)다. 스킬이 고를
// 다음 행동이 다르기 때문에 이 둘을 뭉개면 안 된다.
//
// 종료코드만으로는 구분되지 않는다 — POSIX 셸은 127 을 주지만 **cmd.exe 는 그냥 1 을
// 준다**(2026-08-07 실측: 없는 명령 → exit 1, 진짜 실패와 같은 값). 그래서 실행 전에
// 첫 토큰이 실제로 존재하는 명령인지 먼저 본다.
const NOT_FOUND_STATUS = new Set([127, 9009]);

// 셸 빌트인은 어떤 조회로도 찾을 수 없다 — 검사 대상에서 뺀다(뺐다고 실행이 막히지 않는다).
const BUILTINS = new Set([
  'cd', 'echo', 'set', 'exit', 'call', 'start', 'rem', 'cls', 'type', 'dir', 'copy', 'del', 'md', 'rd', 'ver',
  'export', 'source', '.', ':', 'true', 'false', 'eval', 'exec', 'unset', 'read', 'test', 'alias', 'wait', 'umask',
]);

// 명령의 첫 토큰. 셸 메타문자로 시작하거나(서브셸·리다이렉션) 따옴표로 감싸였으면
// 판단을 포기한다 — 애매하면 검사하지 않고 그냥 실행하는 쪽이 안전하다.
function firstToken(command) {
  const m = /^\s*([^\s"'`|&;<>()]+)/.exec(String(command));
  if (!m) return null;
  const token = m[1];
  if (token.includes('=')) return null;          // FOO=1 npm test 형태
  if (BUILTINS.has(token.toLowerCase())) return null;
  return token;
}

// true=있다 · false=없다 · null=판단 못 함(그냥 실행한다)
function commandExists(token, cwd) {
  // 경로가 섞인 토큰(./gradlew, bin/foo)은 조회 명령이 못 찾는다 — 파일로 확인한다.
  if (/[\\/]/.test(token) || token.startsWith('.')) {
    const exts = isWin ? ['', '.exe', '.cmd', '.bat', '.ps1'] : [''];
    return exts.some((ext) => fs.existsSync(path.resolve(cwd, token + ext)));
  }
  const probe = isWin
    ? cp.spawnSync('where', [token], { cwd, stdio: 'ignore' })
    : cp.spawnSync('command', ['-v', token], { cwd, shell: true, stdio: 'ignore' });
  if (probe.error) return null;
  return probe.status === 0;
}

const PID_DIR = '.pipeline';
const pidFile = (rootDir, repoId) => path.join(rootDir, PID_DIR, `env-${repoId}.json`);
const logFile = (rootDir, repoId) => path.join(rootDir, PID_DIR, `env-${repoId}.log`);

// ── 대상 레포 고르기 ─────────────────────────────────────────
// index.js 의 selectRepo 는 레포가 여럿인데 --repo 가 없으면 usage 로 막는다.
// run 은 그 반대다 — 전부 돌리는 것이 자연스러운 동사(테스트·빌드)라서
// resolveRepos(single:false) 를 쓴다. 대신 무엇을, 어디서 돌렸는지는 반드시 data 에 남긴다.
//
// 디렉터리 판정은 repo-dir.js 다 — 현재 위치가 작업공간 안이면 **그 작업공간의**
// 레포 디렉터리를 쓴다. requireGit 은 걸지 않는다: run 은 git 을 쏘지 않고,
// 체크아웃이 아닌 디렉터리(생성된 산출물 트리 등)를 가리키는 설정도 정상이다.
function pickRepos(ctx, flags) {
  return repoDir.resolveRepos(ctx, flags, process.cwd(), { dirFallback: 'root' });
}

// stacks.{stack}.{key} → 명령 문자열. 없으면 계약 §2.6 대로 exit 3.
function commandFor(ctx, repo, key) {
  const stacks = ctx.config.stacks || {};
  const stackName = repo.config.stack;
  if (!stackName) {
    throw fail('unsupported', `repos[${repo.id}].stack 이 없다 — 실행할 명령을 찾을 수 없다.`, 3,
      { repo: repo.id, verb: key });
  }
  const stack = stacks[stackName];
  if (!stack) {
    throw fail('unsupported', `stacks.${stackName} 정의가 없다 (repos[${repo.id}].stack 이 가리킴).`, 3,
      { repo: repo.id, stack: stackName, verb: key });
  }
  const command = stack[key];
  if (!command || typeof command !== 'string') {
    const known = Object.keys(stack).filter((k) => k !== '_').join(', ') || '(없음)';
    throw fail('unsupported', `stacks.${stackName}.${key} 가 없다 — 이 스택은 '${key}' 를 정의하지 않았다. 정의된 것: ${known}`, 3,
      { repo: repo.id, stack: stackName, verb: key, defined: Object.keys(stack).filter((k) => k !== '_') });
  }
  return command;
}

// 실행 디렉터리. --cwd 가 있으면 그게 1순위(사용자가 명시한 값), 없으면 위에서
// 해석된 레포 디렉터리다.
function cwdFor(ctx, repo, flags) {
  const raw = (flags.cwd !== undefined && flags.cwd !== true) ? String(flags.cwd) : null;
  const abs = raw ? path.resolve(ctx.rootDir, raw) : repo.dir;
  if (!fs.existsSync(abs)) {
    throw fail('not_found', `실행 디렉터리가 없다: ${abs} (repos[${repo.id}])`, 1);
  }
  return abs;
}

// ── 포그라운드 실행 ──────────────────────────────────────────
// stdio: [ignore, 2, 2] — 자식의 stdout 을 **우리 stderr(fd 2)** 로 보낸다.
// 'inherit' 를 쓰면 자식 stdout 이 우리 stdout 으로 새어 봉투가 깨진다.
function runCommand(command, cwd) {
  const token = firstToken(command);
  if (token && commandExists(token, cwd) === false) {
    throw fail('not_found', `명령을 찾을 수 없다: '${token}' (stacks 에 적힌 명령: ${command})`, 1, { command, cwd, missing: token });
  }

  const startedAt = Date.now();
  const r = cp.spawnSync(command, { cwd, shell: true, stdio: ['ignore', 2, 2] });
  const durationMs = Date.now() - startedAt;

  if (r.error) {
    throw fail('spawn_failed', `명령을 실행하지 못했다: ${command} — ${r.error.message}`, 1, { command, cwd });
  }
  if (r.status === null) {
    // 시그널로 죽은 경우. 종료코드가 없으므로 자식 실패로 뭉개지 않고 그대로 알린다.
    throw fail('killed', `명령이 시그널 ${r.signal} 로 종료됐다: ${command}`, 1, { command, cwd, signal: r.signal });
  }
  if (NOT_FOUND_STATUS.has(r.status)) {
    throw fail('not_found', `명령을 찾을 수 없다 (셸 종료코드 ${r.status}): ${command}`, 1, { command, cwd, exitCode: r.status });
  }
  return { command, cwd, exitCode: r.status, durationMs };
}

// 계약 §2.6 의 data 는 { command, exitCode, durationMs } 단수형이다. 레포가 여럿이면
// 그 모양을 버리는 대신 **대표값 + runs[]** 로 넓힌다 — 단일 레포를 가정하고 쓴
// 스킬은 그대로 돌고, 여러 레포를 돌린 사실은 runs 에 남는다.
// 대표 exitCode 는 "0이 아닌 첫 결과" — 하나라도 깨지면 전체가 깨진 것이다.
//
// cwd 를 data 에 담는다. 전에는 stderr 에만 있어서 **스킬이 어디서 돌았는지 알 수 없었고**,
// 작업공간이 아니라 프로젝트 루트에서 도는 결함이 봉투만 보고는 보이지 않았다.
function fold(runs) {
  const bad = runs.find((r) => r.exitCode !== 0);
  const head = bad || runs[runs.length - 1];
  return {
    command: head.command,
    cwd: head.cwd,
    exitCode: head.exitCode,
    durationMs: runs.reduce((sum, r) => sum + r.durationMs, 0),
    repo: head.repo,
    runs,
  };
}

function runVerb(key) {
  return async (ctx, args, flags) => {
    const repos = pickRepos(ctx, flags);
    const filter = (flags.filter !== undefined && flags.filter !== true) ? String(flags.filter) : null;
    const runs = [];
    for (const repo of repos) {
      let command = commandFor(ctx, repo, key);
      // --filter 는 명령 뒤에 그대로 붙인다. 스택마다 필터 문법이 다르므로
      // (gradle --tests, jest -t) 해석은 하지 않고 전달만 한다.
      if (filter) command = `${command} ${filter}`;
      const cwd = cwdFor(ctx, repo, flags);
      log(`▶ [${repo.id}] ${command}   (cwd: ${cwd})`);
      const r = runCommand(command, cwd);
      log(`${r.exitCode === 0 ? '✅' : '❌'} [${repo.id}] exit ${r.exitCode} · ${r.durationMs}ms`);
      runs.push(Object.assign({ repo: repo.id }, r));
    }
    return fold(runs);
  };
}

// ── env up / down ────────────────────────────────────────────
// 개발 서버는 이 프로세스보다 오래 살아야 하므로 detached + unref 로 띄우고,
// PID 를 .pipeline/env-{repo}.json 에 적는다. 이 파일이 없으면 down 이 무엇을
// 죽여야 할지 알 방법이 없다(자식이 우리 프로세스 트리를 떠났기 때문에).

function alive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);   // 시그널 0 = 존재 확인만
    return true;
  } catch (e) {
    return e.code === 'EPERM';   // 있긴 한데 내 권한 밖 — 살아 있는 것으로 본다
  }
}

// Windows 에서 개발 서버를 띄우는 법 — 왜 셸을 바로 detached 로 띄우지 않는가 (2026-08-07 실측)
//
//  · detached 를 빼면: Node 가 자식을 job object 에 묶어서, px 가 끝나는 순간 서버도 같이
//    죽는다. 로그 파일조차 만들어지지 않는다.
//  · detached + shell:true 로 띄우면: 서버는 살아남지만 **로그가 0바이트로 남는다.**
//    DETACHED_PROCESS 로 뜬 cmd.exe 가 물려받은 stdout 핸들을 자기 자식(진짜 서버)에게
//    넘기지 못하기 때문이다. `> file` 리다이렉션을 명령 문자열에 넣어도 결과는 같았다
//    (cmd 자신의 echo 는 찍히고, cmd 가 띄운 exe 의 출력만 사라진다).
//  · detached + shell:false 로 node 를 직접 띄우면: 핸들이 정상 상속된다.
//
// 그래서 Windows 에서는 **node 자신을 얇은 런처로** 끼운다. detached 되는 직접 자식은
// node.exe 이고(핸들 상속 정상), 그 node 가 셸을 평범하게 spawn 해서 손자까지 stdio 를
// 물려준다. 기록하는 PID 는 이 런처이고, down 은 taskkill /T 로 트리째 죽이므로
// 프로세스 하나가 더 끼는 것 외에 동작 차이는 없다.
// POSIX 에는 이 문제가 없다 — sh 가 exec 로 자기 자신을 대체하므로 셸을 바로 띄운다.
const isWin = process.platform === 'win32';

const LAUNCHER = 'process.exit(require("child_process").spawnSync(process.argv[1],{shell:true,stdio:"inherit"}).status||0)';

const spawnFile = (command) => (isWin ? process.execPath : command);
const spawnArgs = (command) => (isWin ? ['-e', LAUNCHER, command] : []);

function readRecord(rootDir, repoId) {
  try {
    return JSON.parse(fs.readFileSync(pidFile(rootDir, repoId), 'utf8'));
  } catch (_) {
    return null;
  }
}

function urlFor(ctx, repo) {
  const c = repo.config;
  const stack = (ctx.config.stacks || {})[c.stack] || {};
  return c.devUrl || c.url || stack.devUrl || stack.url || null;
}

const verbs = {
  'run.test': runVerb('test'),
  'run.build': runVerb('build'),
  'run.lint': runVerb('lint'),

  'env.up': async (ctx, args, flags) => {
    const repos = pickRepos(ctx, flags);
    const started = [];
    const urls = {};
    const details = [];

    fs.mkdirSync(path.join(ctx.rootDir, PID_DIR), { recursive: true });

    for (const repo of repos) {
      const command = commandFor(ctx, repo, 'dev');
      const cwd = cwdFor(ctx, repo, flags);
      const url = urlFor(ctx, repo);

      // 멱등(계약 §1) — 이미 살아 있으면 두 번 띄우지 않는다.
      const prev = readRecord(ctx.rootDir, repo.id);
      if (prev && alive(prev.pid)) {
        log(`↺ [${repo.id}] 이미 떠 있다 (pid ${prev.pid}) — 다시 띄우지 않는다.`);
        started.push(repo.id);
        if (url) urls[repo.id] = url;
        details.push({ repo: repo.id, pid: prev.pid, command: prev.command, cwd: prev.cwd, reused: true });
        continue;
      }

      // detached 자식의 출력은 갈 곳이 필요하다. 우리 stderr 를 물려주면 px 가 끝난 뒤
      // 파이프가 닫혀 자식이 EPIPE 로 죽는다 — 그래서 로그 파일로 보낸다.
      const out = fs.openSync(logFile(ctx.rootDir, repo.id), 'a');
      const child = cp.spawn(spawnFile(command), spawnArgs(command), {
        cwd,
        shell: !isWin,
        detached: true,
        stdio: ['ignore', out, out],
      });
      fs.closeSync(out);

      if (!child.pid) {
        throw fail('spawn_failed', `[${repo.id}] 개발 서버를 띄우지 못했다: ${command}`, 1, { repo: repo.id, command });
      }
      child.unref();

      const record = {
        repo: repo.id,
        pid: child.pid,
        command,
        cwd,
        url,
        log: path.relative(ctx.rootDir, logFile(ctx.rootDir, repo.id)).split(path.sep).join('/'),
        startedAt: new Date().toISOString(),
      };
      fs.writeFileSync(pidFile(ctx.rootDir, repo.id), `${JSON.stringify(record, null, 2)}\n`);

      log(`▶ [${repo.id}] pid ${child.pid} — ${command}   (로그: ${record.log})`);
      started.push(repo.id);
      if (url) urls[repo.id] = url;
      details.push({ repo: repo.id, pid: child.pid, command, cwd, reused: false });
    }

    return { started, urls, processes: details };
  },

  'env.down': async (ctx, args, flags) => {
    const repos = pickRepos(ctx, flags);
    const stopped = [];
    const details = [];

    for (const repo of repos) {
      const file = pidFile(ctx.rootDir, repo.id);
      const record = readRecord(ctx.rootDir, repo.id);

      // 멱등 — 기록이 없거나 이미 죽었으면 성공이다. 죽일 게 없다는 건 실패가 아니다.
      if (!record) {
        details.push({ repo: repo.id, pid: null, result: 'not_running' });
        continue;
      }
      if (!alive(record.pid)) {
        try { fs.unlinkSync(file); } catch (_) {}
        log(`↺ [${repo.id}] pid ${record.pid} 는 이미 죽어 있다 — 기록만 지운다.`);
        details.push({ repo: repo.id, pid: record.pid, result: 'already_dead' });
        continue;
      }

      // 셸을 거쳐 띄웠기 때문에 실제 서버는 셸의 자식이다. 트리를 통째로 죽여야
      // 한다 — 셸만 죽이면 포트를 쥔 프로세스가 그대로 남는다.
      let killed = false;
      if (process.platform === 'win32') {
        // taskkill 의 자체 출력은 버린다 — 콘솔 코드페이지(cp949)로 나와서 UTF-8 로 읽는
        // 하니스에서 깨진다. 결과는 아래에서 우리 문장으로 다시 알린다.
        const r = cp.spawnSync('taskkill', ['/PID', String(record.pid), '/T', '/F'], { stdio: 'ignore' });
        killed = r.status === 0;
      } else {
        try { process.kill(-record.pid, 'SIGTERM'); killed = true; } catch (_) {}
        if (!killed) { try { process.kill(record.pid, 'SIGTERM'); killed = true; } catch (_) {} }
      }

      try { fs.unlinkSync(file); } catch (_) {}
      log(`${killed ? '✅' : '⚠️ '} [${repo.id}] pid ${record.pid} ${killed ? '종료' : '종료 실패 — 수동으로 확인해라'}`);
      stopped.push(repo.id);
      details.push({ repo: repo.id, pid: record.pid, result: killed ? 'killed' : 'kill_failed' });
    }

    // started 를 함께 돌려주는 이유: 계약 §2.6 의 data 모양이 up/down 공통이고,
    // down 뒤에는 떠 있는 것이 없다는 사실을 같은 필드로 읽을 수 있어야 한다.
    return { started: [], stopped, urls: {}, processes: details };
  },
};

async function doctor(ctx) {
  const checks = [];
  const repos = Array.isArray(ctx.config.repos) ? ctx.config.repos : [];
  checks.push({ name: 'repos', ok: repos.length > 0, detail: repos.map((r) => r.id).join(', ') || 'repos[] 가 비어 있다' });

  const stacks = ctx.config.stacks || {};
  for (const repo of repos) {
    const stack = stacks[repo.stack];
    if (!repo.stack) {
      checks.push({ name: `repos.${repo.id}.stack`, ok: false, detail: 'stack 이 없다 — run 동사가 전부 exit 3 이 된다' });
      continue;
    }
    if (!stack) {
      checks.push({ name: `repos.${repo.id}.stack`, ok: false, detail: `stacks.${repo.stack} 정의가 없다` });
      continue;
    }
    const defined = ['test', 'build', 'lint', 'dev'].filter((k) => typeof stack[k] === 'string' && stack[k]);
    const missing = ['test', 'build', 'lint', 'dev'].filter((k) => !defined.includes(k));
    // 정의 안 된 verb 는 fail 이 아니다 — lint 가 없는 스택은 흔하고, 부르면 exit 3 으로
    // 정확히 알려준다. doctor 가 빨간불이 되면 아무도 안 보게 된다(계약 §2.8).
    checks.push({
      name: `stacks.${repo.stack}`,
      ok: true,
      detail: `정의됨: ${defined.join(', ') || '(없음)'}${missing.length ? ` · 미정의(호출 시 exit 3): ${missing.join(', ')}` : ''}`,
    });
  }

  // 떠 있는 env 를 보여준다 — down 을 안 하고 끝낸 세션이 남긴 좀비를 찾는 유일한 곳이다.
  const running = repos
    .map((r) => readRecord(ctx.rootDir, r.id))
    .filter((rec) => rec && alive(rec.pid))
    .map((rec) => `${rec.repo}:${rec.pid}`);
  checks.push({ name: 'env', ok: true, detail: running.length ? `실행 중: ${running.join(', ')}` : '실행 중인 env 없음' });

  return checks;
}

module.exports = { id: 'shell', verbs, doctor };
