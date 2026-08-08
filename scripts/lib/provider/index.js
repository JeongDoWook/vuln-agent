'use strict';

// px.js와 프로바이더 구현 사이의 유일한 접착층.
// 여기가 하는 일은 넷뿐이다 — (1) .pipeline.json 찾기·읽기, (2) group → kind → 구현 모듈 해석,
// (3) 토큰을 *Env 환경변수로만 꺼내주기, (4) 계약 §1의 종료코드를 에러 code에 못박기.
// 실제 API 호출은 전부 하위 모듈(tracker/*.js 등)이 한다. 이 파일은 https를 모른다.
//
// 순환 require 주의: http.js가 PxError를 쓰려고 이 파일을 require한다. 그래서 여기서는
// 하위 모듈을 **로드 시점에 require하지 않는다**(loadModule은 호출될 때 require한다).

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const CONFIG_NAME = '.pipeline.json';

// 계약 §1의 종료코드를 에러 code에 고정한다 — 호출부가 exit 숫자를 직접 고르게 두면
// 같은 성격의 오류가 파일마다 다른 코드로 새어나간다.
const EXIT_BY_CODE = {
  unsupported: 3,             // 이 프로바이더가 그 동사를 모른다
  confirmation_required: 2,   // 파괴적 동사인데 --yes 가 없다
  gate: 2,                    // 게이트 미승인
  drift: 2,                   // 대상 브랜치 드리프트
};

class PxError extends Error {
  constructor(code, message, extra) {
    super(message);
    this.name = 'PxError';
    this.code = code;
    this.extra = extra || null;   // 봉투의 error.data 로 같이 나간다(무엇을 지울지 등)
    this.exitCode = EXIT_BY_CODE[code] || 1;
  }
}

// 동사 그룹 → 프로바이더 종류. 계약 §2의 그룹을 그대로 옮긴 표다.
// branch/ws는 workspace, tab은 mux가 담당한다 — 이 파일은 그 구현이 아직 없어도
// "미설치"로만 답하고 죽지 않는다(다른 워커의 범위).
const GROUP_KIND = {
  issue: 'tracker',
  pr: 'tracker',
  branch: 'workspace',
  ws: 'workspace',
  notify: 'notify',
  tab: 'mux',
  run: 'run',
  env: 'run',
  release: 'release',
};

// 계약 §3의 providers 기본값. 설정이 없어도 doctor가 무엇을 찾는지는 말할 수 있어야 한다.
const KIND_DEFAULT = {
  tracker: 'local',
  notify: 'none',
  workspace: 'clone',
  mux: 'none',
  run: 'shell',
  // git 이 기본값인 이유 — 트래커 토큰이 없어도 태그는 만들 수 있다. 릴리스 노트가
  // 필요할 때만 providers.release 를 gitlab|github 으로 올린다(계약 §2.9).
  release: 'git',
};

const KINDS = Object.keys(KIND_DEFAULT);

// ── 설정 로드 ────────────────────────────────────────────────
function findConfigPath(startDir) {
  // gen-score.js의 findAdapter와 같은 규칙(위로 8단계). 탐색 깊이가 서로 다르면
  // "어댑터는 찾는데 파이프라인 설정은 못 찾는" 디렉터리가 생긴다.
  let dir = path.resolve(startDir);
  for (let i = 0; i < 8; i += 1) {
    const candidate = path.join(dir, CONFIG_NAME);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function loadConfig(startDir) {
  const from = path.resolve(startDir || process.cwd());
  const configPath = findConfigPath(from);
  if (!configPath) {
    throw new PxError('no_config', `${CONFIG_NAME} 을 ${from} 에서 위로 8단계까지 찾지 못했다. 라이프사이클 스킬은 이 파일 없이 동작하지 않는다.`);
  }
  let config;
  try {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (e) {
    throw new PxError('bad_config', `${configPath} JSON 파싱 실패: ${e.message}`);
  }
  return { configPath, rootDir: path.dirname(configPath), config };
}

function providerName(config, kind) {
  const chosen = (config.providers || {})[kind];
  return chosen || KIND_DEFAULT[kind];
}

function loadModule(kind, name) {
  // 파일이 없으면 throw 대신 null — doctor가 "미설치"를 표시할 수 있어야 하고,
  // 동사 호출 경로에서는 호출부가 이걸 exit 3(unsupported)으로 바꾼다.
  if (!/^[a-z0-9-]+$/i.test(String(name || ''))) {
    throw new PxError('bad_config', `프로바이더 이름이 이상하다: '${name}'`);
  }
  const file = path.join(__dirname, kind, `${name}.js`);
  if (!fs.existsSync(file)) return null;
  return require(file);
}

// ── 비밀값 해석 ──────────────────────────────────────────────
// 토큰은 **어댑터가 선언한 출처**에서만 읽는다. 두 가지뿐이다:
//   1. `<x>Env`     — 환경변수 이름 (기본 경로)
//   2. `<x>Command` — 토큰을 stdout 으로 뱉는 명령 (선택. 예: "gh auth token")
// 값이 `.pipeline.json` 에 직접 적혀 있으면 무시한다 — 이 파일은 커밋 대상이고 토큰은 아니다.
//
// Command 를 둔 이유: 토큰이 이미 다른 도구의 자격증명 저장소(gh keyring, 사내 vault CLI)에
// 있는 프로젝트가 흔하다. 그걸 환경변수로 **다시 한 번 복사해 두라고 요구하면**, 토큰 사본이
// 셸 설정·CI 변수에 흩어지고 만료·회수 때 어디를 지워야 하는지 아무도 모르게 된다.
// 그렇다고 "gh 가 있으면 알아서 쓴다"로 암묵 폴백하면, 어떤 자격증명으로 나갔는지가
// 설정 어디에도 안 남는다 — 그래서 **어댑터가 명시로 적을 때만** 실행한다.
//
// 명령은 셸을 거치지 않고 공백으로 쪼개 그대로 실행한다(shell:true 였다면 어댑터 한 줄이
// 임의 셸 구문이 된다). stdout 은 절대 로그·에러 메시지로 내보내지 않는다 — 그게 토큰 본문이다.
//
// settings 는 여러 겹일 수 있다. release.github 는 자기 설정이 없으면 tracker.github 로
// 폴백하므로, 겹을 배열로 받아 **처음 값이 나오는 겹**을 쓴다.
function runTokenCommand(label, cmdKey, command) {
  const parts = String(command).trim().split(/\s+/);
  const r = cp.spawnSync(parts[0], parts.slice(1), { encoding: 'utf8', shell: false });
  if (r.error || r.status !== 0) {
    const why = r.error ? r.error.message : `종료코드 ${r.status}`;
    throw new PxError('no_token', `${label}.${cmdKey} 실행 실패 (${command}): ${why}`);
  }
  return (r.stdout || '').trim();
}

function resolveSecret({ settings, fallback, envKey, label, optional = false }) {
  const layers = [settings || {}].concat(fallback ? [fallback] : []);
  const raw = envKey.replace(/Env$/, '');
  const cmdKey = `${raw}Command`;
  const pick = (key) => { for (const s of layers) if (s[key]) return s[key]; return null; };

  if (pick(raw)) {
    process.stderr.write(`⚠️  ${label}.${raw} 는 무시한다 — 비밀값은 ${envKey} 또는 ${cmdKey} 로만 읽는다.\n`);
  }

  // 환경변수가 먼저다 — 명시적 주입이 어댑터 기본값을 이길 수 있어야 CI·일회성 실행이 된다.
  const varName = pick(envKey);
  if (varName && process.env[varName]) {
    return { value: process.env[varName], source: `환경변수 ${varName}` };
  }

  const command = pick(cmdKey);
  if (command) {
    const value = runTokenCommand(label, cmdKey, command);
    if (value) return { value, source: `명령 '${command}'` };
    if (optional) return { value: null, source: null };
    throw new PxError('no_token', `${label}.${cmdKey} 가 빈 값을 냈다 (${command}).`);
  }

  if (optional) return { value: null, source: null };
  if (!varName) {
    throw new PxError('bad_config', `${label}.${envKey} 도 ${cmdKey} 도 없다 — 토큰을 담은 환경변수 이름이나, 토큰을 출력하는 명령을 적어라.`);
  }
  throw new PxError('no_token', `환경변수 ${varName} 가 비어 있다 (${label}.${envKey} 가 가리킴). ${cmdKey} 로 명령을 지정할 수도 있다 (예: "gh auth token").`);
}

// ── 실행 컨텍스트 ────────────────────────────────────────────
function buildContext(kind, loaded, name) {
  const settings = (loaded.config[kind] || {})[name] || {};
  const label = `${kind}.${name}`;

  const secret = (envKey, opts) =>
    resolveSecret({ settings, envKey, label, optional: (opts || {}).optional }).value;

  // doctor 가 "어디서 읽었는지"를 표시할 때 쓴다. 값은 절대 돌려주지 않는다.
  const secretSource = (envKey) => {
    try { return resolveSecret({ settings, envKey, label, optional: true }).source; }
    catch (_) { return null; }
  };

  return {
    secretSource,
    kind,
    provider: name,
    config: loaded.config,
    configPath: loaded.configPath,
    rootDir: loaded.rootDir,
    settings,
    secret,
  };
}

// ── 동사 해석 ────────────────────────────────────────────────
function attachProvider(err, name) {
  err.provider = name;
  return err;
}

function resolveCall(group, verb, cwd) {
  const kind = GROUP_KIND[group];
  if (!kind) {
    throw new PxError('usage', `모르는 그룹 '${group}'. 사용 가능: ${Object.keys(GROUP_KIND).join(', ')}, doctor`);
  }
  const loaded = loadConfig(cwd);
  const name = providerName(loaded.config, kind);
  const mod = loadModule(kind, name);
  // 봉투의 provider 필드는 실패했을 때도 채워야 한다 — "무엇이 이 동사를 거부했는지"가
  // 폴백 경로를 고르는 근거이기 때문이다. 그래서 에러에 provider를 붙여 던진다.
  if (!mod) {
    throw attachProvider(new PxError('unsupported', `${kind} 프로바이더 '${name}' 구현이 없다 (scripts/lib/provider/${kind}/${name}.js 미설치).`), name);
  }
  const verbKey = `${group}.${verb}`;
  const handler = (mod.verbs || {})[verbKey];
  if (!handler) {
    const known = Object.keys(mod.verbs || {}).join(', ') || '(없음)';
    throw attachProvider(new PxError('unsupported', `'${verbKey}' 는 ${name} 프로바이더가 지원하지 않는다. 지원 동사: ${known}`), name);
  }
  return { kind, provider: name, verbKey, handler, ctx: buildContext(kind, loaded, name) };
}

// ── doctor ───────────────────────────────────────────────────
// status: ok | fail | missing. missing(구현 미설치)은 실패로 치지 않는다 —
// workspace/notify/mux는 이 계약을 나눠 구현하는 중이라, 없다고 해서 tracker가
// 못 돌아가는 건 아니기 때문이다.
async function diagnose(cwd) {
  const rows = [];
  let loaded;
  try {
    loaded = loadConfig(cwd);
  } catch (e) {
    rows.push({ kind: 'config', provider: '-', name: CONFIG_NAME, status: 'fail', detail: e.message });
    return { rows, configPath: null };
  }
  rows.push({ kind: 'config', provider: '-', name: CONFIG_NAME, status: 'ok', detail: loaded.configPath });

  for (const kind of KINDS) {
    const name = providerName(loaded.config, kind);
    let mod;
    try {
      mod = loadModule(kind, name);
    } catch (e) {
      rows.push({ kind, provider: name, name: 'module', status: 'fail', detail: e.message });
      continue;
    }
    if (!mod) {
      rows.push({ kind, provider: name, name: 'module', status: 'missing', detail: `scripts/lib/provider/${kind}/${name}.js 미설치` });
      continue;
    }
    if (typeof mod.doctor !== 'function') {
      rows.push({ kind, provider: name, name: 'module', status: 'ok', detail: '로드됨 (자체 진단 없음)' });
      continue;
    }
    let checks;
    try {
      checks = await mod.doctor(buildContext(kind, loaded, name));
    } catch (e) {
      rows.push({ kind, provider: name, name: 'doctor', status: 'fail', detail: e.message });
      continue;
    }
    (checks || []).forEach((c) => {
      rows.push({ kind, provider: name, name: c.name, status: c.ok ? 'ok' : 'fail', detail: c.detail || '' });
    });
  }
  return { rows, configPath: loaded.configPath };
}

// ── 프로바이더 구현이 공유하는 작은 헬퍼들 ────────────────────
// (트래커끼리 서로를 require하지 않게 하려면 이런 설정 해석은 여기 있어야 한다)

function selectRepo(ctx, flags) {
  const repos = Array.isArray(ctx.config.repos) ? ctx.config.repos : [];
  const ids = repos.map((r) => r.id).join(', ') || '(없음)';
  if (flags.repo) {
    const hit = repos.find((r) => r.id === flags.repo);
    if (!hit) throw new PxError('bad_config', `repos 에 '${flags.repo}' 가 없다. 사용 가능: ${ids}`);
    return hit;
  }
  if (repos.length === 1) return repos[0];
  if (repos.length === 0) return null;   // 단일 프로젝트 설정(tracker.*.project)으로 폴백
  throw new PxError('usage', `repos 가 ${repos.length}개다 — --repo <id> 로 지정해라 (${ids})`);
}

function requireFlag(flags, name, verbKey) {
  const v = flags[name];
  if (v === undefined || v === true || v === '') {
    throw new PxError('usage', `${verbKey}: --${kebab(name)} <값> 이 필요하다.`);
  }
  return String(v);
}

function requireArg(args, index, label, verbKey) {
  const v = args[index];
  if (v === undefined || v === '') throw new PxError('usage', `${verbKey}: <${label}> 인자가 필요하다.`);
  return String(v);
}

// 파괴적 동사(계약 §1)는 --yes 없이는 실행하지 않고, 무엇을 하려 했는지 보여주며 exit 2.
function requireYes(flags, verbKey, preview) {
  if (flags.yes) return;
  throw new PxError('confirmation_required', `${verbKey} 는 파괴적 동사다 — --yes 없이는 실행하지 않는다.`, preview);
}

function kebab(s) {
  return String(s).replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
}

// "a,b , c" → ["a","b","c"] (빈 값 제거). 라벨 플래그가 세 트래커에서 같은 모양이어야 한다.
function splitList(value) {
  if (value === undefined || value === null || value === true) return null;
  const items = String(value).split(',').map((s) => s.trim()).filter(Boolean);
  return items;
}

module.exports = {
  CONFIG_NAME,
  GROUP_KIND,
  KINDS,
  PxError,
  buildContext,
  diagnose,
  findConfigPath,
  loadConfig,
  loadModule,
  providerName,
  requireArg,
  requireFlag,
  requireYes,
  resolveCall,
  resolveSecret,
  selectRepo,
  splitList,
};
