'use strict';

// notify 프로바이더 — slack (계약 §2.5)
//
// 알림은 부수 효과다. 이 모듈은 **절대 파이프라인을 멈추지 않는다** — 웹훅 미설정,
// DNS 실패, 타임아웃, 4xx/5xx 무엇이든 예외를 던지지 않고 { sent:false, error }
// 로 돌려준다. 리뷰가 통과했는데 Slack 이 죽어서 릴리스가 막히는 상황을 만들지
// 않기 위해서다.
//
// 웹훅 URL 은 설정 파일이 아니라 notify.slack.webhookEnv 가 가리키는 **환경변수**
// 에서만 읽는다(계약 §3). .pipeline.json 은 커밋 대상이고 웹훅 URL 은 비밀값이다.

const https = require('https');
const http = require('http');
const { URL } = require('url');

const DEFAULT_WEBHOOK_ENV = 'SLACK_WEBHOOK_URL';
const DEFAULT_TIMEOUT_MS = 5000;

const flag = (args, ...names) => {
  if (!args || Array.isArray(args)) return undefined;
  for (const n of names) if (args[n] !== undefined) return args[n];
  return undefined;
};

const positionals = (args) => {
  if (!args) return [];
  if (Array.isArray(args)) return args.slice();
  for (const k of ['_', 'positional', 'positionals', 'args']) {
    if (Array.isArray(args[k])) return args[k].slice();
  }
  return [];
};

const unsupported = (verb) => {
  const e = new Error(`notify(slack) 는 '${verb}' 를 지원하지 않습니다`);
  e.code = 'unsupported';
  e.exitCode = 3;
  throw e;
};

const LEVEL_MARK = Object.freeze({ info: ':information_source:', warn: ':warning:', error: ':rotating_light:' });

const post = (webhook, payload, timeoutMs) => new Promise((resolve) => {
  let target;
  try {
    target = new URL(webhook);
  } catch (_) {
    resolve({ ok: false, error: '웹훅 URL 형식이 올바르지 않습니다' });
    return;
  }

  const mod = target.protocol === 'http:' ? http : https;
  const body = Buffer.from(JSON.stringify(payload), 'utf8');

  const req = mod.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || undefined,
    path: target.pathname + target.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': body.length,
    },
  }, (res) => {
    let raw = '';
    res.setEncoding('utf8');
    res.on('data', (c) => { raw += c; });
    res.on('end', () => {
      const status = res.statusCode || 0;
      resolve(status >= 200 && status < 300
        ? { ok: true, status }
        : { ok: false, status, error: `HTTP ${status}: ${raw.slice(0, 200)}` });
    });
  });

  // 알림 하나 때문에 파이프라인이 몇 분씩 매달리지 않도록 짧게 끊는다.
  req.setTimeout(timeoutMs, () => { req.destroy(new Error(`timeout ${timeoutMs}ms`)); });
  req.on('error', (e) => resolve({ ok: false, error: e.message }));
  req.write(body);
  req.end();
});

const send = async (args, ctx) => {
  const log = (ctx && ctx.log) || (() => {});
  const cfg = ((ctx && ctx.config && ctx.config.notify) || {}).slack || {};

  const pos = positionals(args);
  const event = String(flag(args, 'event') || pos[0] || '').trim();
  const text = String(flag(args, 'text') || pos[1] || '').trim();
  const level = String(flag(args, 'level') || 'info').toLowerCase();
  const link = flag(args, 'url'); // 메시지에 덧붙일 링크. 웹훅 URL 이 아니다.

  if (!event) {
    const e = new Error('--event 가 필요합니다');
    e.code = 'usage';
    e.exitCode = 1;
    throw e;
  }

  // 구독하지 않은 이벤트는 조용히 흘린다 — 에러가 아니다(계약 §2.5).
  if (Array.isArray(cfg.events) && !cfg.events.includes(event)) {
    log(`[notify] '${event}' 는 notify.events 에 없습니다 — skip`);
    return { sent: false, skipped: true, event, reason: 'event_not_subscribed', channel: cfg.channel || null };
  }

  const envKey = cfg.webhookEnv || DEFAULT_WEBHOOK_ENV;
  const webhook = process.env[envKey];
  if (!webhook) {
    log(`[notify] 환경변수 ${envKey} 가 비어 있습니다 — 전송 생략`);
    return { sent: false, event, channel: cfg.channel || null, error: `${envKey} 미설정` };
  }

  const mark = LEVEL_MARK[level] || LEVEL_MARK.info;
  const lines = [`${mark} *${event}*`, text].filter(Boolean);
  if (link) lines.push(String(link));

  const payload = { text: lines.join('\n') };
  if (cfg.channel) payload.channel = cfg.channel;
  if (cfg.username) payload.username = cfg.username;
  if (cfg.iconEmoji) payload.icon_emoji = cfg.iconEmoji;

  const r = await post(webhook, payload, Number(cfg.timeoutMs) || DEFAULT_TIMEOUT_MS);
  if (!r.ok) {
    // 네트워크 오류도 여기서 삼킨다. 던지면 스킬이 멈춘다.
    log(`[notify] 전송 실패 (${event}): ${r.error}`);
    return { sent: false, event, channel: cfg.channel || null, error: r.error };
  }

  log(`[notify] 전송 완료: ${event}`);
  return { sent: true, event, channel: cfg.channel || null, status: r.status };
};

// ── doctor (계약 §2.8) ───────────────────────────────────────

const doctor = async (ctx) => {
  const cfg = ((ctx && ctx.config && ctx.config.notify) || {}).slack || {};
  const envKey = cfg.webhookEnv || DEFAULT_WEBHOOK_ENV;
  return [
    { name: 'webhookEnv', ok: Boolean(cfg.webhookEnv), detail: cfg.webhookEnv || `미지정 — ${DEFAULT_WEBHOOK_ENV} 로 가정` },
    { name: envKey, ok: Boolean(process.env[envKey]), detail: process.env[envKey] ? '설정됨' : `환경변수 ${envKey} 가 비어 있다 — 알림은 조용히 skip 된다` },
    { name: 'events', ok: true, detail: Array.isArray(cfg.events) ? cfg.events.join(', ') : '미지정 — 전 이벤트 전송' },
  ];
};

// ── px.js 접속부 ─────────────────────────────────────────────
// send() 가 본체다. index.js 는 verbs 표와 handler(ctx, args, flags) 를 쓴다.

const adapt = (fn) => (ctx, args, flags) => fn(
  Object.assign({ _: Array.isArray(args) ? args : [] }, flags || {}),
  {
    config: (ctx && ctx.config) || {},
    repoRoot: (ctx && (ctx.repoRoot || ctx.rootDir)) || process.cwd(),
    log: (ctx && ctx.log) || ((m) => process.stderr.write(`${m}\n`)),
  }
);

module.exports = { id: 'slack', send, verbs: { 'notify.send': adapt(send) }, doctor, unsupported };
