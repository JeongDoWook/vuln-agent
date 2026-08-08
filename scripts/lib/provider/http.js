'use strict';

// gitlab.js·github.js가 공유하는 유일한 공통 모듈.
// 계약 §4가 "프로바이더 모듈은 서로를 모른다"고 못박았기 때문에, 두 트래커가 겹치는 부분
// (JSON 요청 / 상태코드→에러코드 / 페이지네이션)은 전부 여기로만 올라온다.
// 여기는 GitLab도 GitHub도 모른다 — 헤더와 URL은 호출부가 만들어 넘긴다.

const https = require('https');
const http = require('http');
const { PxError } = require('./index');   // index는 로드 시점에 http를 require하지 않는다(순환 없음)

const DEFAULT_TIMEOUT_MS = 20000;
const MAX_REDIRECTS = 3;

// HTTP 상태 → 계약 봉투의 error.code. 여기서 한 번만 정해두면 트래커들이
// 각자 다른 이름("notfound" / "not_found")을 쓰는 일이 없다.
const BY_STATUS = {
  400: 'bad_request',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'unsupported',
  409: 'conflict',
  410: 'not_found',
  422: 'unprocessable',
  429: 'rate_limited',
};

function codeForStatus(status) {
  if (BY_STATUS[status]) return BY_STATUS[status];
  if (status >= 500) return 'server_error';
  if (status >= 400) return 'bad_request';
  return 'ok';
}

// 에러 본문에서 사람이 읽을 한 줄을 뽑는다.
// GitLab은 {message: {...}} 처럼 message가 객체인 경우가 있어 문자열 강제가 필요하다.
function messageOf(res) {
  const d = res.data;
  if (d && typeof d === 'object') {
    const m = d.message ?? d.error ?? d.error_description;
    if (typeof m === 'string') return m;
    if (m) return JSON.stringify(m);
    if (Array.isArray(d.errors) && d.errors.length) return JSON.stringify(d.errors);
  }
  return String(res.raw || '').slice(0, 300).replace(/\s+/g, ' ').trim() || '(본문 없음)';
}

function once(url, opts) {
  const { method = 'GET', headers = {}, body = null, timeoutMs = DEFAULT_TIMEOUT_MS } = opts || {};
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch (_) {
      reject(new PxError('usage', `잘못된 URL: ${url}`));
      return;
    }
    // 사내 GitLab이 https 없이 열려 있는 배치가 실제로 있다 — 프로토콜로 모듈을 고른다.
    const mod = target.protocol === 'http:' ? http : https;
    const payload = body === null || body === undefined ? null : Buffer.from(JSON.stringify(body), 'utf8');

    const req = mod.request({
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method,
      headers: Object.assign(
        { Accept: 'application/json' },
        payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {},
        headers,
      ),
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        let data = null;
        try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = null; }
        resolve({ status: res.statusCode, headers: res.headers, data, raw });
      });
    });

    req.on('error', (e) => reject(new PxError('network', `${method} ${url} 실패: ${e.message}`)));
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new PxError('network', `${method} ${url} 타임아웃 (${timeoutMs}ms)`));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

// 리다이렉트를 따라가며 응답을 받는다(상태코드 판정은 하지 않는다).
// GitHub는 레포 이름이 바뀌면 301로 새 경로를 준다 — 그때 조용히 실패하지 않게.
async function raw(url, opts = {}) {
  let current = url;
  for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
    const res = await once(current, opts);
    const loc = res.headers && res.headers.location;
    if ([301, 302, 307, 308].includes(res.status) && loc && i < MAX_REDIRECTS) {
      current = new URL(loc, current).toString();
      continue;
    }
    return res;
  }
  throw new PxError('network', `리다이렉트가 ${MAX_REDIRECTS}회를 넘었다: ${url}`);
}

// 2xx가 아니면 PxError를 던진다. 트래커는 성공 경로만 쓰면 된다.
async function json(url, opts = {}) {
  const res = await raw(url, opts);
  if (res.status >= 400) {
    throw new PxError(codeForStatus(res.status), `${opts.method || 'GET'} ${url} → ${res.status} ${messageOf(res)}`);
  }
  return res;
}

// 404를 에러 대신 null로 받고 싶을 때(멱등성 확인 경로에서 자주 필요하다).
async function jsonOrNull(url, opts = {}) {
  try {
    return await json(url, opts);
  } catch (e) {
    if (e instanceof PxError && e.code === 'not_found') return null;
    throw e;
  }
}

// { a: 1, b: null } → "?a=1" (null/undefined/빈문자는 뺀다)
function qs(params) {
  const parts = [];
  Object.keys(params || {}).forEach((k) => {
    const v = params[k];
    if (v === undefined || v === null || v === '' || v === false) return;
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  });
  return parts.length ? `?${parts.join('&')}` : '';
}

// 다음 페이지가 있는지 헤더로 판정한다.
// GitLab은 x-next-page(끝이면 빈 문자열), GitHub은 Link 헤더의 rel="next"를 준다.
// 힌트가 아예 없으면 판단하지 않고 호출부의 "받은 개수 < perPage" 규칙에 맡긴다.
function hasNextPage(headers) {
  const gl = headers && headers['x-next-page'];
  if (gl !== undefined) return String(gl).trim() !== '';
  const link = headers && headers.link;
  if (link) return /rel="next"/.test(link);
  return true;
}

// makeUrl(page, perPage) → URL 문자열. 배열 응답을 limit까지 모아준다.
// maxPages는 안전장치다 — 잘못된 필터로 수천 페이지를 긁는 사고를 막고,
// 잘렸다는 사실은 stdout(계약상 JSON 전용)이 아니라 stderr로 알린다.
async function paginate(makeUrl, opts = {}) {
  const perPage = opts.perPage || 100;
  const limit = Number(opts.limit) || 0;
  const maxPages = opts.maxPages || 20;
  const out = [];
  for (let page = 1; page <= maxPages; page += 1) {
    const res = await json(makeUrl(page, perPage), opts);
    const items = Array.isArray(res.data) ? res.data : [];
    out.push(...items);
    if (limit && out.length >= limit) return out.slice(0, limit);
    if (items.length < perPage) return out;
    if (!hasNextPage(res.headers)) return out;
  }
  process.stderr.write(`⚠️  페이지 ${maxPages}장에서 끊었다 — --limit 이나 필터로 범위를 좁혀라.\n`);
  return limit ? out.slice(0, limit) : out;
}

module.exports = { codeForStatus, hasNextPage, json, jsonOrNull, messageOf, paginate, qs, raw };
