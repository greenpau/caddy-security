// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Real form login and real SQLite COMMIT failure; controls stay on process pipes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const readline = require('node:readline');
const { BrowserProtocolError, waitForRead } = require('./authorization_redirect_cdp.cjs');
const { disposeBrowserContexts } = require('./browser_contexts.cjs');
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const controls = [], controlWaiters = [];
let inputClosed = false;
const lines = readline.createInterface({ input: process.stdin, terminal: false });
lines.on('line', line => {
  if (Buffer.byteLength(line) > 8192 || controls.length > 8) { inputClosed = true; lines.close(); return; }
  const next = controlWaiters.shift();
  if (next) next(line); else controls.push(line);
});
lines.on('close', () => { inputClosed = true; for (const resolve of controlWaiters.splice(0)) resolve(null); });
async function control(expected) {
  let timer;
  const line = controls.length ? controls.shift() : await new Promise((resolve, reject) => {
    if (inputClosed) return reject(new Error('control input closed'));
    const receive = value => { clearTimeout(timer); resolve(value); };
    controlWaiters.push(receive);
    timer = setTimeout(() => { const at = controlWaiters.indexOf(receive); if (at >= 0) controlWaiters.splice(at, 1); reject(new Error('control deadline')); }, 30000);
  });
  const value = JSON.parse(line);
  assert.ok(value && value.phase === expected, 'unexpected fixture phase');
  return value;
}
function signal(phase) { process.stdout.write(JSON.stringify({ phase }) + '\n'); }

const socket = new WebSocket(endpoint);
const calls = new Map(), contexts = new Set(), secrets = new Set(), pendingCapture = new Set();
const refreshRequests = new Map(), extras = new Map(), responseExtras = new Map();
let sequence = 0, exceptionCount = 0, captureFailed = false, evidenceBytes = 0, stage = 'startup', complete = false;
const evidence = fs.openSync(config.evidenceFile, 'wx', 0o600);
function record(value) {
  const line = JSON.stringify({ version: 1, ...value }) + '\n';
  evidenceBytes += Buffer.byteLength(line);
  if (evidenceBytes > 128 * 1024) throw new Error('evidence bound');
  fs.writeSync(evidence, line);
}
function secret(value) {
  if (typeof value === 'string' && value && value !== 'delete' && !secrets.has(value)) {
    secrets.add(value); record({ kind: 'secret', value });
  }
}
function credential(name) {
  return name === config.accessCookie || name === config.refreshCookie ||
    name.startsWith('AUTHP_SANDBOX_ID') || name.endsWith('_OIDC_SESSION_ID');
}
function header(headers, name) { return Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name)?.[1] || ''; }
function captureHeaders(headers) {
  for (const line of String(header(headers, 'set-cookie')).split('\n')) {
    const match = /^([^=;]+)=([^;]*)/.exec(line);
    if (match && credential(match[1])) secret(match[2]);
  }
}
function background(work) {
  const task = work.catch(() => { captureFailed = true; }).finally(() => pendingCapture.delete(task));
  pendingCapture.add(task);
}
socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data);
  const key = message.sessionId + ':' + message.params?.requestId;
  try {
    if (message.method === 'Runtime.exceptionThrown') exceptionCount++;
    if (message.method === 'Network.requestWillBeSentExtraInfo') {
      for (const item of message.params.associatedCookies || []) if (credential(item.cookie.name)) secret(item.cookie.value);
      extras.set(key, message.params.headers);
      if (refreshRequests.has(key)) refreshRequests.get(key).extra = message.params.headers;
    }
    if (message.method === 'Network.responseReceivedExtraInfo') {
      captureHeaders(message.params.headers);
      responseExtras.set(key, message.params.headers);
      if (refreshRequests.has(key)) refreshRequests.get(key).responseExtra = message.params.headers;
    }
    if (message.method === 'Network.requestWillBeSent') {
      const request = message.params.request;
      const url = new URL(request.url);
      if (url.origin === config.origin && url.pathname === config.mount + '/api/refresh_token') {
        assert.ok(refreshRequests.size < 8, 'too many exchanges');
        refreshRequests.set(key, { method: request.method, body: request.postData || '', extra: extras.get(key),
          responseExtra: responseExtras.get(key), complete: false, status: 0 });
      }
    }
    if (message.method === 'Network.responseReceived') {
      captureHeaders(message.params.response.headers);
      const item = refreshRequests.get(key);
      if (item) { item.status = message.params.response.status; item.headers = message.params.response.headers; }
    }
    if (message.method === 'Network.loadingFinished' && refreshRequests.has(key)) {
      const item = refreshRequests.get(key);
      if (item.status === 200) background((async () => {
        const result = await command('Network.getResponseBody', { requestId: message.params.requestId }, message.sessionId);
        item.response = result.base64Encoded ? Buffer.from(result.body, 'base64').toString('utf8') : result.body;
        assert.ok(Buffer.byteLength(item.response) <= 128 * 1024, 'response bound');
        item.complete = true;
      })());
    }
  } catch { captureFailed = true; }
  if (!message.id) return;
  const call = calls.get(message.id);
  if (!call) return;
  calls.delete(message.id); clearTimeout(call.timer);
  if (message.error) call.reject(new BrowserProtocolError(call.method, message.error)); else call.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { calls.delete(id); reject(new Error('browser command deadline')); }, 20000);
    calls.set(id, { resolve, reject, timer, method });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(tab, fn, args) {
  const result = await command('Runtime.evaluate', { expression: `(${fn.toString()})(${JSON.stringify(args)})`,
    awaitPromise: true, returnByValue: true }, tab);
  assert.ok(!result.exceptionDetails, 'browser evaluation failed');
  return result.result.value;
}
async function page(context) {
  const { targetId } = await command('Target.createTarget', { url: 'about:blank', browserContextId: context });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Runtime']) await command(domain + '.enable', {}, sessionId);
  await command('Network.enable', { maxPostDataSize: 64 * 1024, maxTotalBufferSize: 2 * 1024 * 1024,
    maxResourceBufferSize: 256 * 1024 }, sessionId);
  return sessionId;
}
async function navigate(tab, url) {
  const result = await command('Page.navigate', { url }, tab);
  assert.ok(!result.errorText, 'verified navigation failed');
  await waitForRead(() => evaluate(tab, url => location.href === url && document.readyState === 'complete', url));
}
async function session(tab) {
  return evaluate(tab, mount => JSON.parse(localStorage.getItem('authcrunch-session:' + mount) || 'null'), config.mount);
}
async function cookies(context) {
  const all = (await command('Storage.getCookies', { browserContextId: context })).cookies;
  for (const cookie of all) if (credential(cookie.name)) secret(cookie.value);
  const access = all.filter(cookie => cookie.name === config.accessCookie);
  const refresh = all.filter(cookie => cookie.name === config.refreshCookie);
  assert.ok(access.length === 1 && refresh.length === 1 && access[0].httpOnly && access[0].secure &&
    refresh[0].httpOnly && refresh[0].secure, 'private cookie contract');
  assert.ok(!all.some(cookie => cookie.name.endsWith('_OIDC_SESSION_ID')), 'unexpected OP authority');
  return { access: access[0].value, refresh: refresh[0].value };
}
async function privacy(tab) {
  const exposed = await evaluate(tab, () => JSON.stringify({ local: Object.entries(localStorage), session: Object.entries(sessionStorage),
    cookie: document.cookie, url: location.href, body: document.body.innerText }));
  assert.ok(![...secrets].some(value => exposed.includes(value)), 'credential exposed to page state');
}
async function login(tab, context, password, fresh) {
  stage = 'login navigation';
  await navigate(tab, config.origin + config.mount + '/login' + (fresh ? '?fresh=1' : ''));
  stage = 'local form selection';
  await evaluate(tab, () => {
    if (document.querySelector('input[name="username"]')?.getClientRects().length) return;
    const action = [...document.querySelectorAll('#authenticators a')].find(link => link.textContent.trim() === 'LOCAL');
    if (!action) throw new Error('local form choice absent');
    action.click();
  });
  await waitForRead(() => evaluate(tab, () => document.querySelector('input[name="username"]')?.getClientRects().length &&
    document.querySelector('[name="realm"]')?.value === 'local'));
  stage = 'username submission';
  await evaluate(tab, () => {
    const field = document.querySelector('input[name="username"]');
    field.value = 'alice'; field.dispatchEvent(new Event('input', { bubbles: true })); field.form.requestSubmit();
  });
  await waitForRead(() => evaluate(tab, mount => location.pathname.startsWith(mount + '/sandbox/') &&
    document.querySelector('input[name="secret"][type="password"]')?.getClientRects().length, config.mount));
  for (const cookie of (await command('Storage.getCookies', { browserContextId: context })).cookies) if (credential(cookie.name)) secret(cookie.value);
  stage = 'password submission';
  await evaluate(tab, password => {
    const field = document.querySelector('input[name="secret"][type="password"]');
    field.value = password; field.dispatchEvent(new Event('input', { bubbles: true })); field.form.requestSubmit();
  }, password);
  await waitForRead(() => evaluate(tab, mount => location.pathname === mount + '/portal' &&
    document.readyState === 'complete' && !!window.AuthCrunchSession, config.mount));
  await waitForRead(async () => { const state = await session(tab); return state?.session_id && !state.pending && !state.blocked; });
  stage = 'login private cookie evidence';
  const grant = await cookies(context), state = await session(tab);
  record({ kind: 'grant', phase: fresh ? 'fresh' : 'initial', access: grant.access, refresh: grant.refresh, sessionID: state.session_id });
  await privacy(tab);
  return { ...grant, sessionID: state.session_id };
}
async function refresh(tab) {
  return evaluate(tab, async () => { try { await window.AuthCrunchSession.refresh(true); return true; } catch { return false; } });
}
async function blocked(tab, expected) {
  const state = await session(tab);
  assert.ok(state?.blocked === true && state.session_id === expected && !state.pending, 'delivered 503 blocked-state contract');
  assert.ok(await refresh(tab) === false, 'uncertain exchange was automatically repeated');
  await privacy(tab);
}
async function wire(index, status) {
  await waitForRead(() => {
    const item = [...refreshRequests.values()][index];
    return item?.status && item.extra && item.responseExtra && (status !== 200 || item.complete);
  });
  const item = [...refreshRequests.values()][index];
  assert.ok(item.status === status && item.method === 'POST' && item.body === '{}', 'refresh wire status/method/body');
  assert.ok(header(item.extra, 'origin') === config.origin && header(item.extra, 'sec-fetch-site') === 'same-origin' &&
    header(item.extra, 'x-authcrunch-refresh') === '1' && header(item.extra, 'x-authcrunch-refresh-session'), 'natural refresh origin/binding');
  assert.ok(String(header(item.responseExtra, 'cache-control')).includes('no-store'), 'refresh cache policy');
  if (status === 503) {
    // The real client rejects on status without consuming the error body, so
    // Chrome may not emit loadingFinished here. The Go probe checks the exact
    // complete forwarded body; observe delivered status/headers in the browser.
    assert.ok(!header(item.responseExtra, 'location'), 'uncertain response authority');
    assert.ok(!header(item.responseExtra, 'set-cookie'), 'uncertain response published cookies');
  } else {
    const result = JSON.parse(item.response);
    assert.ok(!result.access_token && !result.refresh_token, 'browser response exposed credentials');
  }
}
async function resource(tab) {
  const result = await evaluate(tab, async origin => {
    const response = await fetch(origin + '/resource', { credentials: 'same-origin', redirect: 'manual', cache: 'no-store' });
    return { status: response.status, body: await response.text() };
  }, config.origin);
  assert.ok(result.status === 200 && result.body === 'identity resource', 'genuine protected resource');
}

(async () => {
  try {
    const input = await control('credentials'); secret(input.password);
    await new Promise((resolve, reject) => {
      if (socket.readyState === WebSocket.OPEN) return resolve();
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', () => reject(new Error('debugging socket unavailable')), { once: true });
    });
    const { browserContextId: context } = await command('Target.createBrowserContext'); contexts.add(context);
    const primary = await page(context);
    stage = 'negative TLS';
    const rejected = await command('Page.navigate', { url: config.untrustedURL }, primary);
    assert.ok(/ERR_CERT_/.test(rejected.errorText || ''), 'untrusted certificate accepted');
    stage = 'initial form proof';
    const initial = await login(primary, context, input.password, false);
    stage = 'initial protected resource';
    await resource(primary);
    stage = 'secondary tab initialization';
    const secondary = await page(context);
    await navigate(secondary, config.origin + config.mount + '/portal');
    await waitForRead(() => evaluate(secondary, () => !!window.AuthCrunchSession));
    await waitForRead(async () => (await session(secondary))?.session_id === initial.sessionID);
    stage = 'armed exchange'; signal('ready'); await control('attempt');
    assert.ok(await refresh(primary) === false, 'real uncertain exchange reported success');
    stage = 'uncertain exchange wire evidence';
    await wire(0, 503);
    stage = 'unchanged uncertain cookies';
    const unchanged = await cookies(context);
    assert.ok(unchanged.access === initial.access && unchanged.refresh === initial.refresh, 'failed COMMIT replaced browser credentials');
    await blocked(primary, initial.sessionID);
    stage = 'secondary tab uncertainty refusal';
    await command('Page.bringToFront', {}, secondary);
    await blocked(secondary, initial.sessionID);
    assert.ok(refreshRequests.size === 1, 'uncertain browser repeated the original exchange');
    stage = 'reopen refusal'; signal('uncertain'); await control('reopened');
    await navigate(secondary, config.origin + config.mount + '/portal');
    await waitForRead(() => evaluate(secondary, () => !!window.AuthCrunchSession));
    await blocked(secondary, initial.sessionID);
    await blocked(primary, initial.sessionID);
    assert.ok(refreshRequests.size === 1, 'reopen triggered an old-credential retry');
    signal('blocked_after_reopen'); await control('fresh');
    stage = 'fresh independent form proof';
    const fresh = await login(primary, context, input.password, true);
    assert.ok(fresh.sessionID !== initial.sessionID && fresh.access !== initial.access && fresh.refresh !== initial.refresh,
      'fresh login did not replace the uncertain family');
    await resource(primary);
    await waitForRead(async () => { const state = await session(secondary); return state?.session_id === fresh.sessionID && !state.blocked && !state.pending; });
    stage = 'new-family rotation';
    assert.ok(await refresh(secondary) === true, 'fresh family did not recover renewal');
    await wire(1, 200);
    const rotated = await cookies(context), state = await session(secondary);
    assert.ok(state.session_id === fresh.sessionID && !state.blocked && !state.pending && rotated.refresh !== fresh.refresh &&
      rotated.access !== fresh.access && refreshRequests.size === 2, 'recovery did not rotate only the new family');
    record({ kind: 'grant', phase: 'rotated', access: rotated.access, refresh: rotated.refresh, sessionID: state.session_id });
    await resource(secondary); await privacy(primary); await privacy(secondary);
    await Promise.all([...pendingCapture]);
    assert.ok(!captureFailed && exceptionCount === 0, 'browser wire/runtime evidence failed');
    complete = true;
  } catch {
    process.stderr.write('SQLite refresh browser failed at ' + stage + '\n'); process.exitCode = 1;
    // Only fixed-shape transport diagnostics; no headers, bodies or credentials.
    process.stderr.write(JSON.stringify({ captureFailed, exceptionCount, requests: [...refreshRequests.values()].map(item => ({
      status: item.status, complete: item.complete, requestExtra: !!item.extra, responseExtra: !!item.responseExtra,
    })) }) + '\n');
  } finally {
    try { await disposeBrowserContexts(command, contexts); await Promise.all([...pendingCapture]);
      if (captureFailed || exceptionCount) { process.stderr.write('SQLite refresh browser teardown evidence failed\n'); process.exitCode = 1; }
    } catch { process.stderr.write('SQLite refresh browser cleanup failed\n'); process.exitCode = 1; }
    // The terminal evidence record follows awaited disposal and late capture.
    if (complete && process.exitCode !== 1) { record({ kind: 'phase', phase: 'complete' }); signal('complete'); }
    lines.close(); socket.close(); fs.closeSync(evidence);
    for (const call of calls.values()) clearTimeout(call.timer);
  }
})();
