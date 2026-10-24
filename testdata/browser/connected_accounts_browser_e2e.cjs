// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Real Caddy/OAuth, natural HTML forms and private incremental observations.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { BrowserProtocolError, waitForRead } = require('./authorization_redirect_cdp.cjs');
const { disposeBrowserContexts } = require('./browser_contexts.cjs');

const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded), input = JSON.parse(fs.readFileSync(0, 'utf8'));
const evidence = fs.openSync(config.evidenceFile, 'wx', 0o600);
const socket = new WebSocket(endpoint), pending = new Map(), contexts = new Set();
const documents = new Map(), requests = new Map(), extras = new Map(), posts = [], assets = new Map(), secrets = new Set();
let sequence = 0, evidenceBytes = 0, exceptionCount = 0, captureFailed = false, lastCounter = -1;
let stage = 'connect', failureDiagnostics = '', activeTab = '';

function record(value) {
  const line = JSON.stringify({ version: 1, ...value }) + '\n';
  evidenceBytes += Buffer.byteLength(line);
  if (evidenceBytes > 256 * 1024) throw new Error('private evidence exceeded bound');
  fs.writeSync(evidence, line);
}
function secret(value) {
  if (typeof value !== 'string' || !value || secrets.has(value)) return;
  secrets.add(value); record({ kind: 'secret', value });
}
secret(input.password); secret(input.totpSecret);
function header(headers, name) { return Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name)?.[1] || ''; }
function captureCookie(cookie) {
  if (cookie.name !== 'AUTHP_SESSION_ID' && (/_(ACCESS_TOKEN|REFRESH_TOKEN|OIDC_SESSION_ID)$/.test(cookie.name) || cookie.name.startsWith('AUTHP_SANDBOX_ID')) && cookie.value !== 'delete') secret(cookie.value);
}
function captureURL(raw) {
  const url = new URL(raw);
  for (const name of ['state', 'nonce', 'code', 'redirect_url']) for (const value of url.searchParams.getAll(name)) secret(value);
  if (url.origin === config.origin && url.pathname.startsWith(config.mount + '/connected-accounts/')) {
    const ticket = url.pathname.slice((config.mount + '/connected-accounts/').length);
    if (ticket) { secret(ticket); secret(url.href); }
  }
}
function captureHeaders(headers) {
  const cookies = header(headers, 'set-cookie');
  for (const line of cookies.split('\n')) {
    const pair = line.split(';')[0], index = pair.indexOf('=');
    if (index > 0) captureCookie({ name: pair.slice(0, index), value: pair.slice(index + 1) });
  }
}

socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data), key = message.sessionId + ':' + message.params?.requestId;
  try {
    if (message.method === 'Runtime.exceptionThrown') exceptionCount++;
    if (message.method === 'Network.requestWillBeSentExtraInfo') {
      for (const item of message.params.associatedCookies || []) captureCookie(item.cookie);
      const list = extras.get(key) || []; list.push(message.params); extras.set(key, list);
    }
    if (message.method === 'Network.responseReceivedExtraInfo') captureHeaders(message.params.headers);
    if (message.method === 'Network.requestWillBeSent') {
      const request = message.params.request, url = new URL(request.url);
      captureURL(request.url);
      const hops = requests.get(key) || []; requests.set(key, hops);
      if (message.params.redirectResponse) captureHeaders(message.params.redirectResponse.headers);
      const hop = { key, index: hops.length, url: request.url, method: request.method };
      hops.push(hop);
      if (url.origin === config.origin && request.method === 'POST') {
        const form = new URLSearchParams(request.postData || '');
        for (const name of ['secret', 'passcode', 'csrf']) secret(form.get(name));
        if (url.pathname.startsWith(config.mount + '/connected-accounts/')) {
          posts.push({ ...hop, action: form.get('action'), csrf: form.get('csrf'), fields: [...form.keys()] });
        }
      }
    }
    if (message.method === 'Network.responseReceived') {
      const response = message.params.response, url = new URL(response.url);
      captureHeaders(response.headers);
      if (message.params.type === 'Document') documents.set(message.sessionId, { status: response.status, headers: response.headers });
      if (url.origin === config.origin && url.pathname.startsWith(config.mount + '/assets/')) assets.set(url.pathname, { status: response.status, type: header(response.headers, 'content-type') });
    }
  } catch { captureFailed = true; }
  if (!message.id) return;
  const call = pending.get(message.id); if (!call) return;
  pending.delete(message.id); clearTimeout(call.timer);
  if (message.error) call.reject(new BrowserProtocolError(call.method, message.error)); else call.resolve(message.result);
});

function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('browser command timed out')); }, 20000);
    pending.set(id, { resolve, reject, timer, method });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(tab, fn, args) {
  const result = await command('Runtime.evaluate', { expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true }, tab);
  if (result.exceptionDetails) throw new Error('browser evaluation failed');
  return result.result.value;
}
async function waitFor(read, timeout = 20000) { await waitForRead(read, { timeout }); }
async function page(contextId) {
  const { targetId } = await command('Target.createTarget', { url: 'about:blank', browserContextId: contextId });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Network', 'Runtime']) await command(domain + '.enable', domain === 'Network' ? { maxPostDataSize: 16384 } : {}, sessionId);
  return sessionId;
}
async function navigate(tab, url, selector) {
  await evaluate(tab, () => { window.connectedNavigating = true; });
  documents.delete(tab);
  const result = await command('Page.navigate', { url }, tab);
  assert.ok(!result.errorText, 'trusted navigation failed');
  await waitFor(() => evaluate(tab, selector => !window.connectedNavigating && document.readyState === 'complete' && !!document.querySelector(selector), selector));
}
async function click(tab, selector) {
  await command('Page.bringToFront', {}, tab);
  const point = await evaluate(tab, selector => {
    const element = document.querySelector(selector);
    if (!element) throw new Error('missing action');
    element.scrollIntoView({ block: 'center' });
    const box = element.getBoundingClientRect();
    return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  }, selector);
  for (const type of ['mousePressed', 'mouseReleased']) await command('Input.dispatchMouseEvent', { type, button: 'left', clickCount: 1, ...point }, tab);
}
async function cookies(contextId) {
  const { cookies } = await command('Storage.getCookies', { browserContextId: contextId });
  cookies.forEach(captureCookie); return cookies;
}
async function access(contextId, label) {
  const current = await cookies(contextId);
  const value = current.find(cookie => cookie.name === 'AUTHP_ACCESS_TOKEN');
  assert.ok(value?.value && value.secure && value.httpOnly, 'completed login omitted private access cookie');
  if (label) record({ kind: 'login', label, token: value.value, session: current.find(cookie => cookie.name === 'AUTHP_SESSION_ID')?.value || '' });
  return value.value;
}
function pagePolicy(tab) {
  const response = documents.get(tab);
  assert.ok(response?.status === 200 && header(response.headers, 'content-type').startsWith('text/html') &&
    header(response.headers, 'cache-control').includes('no-store') && header(response.headers, 'referrer-policy') === 'strict-origin' &&
    header(response.headers, 'content-security-policy').includes("form-action 'self'") && header(response.headers, 'content-security-policy').includes("frame-ancestors 'none'"),
  'connected HTML lost status, cache or browser origin policy');
}
async function layout(tab) {
  for (const width of [390, 1280]) {
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 }, tab);
    assert.ok(await evaluate(tab, async () => {
      await document.fonts.ready;
      return document.documentElement.scrollWidth <= innerWidth + 1 &&
        [...document.querySelectorAll('button,input:not([type="hidden"]),.connection-card')].filter(element => element.getClientRects().length).every(element => {
          const box = element.getBoundingClientRect(); return box.left >= -0.5 && box.right <= innerWidth + 0.5;
        });
    }), 'connected form overflowed viewport');
  }
}
async function operation(tab) {
  const result = await evaluate(tab, () => {
    const form = document.querySelector('.connection-card form');
    const fields = form?.querySelectorAll('input[name="csrf"]');
    const action = form?.getAttribute('action');
    // The protocol's controls named "action" shadow HTMLFormElement.action.
    return form && fields.length === 1 && action ? {
      method: form.method, action: new URL(action, document.baseURI).href, csrf: fields[0].value,
    } : null;
  });
  assert.ok(result && result.method === 'post' && result.csrf.length === 48, 'connection form fields changed');
  const url = new URL(result.action);
  assert.ok(url.origin === config.origin && url.pathname.startsWith(config.mount + '/connected-accounts/') &&
    url.pathname.slice((config.mount + '/connected-accounts/').length).length === 48 && !url.search && !url.hash && !url.username && !url.password,
  'connection action escaped exact mounted ticket');
  secret(result.csrf); captureURL(result.action); return result;
}

function totp(counter) {
  // The Go fixture stores this seed as raw UTF-8 key bytes, not Base32 text.
  const challenge = Buffer.alloc(8); challenge.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', Buffer.from(input.totpSecret, 'utf8')).update(challenge).digest();
  const offset = digest[digest.length - 1] & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
async function factors(tab, contextId, phase) {
  stage = phase + ' password form';
  await waitFor(() => evaluate(tab, () => !!document.getElementById('secret')?.getClientRects().length));
  stage = phase + ' incomplete password authority';
  assert.ok(!(await cookies(contextId)).some(cookie => cookie.name === 'AUTHP_ACCESS_TOKEN'), 'password checkpoint prematurely issued access');
  stage = phase + ' password submission';
  await evaluate(tab, password => { const field = document.getElementById('secret'); field.value = password; field.form.requestSubmit(); }, input.password);
  stage = phase + ' TOTP form';
  await waitFor(() => evaluate(tab, () => !!document.getElementById('passcode')?.getClientRects().length));
  stage = phase + ' incomplete TOTP authority';
  assert.ok(!(await cookies(contextId)).some(cookie => cookie.name === 'AUTHP_ACCESS_TOKEN'), 'password bypassed required TOTP');
  stage = phase + ' fresh TOTP counter';
  await waitFor(() => Math.floor(Date.now() / 30000) > lastCounter, 35000);
  const counter = Math.floor(Date.now() / 30000), code = totp(counter); lastCounter = counter; secret(code);
  stage = phase + ' TOTP submission';
  await evaluate(tab, code => { const field = document.getElementById('passcode'); field.value = code; field.form.requestSubmit(); }, code);
}

async function captureFailureDiagnostics() {
  if (!activeTab) return;
  // Only fixed route categories, statuses and UI booleans leave the private
  // browser. Never report exception text, URLs, form values or cookie contents.
  const state = await evaluate(activeTab, ({ origin, mount }) => {
    const visible = id => !!document.getElementById(id)?.getClientRects().length;
    const route = location.origin !== origin ? 'other-origin' : location.pathname === mount + '/login' ? 'login' :
      location.pathname.startsWith(mount + '/sandbox/') ? 'sandbox' :
        location.pathname.startsWith(mount + '/connected-accounts') ? 'connection' : 'other-route';
    return { route, ready: document.readyState === 'complete', username: visible('username'), password: visible('secret'),
      totp: visible('passcode'), localRealm: document.querySelector('[name="realm"]')?.value === 'local',
      confirmation: !!document.querySelector('button[name="action"][value="connect"]') };
  }, { origin: config.origin, mount: config.mount });
  state.documentStatus = documents.get(activeTab)?.status || 0;
  state.runtimeExceptions = exceptionCount;
  state.captureFailed = captureFailed;
  failureDiagnostics = ' ' + JSON.stringify(state);
}

async function verifyPosts() {
  assert.equal(posts.length, 2, 'connection submitted an unexpected number of decisions');
  for (const [i, post] of posts.entries()) {
    await waitFor(() => (extras.get(post.key) || []).length > post.index);
    const info = extras.get(post.key)[post.index];
    assert.ok(header(info.headers, 'origin') === config.origin && header(info.headers, 'sec-fetch-site') === 'same-origin', 'native connection POST lost actual browser Origin');
    assert.ok(info.associatedCookies.some(item => item.cookie.name === 'AUTHP_SESSION_ID' && item.blockedReasons.length === 0) &&
      info.associatedCookies.some(item => item.cookie.name === 'AUTHP_ACCESS_TOKEN' && item.blockedReasons.length === 0), 'connection POST omitted actual authority cookies');
    assert.ok(post.fields.length === 2 && post.fields.includes('csrf') && post.fields.includes('action') && post.action === (i === 0 ? 'start' : 'connect'),
      'native connection POST changed protocol fields');
  }
}
function noExceptions() { assert.ok(exceptionCount === 0 && !captureFailed, 'asynchronous browser exception or evidence failure'); }

(async () => {
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true }); });
  try {
    const { browserContextId } = await command('Target.createBrowserContext'); contexts.add(browserContextId);
    const tab = await page(browserContextId);
    activeTab = tab;
    stage = 'TLS negative control';
    const untrusted = await command('Page.navigate', { url: config.untrustedURL }, tab);
    assert.ok(untrusted.errorText?.startsWith('net::ERR_CERT_'), 'browser accepted untrusted TLS');
    stage = 'automatic external navigation';
    await navigate(tab, config.origin + config.mount + '/oauth2/upstream', 'a[href*="connected-accounts"]');
    stage = 'automatic external access cookie';
    const automatic = await access(browserContextId, 'automatic');
    stage = 'portal mounted connection link';
    assert.ok(await evaluate(tab, mount => {
      const links = [...document.querySelectorAll('a')].filter(link => new URL(link.href).pathname === mount + '/connected-accounts');
      if (links.length !== 1) return false;
      const url = new URL(links[0].href);
      return url.origin === location.origin && !url.search && !url.hash && !url.username && !url.password;
    }, config.mount), 'portal omitted its actual mounted connection link');
    stage = 'automatic account connection page';
    await click(tab, 'a[href*="connected-accounts"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="action"][value="start"]')));
    stage = 'connection start page policy and layout';
    pagePolicy(tab); await layout(tab);
    stage = 'connection start form';
    const op = await operation(tab);
    for (const [suffix, media] of [['/assets/css/connected_accounts.css', 'text/css'], ['/assets/images/favicon.svg', 'image/svg+xml']]) {
      stage = media === 'text/css' ? 'connection stylesheet' : 'connection favicon';
      await waitFor(() => assets.has(config.mount + suffix));
      const asset = assets.get(config.mount + suffix);
      assert.ok(asset.status === 200 && asset.type.startsWith(media), 'connection asset failed its mounted media contract');
    }
    stage = 'native connection start';
    await click(tab, '.connection-card button[type="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.getElementById('username')));
    assert.ok(await evaluate(tab, ({ action, mount }) => {
      const form = document.getElementById('username').form, url = new URL(form.action);
      const script = document.querySelector('script[src$="/login.js"]');
      return url.origin === location.origin && url.pathname === mount + '/login' && url.searchParams.get('fresh') === '1' &&
        url.searchParams.get('redirect_url') === action && script?.dataset.returnUrl === action && !script.dataset.whoami;
    }, { action: op.action, mount: config.mount }), 'fresh login lost the exact connection destination or installed watcher');
    stage = 'bound local authenticator choice';
    await click(tab, "#authenticators a[onclick^=\"showLoginForm('local',\"]");
    await waitFor(() => evaluate(tab, () => !!document.getElementById('username')?.getClientRects().length &&
      document.querySelector('[name="realm"]')?.value === 'local'));
    stage = 'bound local username submission';
    await evaluate(tab, () => {
      document.getElementById('username').value = 'alice';
      document.getElementById('username').form.requestSubmit();
    });
    await factors(tab, browserContextId, 'bound local');
    stage = 'bound local confirmation return';
    await waitFor(() => evaluate(tab, () => !!document.querySelector('button[name="action"][value="connect"]')));
    stage = 'connection confirmation page policy and layout';
    pagePolicy(tab); await layout(tab);
    stage = 'connection confirmation form';
    const review = await operation(tab);
    assert.ok(review.action === op.action && review.csrf === op.csrf, 'confirmation changed the operation');
    assert.ok(await evaluate(tab, () => document.querySelector('.connection-card').textContent.includes('upstream → alice') &&
      document.querySelector('.connection-card').textContent.includes('Profile data and files from the automatically created identity stay with that identity.') &&
      !!document.querySelector('button[name="action"][value="cancel"]')), 'confirmation omitted identity, cancellation or non-migration warning');
    stage = 'local confirmation access cookie';
    const localAccess = await access(browserContextId, 'local-confirmation');
    assert.notEqual(localAccess, automatic, 'local proof reused external access');
    stage = 'explicit native confirmation';
    await click(tab, 'button[name="action"][value="connect"]');
    await waitFor(() => evaluate(tab, () => document.querySelector('[role="status"]')?.textContent.includes('Account connected.')));
    pagePolicy(tab);
    assert.ok(await evaluate(tab, mount => [...document.querySelectorAll('a')].some(link => {
      const url = new URL(link.href); return url.origin === location.origin && url.pathname === mount + '/login' && url.searchParams.get('fresh') === '1';
    }), config.mount), 'connection result omitted fresh sign-in');
    stage = 'fresh connected external authentication';
    await click(tab, 'a[href*="fresh=1"]');
    await waitFor(() => evaluate(tab, () => !!document.getElementById('username')));
    const providerSelector = 'a[href*="oauth2/upstream"]';
    assert.ok(await evaluate(tab, ({ selector, mount }) => {
      const link = document.querySelector(selector); if (!link) return false;
      const url = new URL(link.href); return url.origin === location.origin && url.pathname === mount + '/oauth2/upstream';
    }, { selector: providerSelector, mount: config.mount }), 'fresh local page omitted provider choice');
    await click(tab, providerSelector);
    await factors(tab, browserContextId, 'connected external');
    stage = 'connected external portal return';
    await waitFor(() => evaluate(tab, mount => location.pathname === mount + '/portal' && document.readyState === 'complete', config.mount));
    await access(browserContextId, 'connected-external');
    assert.ok(!(await cookies(browserContextId)).some(cookie => /_(REFRESH_TOKEN|OIDC_SESSION_ID)$/.test(cookie.name)),
      'external local factors acquired refresh or local-only OP cookie');
    stage = 'connected protected resource';
    await navigate(tab, config.origin + '/resource', 'body');
    assert.equal(await evaluate(tab, () => document.body.textContent.trim()), 'identity resource', 'connected identity did not authorize resource');
    stage = 'established connected account list';
    await navigate(tab, config.origin + config.mount + '/connected-accounts/', '.connection-card');
    pagePolicy(tab);
    assert.ok(await evaluate(tab, () => document.querySelector('.connection-card').textContent.includes('alice') &&
      document.querySelector('.connection-card li')?.textContent.includes('upstream') && !document.querySelector('input[value="start"]')),
    'established connection did not render immutable local account');
    stage = 'native connection POST evidence';
    await verifyPosts(); noExceptions(); record({ kind: 'complete' });
  } catch (error) {
    try { await captureFailureDiagnostics(); }
    catch { failureDiagnostics = ' {"diagnosticsUnavailable":true}'; }
    throw error;
  } finally {
    try { await disposeBrowserContexts(command, contexts); noExceptions(); }
    finally { socket.close(); fs.closeSync(evidence); }
  }
  process.stdout.write('Connected accounts browser passed\n');
})().catch(() => { console.error('Connected accounts browser failed at ' + stage + failureDiagnostics); socket.close(); process.exitCode = 1; });
