// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Actual Caddy, TLS trust, local users and the signing SAML IdP belong to Go.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { BrowserProtocolError, waitForRead } = require('./authorization_redirect_cdp.cjs');
const { disposeBrowserContexts } = require('./browser_contexts.cjs');

const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const password = fs.readFileSync(0, 'utf8');
const socket = new WebSocket(endpoint);
const pending = new Map();
const contexts = new Set();
const documents = new Map();
const requestExtras = new Map();
const callbacks = [];
const localPosts = [];
const secrets = new Set([password]);
const exceptions = [];
let exceptionCount = 0;
let sequence = 0;
let stage = 'connect';

function header(headers, name) {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1] || '';
}

function secretCookie(cookie) {
  return cookie.name === config.sandboxCookieName || cookie.name.startsWith(config.sandboxCookieName + '_') ||
    cookie.name === config.accessCookieName || /_(REFRESH_TOKEN|OIDC_SESSION_ID)$/.test(cookie.name) ||
    cookie.name.startsWith('AUTHP_SAML_SESSION_ID_');
}

function collectCookie(cookie) {
  if (secretCookie(cookie) && cookie.value && cookie.value !== 'delete') secrets.add(cookie.value);
}

socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Runtime.exceptionThrown') {
    exceptionCount++;
    if (exceptions.length < 8) {
      const details = message.params.exceptionDetails;
      exceptions.push({ stage, category: 'uncaught-script', line: details.lineNumber, column: details.columnNumber });
    }
  }
  if (message.method === 'Network.responseReceived' && message.params.type === 'Document') {
    documents.set(message.sessionId, { status: message.params.response.status });
  }
  if (message.method === 'Network.requestWillBeSentExtraInfo') {
    const info = message.params;
    for (const item of info.associatedCookies || []) collectCookie(item.cookie);
    // This private map is never serialized to diagnostics. It is needed to
    // observe the actual browser-sent SameSite/Origin contract, not alter it.
    const key = message.sessionId + ':' + info.requestId;
    const entries = requestExtras.get(key) || [];
    entries.push(info);
    requestExtras.set(key, entries);
  }
  if (message.method === 'Network.requestWillBeSent') {
    const request = message.params.request;
    const target = new URL(request.url);
    if (target.origin === config.origin && request.method === 'POST' &&
      (target.pathname === config.mount + '/login' || target.pathname.startsWith(config.mount + '/sandbox/'))) {
      localPosts.push({ sameOrigin: header(request.headers, 'origin') === config.origin,
        key: message.sessionId + ':' + message.params.requestId });
    }
    if (config.mode === 'saml' && target.origin === config.origin &&
      target.pathname === config.mount + '/saml/cross-device' && request.method === 'POST') {
      const form = new URLSearchParams(request.postData || '');
      const state = form.get('RelayState') || '';
      const response = form.get('SAMLResponse') || '';
      if (state) secrets.add(state);
      if (response) secrets.add(response);
      callbacks.push({ key: message.sessionId + ':' + message.params.requestId, state,
        signedResponsePresent: !!response, singleFields: form.getAll('RelayState').length === 1 && form.getAll('SAMLResponse').length === 1,
        status: 0 });
    }
    if (message.params.redirectResponse) {
      const previous = new URL(message.params.redirectResponse.url);
      if (config.mode === 'saml' && previous.origin === config.origin &&
        previous.pathname === config.mount + '/saml/cross-device') {
        const callback = callbacks.find(item => item.key === message.sessionId + ':' + message.params.requestId);
        if (callback) callback.status = message.params.redirectResponse.status;
      }
    }
  }
  if (!message.id) return;
  const entry = pending.get(message.id);
  if (!entry) return;
  pending.delete(message.id);
  clearTimeout(entry.timer);
  if (message.error) entry.reject(new BrowserProtocolError(entry.method, message.error));
  else entry.resolve(message.result);
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
  const result = await command('Runtime.evaluate', {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true,
  }, tab);
  if (result.exceptionDetails) throw new Error('browser evaluation failed');
  return result.result.value;
}

async function waitFor(read) { await waitForRead(read, { timeout: 20000 }); }

async function context() {
  const { browserContextId } = await command('Target.createBrowserContext');
  contexts.add(browserContextId);
  return browserContextId;
}

async function page(contextId) {
  const { targetId } = await command('Target.createTarget', { url: 'about:blank', browserContextId: contextId });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Network', 'Runtime']) {
    await command(domain + '.enable', domain === 'Network' ? { maxPostDataSize: 128 * 1024 } : {}, sessionId);
  }
  return sessionId;
}

async function cookies(contextId) {
  const result = await command('Storage.getCookies', { browserContextId: contextId });
  result.cookies.forEach(collectCookie);
  return result.cookies;
}

async function navigate(tab, url, selector) {
  await evaluate(tab, () => { window.destinationNavigating = true; });
  documents.delete(tab);
  const result = await command('Page.navigate', { url }, tab);
  assert.ok(!result.errorText, 'trusted browser navigation failed');
  if (selector) {
    await waitFor(() => evaluate(tab, selector => !window.destinationNavigating && document.readyState === 'complete' &&
      !!document.querySelector(selector), selector));
  }
}

function destination(label) {
  // The URL carries an encoded slash, an encoded ampersand and a fragment.
  // All destinations cross the real gatekeeper's protected /resource route.
  // AuthCrunch removes protocol-only fields through url.Values.Encode, which
  // sorts query keys. Start with that canonical order while keeping every
  // encoded value and the fragment part of the exact destination assertion.
  return config.origin + '/resource?path=one%2Ftwo&tab=' + label + '&value=left%26right#section%202';
}

function loginURL(target, fresh) {
  const url = new URL(config.origin + config.mount + '/login');
  url.searchParams.set('redirect_url', target);
  if (fresh) url.searchParams.set('fresh', '1');
  return url.href;
}

async function loginPage(tab, target, fresh) {
  await navigate(tab, loginURL(target, fresh), '#username');
  assert.ok(await evaluate(tab, ({ target, fresh, mount }) => {
    const form = document.getElementById('username').form;
    const action = new URL(form.action);
    const script = document.querySelector('script[src$="/login.js"]');
    return form.method === 'post' && action.origin === location.origin && action.pathname === mount + '/login' &&
      action.searchParams.get('redirect_url') === target && (action.searchParams.get('fresh') === '1') === fresh &&
      script?.dataset.returnUrl === target && !!script.dataset.whoami === !fresh;
  }, { target, fresh, mount: config.mount }), 'login page lost its own destination or freshness');
}

async function checkpoint(tab, contextId) {
  await command('Page.bringToFront', {}, tab);
  await evaluate(tab, () => {
    const input = document.getElementById('username');
    input.value = 'alice';
    input.form.requestSubmit();
  });
  await waitFor(() => evaluate(tab, () => !!document.getElementById('secret') && document.readyState === 'complete'));
  const id = await evaluate(tab, mount => {
    const prefix = mount + '/sandbox/';
    return location.pathname.startsWith(prefix) ? location.pathname.slice(prefix.length).split('/')[0] : '';
  }, config.mount);
  assert.ok(/^[A-Za-z0-9]{36,47}$/.test(id), 'password checkpoint omitted a canonical sandbox identifier');
  assert.ok(await evaluate(tab, ({ origin, mount, id }) => {
    const form = document.getElementById('secret').form;
    const action = new URL(form.action);
    return location.origin === origin && form.method === 'post' && action.origin === origin &&
      action.pathname.startsWith(mount + '/sandbox/' + id + '/');
  }, { origin: config.origin, mount: config.mount, id }), 'password form left its own same-origin transaction');
  const proof = (await cookies(contextId)).find(cookie => cookie.name === config.sandboxCookieName + '_' + id);
  assert.ok(proof && proof.secure && proof.httpOnly && proof.sameSite === 'Lax' &&
    proof.domain === new URL(config.origin).hostname && proof.path === (config.mount || '/') &&
    !proof.session && proof.expires > Date.now() / 1000 && proof.expires <= Date.now() / 1000 + 310,
  'browser did not retain a private, mounted, short-lived transaction proof');
  return { id, name: proof.name, value: proof.value };
}

async function protectedDestination(tab, target) {
  await waitFor(() => evaluate(tab, target => location.href === target && document.readyState === 'complete' &&
    document.body.textContent.trim() === 'identity resource', target));
  assert.equal(documents.get(tab)?.status, 200, 'destination was not actually authorized');
}

async function finish(tab, contextId, target) {
  await command('Page.bringToFront', {}, tab);
  await evaluate(tab, password => {
    const input = document.getElementById('secret');
    input.value = password;
    input.form.requestSubmit();
  }, password);
  await protectedDestination(tab, target);
  const issued = await cookies(contextId);
  const access = issued.find(cookie => cookie.name === config.accessCookieName);
  assert.ok(access?.secure && access.httpOnly && access.path === '/', 'successful login omitted its private usable access cookie');
  return issued;
}

async function overlappingCheckpoints() {
  const contextId = await context();
  const a = await page(contextId);
  const b = await page(contextId);
  const targetA = destination('A');
  const targetB = destination('B');
  stage = 'first tab password checkpoint';
  await loginPage(a, targetA, true);
  const proofA = await checkpoint(a, contextId);
  stage = 'second tab password checkpoint';
  await loginPage(b, targetB, true);
  const proofB = await checkpoint(b, contextId);
  assert.ok(proofA.id !== proofB.id && proofA.value !== proofB.value, 'parallel starts shared transaction proof');
  assert.ok(await evaluate(a, () => !!document.getElementById('secret')) &&
    await evaluate(b, () => !!document.getElementById('secret')), 'both tabs were not at password checkpoints together');
  const before = await cookies(contextId);
  assert.ok(before.some(cookie => cookie.name === proofA.name && cookie.value === proofA.value) &&
    before.some(cookie => cookie.name === proofB.name && cookie.value === proofB.value) &&
    !before.some(cookie => cookie.name === config.accessCookieName), 'second start replaced first proof or issued premature access');
  stage = 'complete second tab before first';
  const afterB = await finish(b, contextId, targetB);
  assert.ok(!afterB.some(cookie => cookie.name === proofB.name) &&
    afterB.some(cookie => cookie.name === proofA.name && cookie.value === proofA.value), 'second completion did not delete only its transaction proof');
  stage = 'complete first pending tab';
  const afterA = await finish(a, contextId, targetA);
  assert.ok(!afterA.some(cookie => cookie.name === proofA.name || cookie.name === proofB.name), 'completed transactions retained their browser proofs');
  await protectedDestination(b, targetB);
  await cookies(contextId);
  await disposeBrowserContexts(command, new Set([contextId]));
  contexts.delete(contextId);
}

async function waitingPages() {
  const contextId = await context();
  const waiting = await page(contextId);
  const fresh = await page(contextId);
  const signer = await page(contextId);
  const ordinaryTarget = destination('waiting');
  const freshTarget = destination('fresh');
  stage = 'ordinary and fresh waiting pages';
  await loginPage(waiting, ordinaryTarget, false);
  await loginPage(fresh, freshTarget, true);
  await loginPage(signer, destination('signer'), true);
  await checkpoint(signer, contextId);
  await finish(signer, contextId, destination('signer'));
  stage = 'ordinary waiting page observes actual other-tab session';
  await command('Page.bringToFront', {}, waiting);
  await protectedDestination(waiting, ordinaryTarget);
  stage = 'fresh waiting page requires its own password';
  await command('Page.bringToFront', {}, fresh);
  assert.ok(await evaluate(fresh, () => !!document.getElementById('username') &&
    !document.querySelector('script[src$="/login.js"]').dataset.whoami), 'fresh page accepted another tab login');
  // Submit the original fresh page while the other tab's access cookie exists.
  // Reloading fresh=1 here would delete it and miss the real waiting-tab case.
  await checkpoint(fresh, contextId);
  await finish(fresh, contextId, freshTarget);
}

async function crossSiteSAML() {
  const contextId = await context();
  const tab = await page(contextId);
  const target = destination('saml');
  stage = 'SAML login page provider-link lookup';
  // Provider endpoints may be authored relative to the mounted login page.
  // Inspect the resolved URL below before following the ordinary UI link.
  await navigate(tab, loginURL(target, false), 'a[href*="saml/cross-device"]');
  stage = 'SAML resolved provider-link validation';
  const link = await evaluate(tab, () => document.querySelector('a[href*="saml/cross-device"]').href);
  const provider = new URL(link);
  assert.ok(provider.origin === config.origin && provider.pathname === config.mount + '/saml/cross-device' &&
    provider.searchParams.get('redirect_url') === target, 'rendered SAML link lost its bound destination');
  // The normal link loads the real IdP. Its signed auto-submit form performs
  // the cross-site POST with Chrome's own cookies, Origin and fetch metadata.
  stage = 'SAML provider navigation and signed browser POST';
  await evaluate(tab, () => document.querySelector('a[href*="saml/cross-device"]').click());
  await waitFor(() => callbacks.length === 1);
  stage = 'SAML callback final protected authorization';
  await protectedDestination(tab, target);
  await cookies(contextId);
  stage = 'SAML cross-site cookie and callback evidence';
  await waitFor(() => callbacks.length === 1 && requestExtras.has(callbacks[0].key));
  const callback = callbacks[0];
  const extra = requestExtras.get(callback.key).find(item => header(item.headers, 'origin') === config.idpOrigin);
  assert.ok(callback.signedResponsePresent && callback.singleFields && /^[A-Za-z0-9_-]{43}$/.test(callback.state) &&
    Buffer.from(callback.state, 'base64url').toString('base64url') === callback.state && callback.status === 303 &&
    extra && header(extra.headers, 'origin') === config.idpOrigin && header(extra.headers, 'sec-fetch-site') === 'cross-site',
  'SAML did not complete one actual cross-site signed POST');
  const stateCookie = (extra.associatedCookies || []).filter(item => item.cookie.name === 'AUTHP_SAML_SESSION_ID_' + callback.state);
  assert.ok(stateCookie.length === 1 && stateCookie[0].blockedReasons.length === 0 &&
    stateCookie[0].cookie.secure && stateCookie[0].cookie.httpOnly && stateCookie[0].cookie.sameSite === 'None' &&
    stateCookie[0].cookie.domain === new URL(config.origin).hostname && stateCookie[0].cookie.path === '/',
  'cross-site callback omitted its private canonical transaction cookie');
  const after = await cookies(contextId);
  assert.ok(!after.some(cookie => cookie.name === 'AUTHP_SAML_SESSION_ID_' + callback.state) &&
    after.some(cookie => cookie.name === config.accessCookieName && cookie.secure && cookie.httpOnly),
  'verified SAML callback did not consume its binding and issue access');
}

function noExceptions() {
  assert.ok(exceptionCount === 0, 'asynchronous browser exceptions: ' + JSON.stringify(exceptions));
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  try {
    if (config.mode === 'local') {
      await overlappingCheckpoints();
      await waitingPages();
      assert.ok(localPosts.length === 8 && localPosts.every(item => item.sameOrigin ||
        (requestExtras.get(item.key) || []).some(info => header(info.headers, 'origin') === config.origin)),
      'local forms did not preserve actual same-origin browser submission');
    } else {
      assert.equal(config.mode, 'saml', 'unknown browser scenario');
      await crossSiteSAML();
    }
    noExceptions();
  } finally {
    try {
      try { for (const contextId of contexts) await cookies(contextId); }
      finally { fs.writeFileSync(config.secretFile, JSON.stringify([...secrets]), { mode: 0o600, flag: 'wx' }); }
    } finally {
      try { await disposeBrowserContexts(command, contexts); noExceptions(); }
      finally { socket.close(); }
    }
  }
  process.stdout.write(JSON.stringify({ passed: true }));
})().catch(error => {
  // Assertions have fixed labels; unknown exceptions can contain protocol data.
  const reason = error instanceof assert.AssertionError || error instanceof BrowserProtocolError ||
    ['browser condition timed out', 'browser command timed out', 'browser evaluation failed', 'browser socket failed'].includes(error.message)
    ? error.message : 'browser fixture failed';
  process.stderr.write(stage + ': ' + reason + '\n');
  process.exitCode = 1;
});
