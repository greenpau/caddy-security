// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Real form sessions and the selected portable Web Crypto consumer, over TLS.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { BrowserProtocolError, waitForRead } = require('./authorization_redirect_cdp.cjs');
const { disposeBrowserContexts } = require('./browser_contexts.cjs');

const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const evidence = fs.openSync(config.evidenceFile, 'wx', 0o600);
const socket = new WebSocket(endpoint);
const pending = new Map(), contexts = new Set(), requests = new Map(), requestExtras = new Map(), responseExtras = new Map();
const captures = new Set(), secrets = new Set(), cryptoSecrets = new Set();
let sequence = 0, evidenceBytes = 0, wireBytes = 0, exceptionCount = 0, captureFailed = false;
let stage = 'connect';
const marker = 'Private browser document payload remains encrypted in transit';
const filename = 'private-budget-browser-qualification.txt';
const emptyFilename = 'private-empty-browser-qualification.txt';

function record(value) {
  const line = JSON.stringify({ version: 1, ...value }) + '\n';
  evidenceBytes += Buffer.byteLength(line);
  if (evidenceBytes > 128 * 1024) throw new Error('private evidence exceeded its bound');
  fs.writeSync(evidence, line);
}

function secret(value, encoding = 'utf8', cryptographic = false) {
  if (typeof value !== 'string' || !value) return;
  if (!secrets.has(value)) { secrets.add(value); record({ kind: 'secret', encoding, value }); }
  if (cryptographic) cryptoSecrets.add(value);
}

for (const password of Object.values(input.credentials)) secret(password);
for (const value of [marker, filename, emptyFilename]) secret(value, 'utf8', true);
for (const value of input.recovery || []) secret(value.recoveryKey, 'base64url', true);

function header(headers, name) {
  return Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name)?.[1] || '';
}

function credential(cookie) {
  return cookie.name === 'AUTHP_ACCESS_TOKEN' || cookie.name.startsWith('AUTHP_SANDBOX_ID') ||
    /_(REFRESH_TOKEN|OIDC_SESSION_ID)$/.test(cookie.name);
}

function captureCookie(cookie) {
  if (credential(cookie) && cookie.value && cookie.value !== 'delete') secret(cookie.value);
}

function wire(value) {
  wireBytes += Buffer.byteLength(value);
  if (wireBytes > 16 * 1024 * 1024) throw new Error('Documents wire capture exceeded its bound');
  return value;
}

function background(work) {
  const task = work.catch(() => { captureFailed = true; }).finally(() => captures.delete(task));
  captures.add(task);
}

socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data);
  const key = message.sessionId + ':' + message.params?.requestId;
  try {
    if (message.method === 'Runtime.exceptionThrown') exceptionCount++;
    if (message.method === 'Network.requestWillBeSentExtraInfo') {
      for (const item of message.params.associatedCookies || []) captureCookie(item.cookie);
      requestExtras.set(key, message.params.headers);
      const request = requests.get(key);
      if (request) request.extra = message.params.headers;
    }
    if (message.method === 'Network.responseReceivedExtraInfo') {
      responseExtras.set(key, message.params.headers);
      const request = requests.get(key);
      if (request) request.responseExtra = message.params.headers;
    }
    if (message.method === 'Network.requestWillBeSent') {
      const request = message.params.request;
      const url = new URL(request.url);
      if (url.origin === config.origin && url.pathname.startsWith(config.mount + '/api/documents/')) {
        const item = { url: wire(request.url), method: request.method, headers: request.headers, extra: requestExtras.get(key),
          body: wire(request.postData || ''), response: '', responseExtra: responseExtras.get(key), status: 0, complete: false };
        requests.set(key, item);
        if (request.hasPostData && !request.postData) background((async () => {
          const result = await command('Network.getRequestPostData', { requestId: message.params.requestId }, message.sessionId);
          item.body = wire(result.postData);
        })());
      }
    }
    if (message.method === 'Network.responseReceived') {
      const item = requests.get(key);
      if (item) {
        item.status = message.params.response.status;
        item.responseHeaders = message.params.response.headers;
        item.hasResponseExtra = message.params.hasExtraInfo;
      }
    }
    if (message.method === 'Network.loadingFinished' && requests.has(key)) {
      const item = requests.get(key);
      background((async () => {
        const result = await command('Network.getResponseBody', { requestId: message.params.requestId }, message.sessionId);
        item.response = wire(result.base64Encoded ? Buffer.from(result.body, 'base64').toString('utf8') : result.body);
        item.complete = true;
      })());
    }
  } catch { captureFailed = true; }
  if (!message.id) return;
  const call = pending.get(message.id);
  if (!call) return;
  pending.delete(message.id); clearTimeout(call.timer);
  if (message.error) call.reject(new BrowserProtocolError(call.method, message.error));
  else call.resolve(message.result);
});

function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('browser command timed out')); }, 25000);
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

async function page() {
  const { browserContextId } = await command('Target.createBrowserContext');
  contexts.add(browserContextId);
  const { targetId } = await command('Target.createTarget', { url: 'about:blank', browserContextId });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Runtime']) await command(domain + '.enable', {}, sessionId);
  await command('Network.enable', { maxPostDataSize: 2 * 1024 * 1024, maxTotalBufferSize: 16 * 1024 * 1024,
    maxResourceBufferSize: 2 * 1024 * 1024 }, sessionId);
  return { tab: sessionId, context: browserContextId };
}

async function navigate(tab, url) {
  const result = await command('Page.navigate', { url }, tab);
  assert.ok(!result.errorText, 'verified TLS navigation failed');
  await waitForRead(() => evaluate(tab, url => location.href === url &&
    document.readyState === 'complete', url));
}

async function login(account) {
  stage = account + ' natural form login';
  const p = await page();
  const rejected = await command('Page.navigate', { url: config.untrustedURL }, p.tab);
  assert.ok(/ERR_CERT_/.test(rejected.errorText || ''), 'untrusted TLS accepted');
  await navigate(p.tab, config.origin + config.mount + '/login');
  await evaluate(p.tab, () => {
    const username = document.querySelector('input[name="username"]');
    if (username?.getClientRects().length) return;
    const action = [...document.querySelectorAll('#authenticators a')].find(link => link.textContent.trim() === 'Local');
    if (!action) throw new Error('local login action absent');
    action.click();
  });
  await waitForRead(() => evaluate(p.tab, () => document.querySelector('input[name="username"]')?.getClientRects().length &&
    document.querySelector('[name="realm"]')?.value === 'local'));
  await evaluate(p.tab, account => {
    const field = document.querySelector('input[name="username"]');
    field.value = account;
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.form.requestSubmit();
  }, account);
  await waitForRead(() => evaluate(p.tab, mount => location.pathname.startsWith(mount + '/sandbox/') &&
    document.querySelector('input[name="secret"][type="password"]')?.getClientRects().length, config.mount));
  for (const cookie of (await command('Storage.getCookies', { browserContextId: p.context })).cookies) captureCookie(cookie);
  await evaluate(p.tab, password => {
    const field = document.querySelector('input[name="secret"][type="password"]');
    field.value = password;
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.form.requestSubmit();
  }, input.credentials[account]);
  await waitForRead(() => evaluate(p.tab, mount => location.pathname === mount + '/portal' &&
    document.readyState === 'complete', config.mount));
  const cookies = (await command('Storage.getCookies', { browserContextId: p.context })).cookies;
  for (const cookie of cookies) captureCookie(cookie);
  const access = cookies.find(cookie => cookie.name === 'AUTHP_ACCESS_TOKEN');
  assert.ok(access?.value && access.secure && access.httpOnly, 'natural login omitted its private access cookie');
  record({ kind: 'login', account, access: access.value });
  assert.ok(!cookies.some(cookie => /_(REFRESH_TOKEN|OIDC_SESSION_ID)$/.test(cookie.name)), 'unexpected refresh or OP authority');
  const exposed = await evaluate(p.tab, () => JSON.stringify({ visible: document.cookie, local: Object.entries(localStorage),
    session: Object.entries(sessionStorage), url: location.href }));
  assert.ok(![...secrets].some(value => exposed.includes(value)), 'login credential escaped into browser-accessible state');
  await navigate(p.tab, config.fixtureURL);
  const ready = await evaluate(p.tab, install, { ...config, marker, filename, emptyFilename });
  assert.ok(ready.secure && ready.crypto, 'Documents consumer lacks a secure Web Crypto context');
  const bootstrap = await step(p, 'bootstrap');
  assert.ok(bootstrap.user_id === config.expectedUsers[account] && bootstrap.protocol === 'authcrunch-documents' &&
    bootstrap.chunk_size === 1048576 && /^[A-Za-z0-9_-]{43}$/.test(bootstrap.portal_id), 'Documents bootstrap identity/protocol changed');
  p.bootstrap = bootstrap;
  return p;
}

// This function executes in the authenticated page. No token is passed to it:
// fetch uses the natural HttpOnly cookie, real Origin and browser fetch metadata.
async function install(config) {
  const c = await import(config.cryptoURL);
  const state = { bootstrap: null, registration: null, privateKey: null, files: new Map(), calls: 0 };
  class ConsumerCheck extends Error {}
  const check = (condition, label) => { if (!condition) throw new ConsumerCheck(label); };
  async function rejected(fn) { try { await fn(); return false; } catch { return true; } }
  const endpoints = {
    bootstrap: ['GET', '/bootstrap'], fetchKey: ['GET', '/keys/fetch'], register: ['PUT', '/keys/register'],
    lookup: ['GET', '/key/{user}/lookup'], allocate: ['POST', '/files/allocate'], list: ['GET', '/files'],
    manifest: ['PUT', '/file/{id}/manifest'], put: ['PUT', '/file/{id}/chunk/{index}/put'],
    chunk: ['GET', '/file/{id}/chunk/{index}/fetch'], commit: ['POST', '/file/{id}/commit'],
    fetch: ['GET', '/file/{id}/fetch'], delete: ['DELETE', '/file/{id}/delete'],
    share: ['PUT', '/file/{id}/share/{user}/put'], shares: ['GET', '/file/{id}/share/list'],
    revoke: ['DELETE', '/file/{id}/share/{user}/delete'],
  };
  async function request(operation, params = {}, body, status = 200) {
    const [method, suffix] = endpoints[operation];
    const path = suffix.replace(/\{([^}]+)\}/g, (_, name) => encodeURIComponent(params[name]));
    state.calls++;
    const response = await fetch(config.origin + config.mount + '/api/documents' + path, {
      method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    });
    check(response.status === status, operation + ' HTTP ' + response.status + ', expected ' + status);
    check(response.headers.get('cache-control') === 'no-store' && response.headers.get('content-type') === 'application/json' &&
      response.headers.get('x-content-type-options') === 'nosniff' && response.headers.get('referrer-policy') === 'no-referrer', 'Documents response policy');
    const result = await response.json();
    check(result && typeof result === 'object' && !('operation' in result) && !('result' in result), 'direct resource response');
    if (status === 200 && ['register', 'manifest', 'put', 'commit', 'share', 'revoke', 'delete'].includes(operation)) {
      check(result.success === true && Object.keys(result).length === 1, 'mutation confirmation');
    }
    return result;
  }
  function plaintext(empty) {
    const bytes = new Uint8Array(empty ? 0 : c.chunkSize + 53);
    bytes.fill(91);
    if (!empty) bytes.set(new TextEncoder().encode(config.marker));
    return bytes;
  }
  async function unlock(recoveryKey) {
    state.registration = await request('fetchKey');
    state.privateKey = await c.unlock(state.bootstrap, state.registration, recoveryKey);
    check(state.privateKey.type === 'private' && !state.privateKey.extractable, 'private key must remain non-exportable');
  }
  async function decrypt(id, empty) {
    const file = await request('fetch', { id });
    const key = await c.unwrapKey(state.bootstrap, file, state.registration, state.privateKey);
    const metadata = await c.decryptMetadata(state.bootstrap, file, key);
    const expected = plaintext(empty);
    check(metadata.name === (empty ? config.emptyFilename : config.filename) && metadata.type === 'text/plain' &&
      metadata.size === expected.length && file.state === 'ready', 'decrypted metadata');
    const recovered = new Uint8Array(expected.length);
    for (let index = 0; index < file.chunks; index++) {
      const chunk = await request('chunk', { id, index });
      recovered.set(await c.decryptChunk(state.bootstrap, file, key, index, c.decode(chunk.ciphertext)), index * c.chunkSize);
    }
    check(recovered.length === expected.length && recovered.every((value, index) => value === expected[index]), 'decrypted document bytes');
    state.files.set(id, { file, key, empty });
    return { key: c.encode(key), chunks: file.chunks, size: file.size };
  }
  window.documentsStep = async ({ action, args }) => {
    try {
      let result;
      switch (action) {
        case 'bootstrap':
          result = state.bootstrap = await request('bootstrap'); break;
        case 'enroll':
          result = await c.enroll(state.bootstrap); state.registration = result.registration; break;
        case 'register':
          await request('register', {}, { key: state.registration }); await unlock(args.recoveryKey);
          result = { key_id: state.registration.key_id, public_key: state.registration.public_key }; break;
        case 'unlock':
          await unlock(args.recoveryKey); result = state.registration; break;
        case 'allocate': {
          const plain = plaintext(args.empty);
          const file = await request('allocate', {}, c.describeSize(plain.length));
          check(file.owner === state.bootstrap.user_id && file.state === 'uploading' &&
            file.chunks === (args.empty ? 1 : 2) && file.size === plain.length + file.chunks * 16, 'allocated descriptor');
          const upload = await c.prepareUpload(state.bootstrap, file, state.registration,
            { name: args.empty ? config.emptyFilename : config.filename, type: 'text/plain', size: plain.length });
          const key = await c.unwrapKey(state.bootstrap, { ...file, ...upload.manifest }, state.registration, state.privateKey);
          state.files.set(file.id, { file, upload, key, empty: args.empty, encrypted: [] });
          result = { id: file.id, key: c.encode(key) }; break;
        }
        case 'upload': {
          const item = state.files.get(args.id);
          const plain = plaintext(item.empty);
          await request('manifest', { id: args.id }, { manifest: item.upload.manifest });
          await request('commit', { id: args.id }, undefined, 409);
          for (let index = 0; index < item.file.chunks; index++) {
            const part = plain.slice(index * c.chunkSize, (index + 1) * c.chunkSize);
            const work = item.upload.encryptChunk(index, part);
            part.fill(0);
            check(await rejected(() => item.upload.encryptChunk(index, part)), 'repeated chunk nonce accepted');
            const ciphertext = item.encrypted[index] = await work;
            const payload = { ciphertext: c.encode(ciphertext) };
            await request('put', { id: args.id, index }, payload);
            await request('put', { id: args.id, index }, payload);
            if (index === 0) {
              const changed = ciphertext.slice(); changed[0] ^= 1;
              await request('put', { id: args.id, index }, { ciphertext: c.encode(changed) }, 409);
            }
          }
          item.upload.dispose();
          await request('commit', { id: args.id });
          result = true; break;
        }
        case 'decrypt': result = await decrypt(args.id, args.empty); break;
        case 'lookup': result = await request('lookup', { user: args.user }); break;
        case 'share': {
          const item = state.files.get(args.id), recipient = { ...args.recipient }, key = item.key.slice();
          const work = c.wrapKey(state.bootstrap, item.file, recipient, key);
          key.fill(0); recipient.public_key = 'changed after starting wrap';
          result = await work;
          await request('share', { id: args.id, user: args.recipient.user_id }, { envelope: result }); break;
        }
        case 'deny':
          await request(args.operation, args.params, args.body, 404); result = true; break;
        case 'revoke':
          await request('revoke', { id: args.id, user: args.user }); result = true; break;
        case 'list': {
          const list = await request('list');
          check(list.files.length === 2 && list.files.every(file => !file.metadata && !file.envelope && file.state === 'ready'), 'listing disclosed private fields');
          result = list.files.map(file => file.id); break;
        }
        case 'tampering': {
          const item = state.files.get(args.id), file = item.file, key = item.key;
          const original = await request('chunk', { id: args.id, index: 0 });
          const ciphertext = c.decode(original.ciphertext); ciphertext[0] ^= 1;
          const corrupt = value => { const data = c.decode(value); data[0] ^= 1; return c.encode(data); };
          const foreign = { ...state.bootstrap, portal_id: c.encode(new Uint8Array(32).fill(77)) };
          const foreignFile = { ...file, id: c.encode(new Uint8Array(32).fill(78)) };
          const foreignOwner = { ...file, owner: args.otherUser };
          const failures = [
            () => c.decryptChunk(state.bootstrap, file, key, 0, ciphertext),
            () => c.decryptMetadata(state.bootstrap, { ...file, metadata: corrupt(file.metadata) }, key),
            () => c.unlock(state.bootstrap, { ...state.registration, vault: { ...state.registration.vault,
              ciphertext: corrupt(state.registration.vault.ciphertext) } }, args.recoveryKey),
            () => c.unlock(state.bootstrap, state.registration, args.wrongRecovery),
            () => c.unwrapKey(state.bootstrap, { ...file, envelope: { ...file.envelope,
              ciphertext: corrupt(file.envelope.ciphertext) } }, state.registration, state.privateKey),
            () => c.unwrapKey(foreign, file, state.registration, state.privateKey),
            () => c.unwrapKey(state.bootstrap, foreignFile, state.registration, state.privateKey),
            () => c.unwrapKey(state.bootstrap, foreignOwner, state.registration, state.privateKey),
          ];
          for (const failure of failures) check(await rejected(failure), 'tampered cryptographic context accepted');
          result = failures.length; break;
        }
        case 'calls': result = state.calls; break;
        default: throw new Error('unknown fixture action');
      }
      return { ok: true, result };
    } catch (error) { return { ok: false, detail: error instanceof ConsumerCheck ? error.message : 'crypto or fetch operation failed' }; }
  };
  return { secure: isSecureContext, crypto: !!crypto.subtle };
}

async function step(page, action, args = {}) {
  stage = config.phase + ' ' + action;
  const value = await evaluate(page.tab, data => window.documentsStep(data), { action, args });
  assert.ok(value?.ok, 'Documents consumer step failed: ' + (value?.detail || 'missing result'));
  return value.result;
}

async function enroll(page, account) {
  const value = await step(page, 'enroll');
  secret(value.recoveryKey, 'base64url', true);
  record({ kind: 'recovery', account, userID: page.bootstrap.user_id, portalID: page.bootstrap.portal_id,
    keyID: value.registration.key_id, publicKey: value.registration.public_key, recoveryKey: value.recoveryKey });
  const stored = await step(page, 'register', { recoveryKey: value.recoveryKey });
  assert.ok(stored.key_id === value.registration.key_id && stored.public_key === value.registration.public_key, 'registered vault changed');
  return value;
}

async function create(pages) {
  const alice = await login('alice'), bob = await login('bob'), admin = await login('admin');
  pages.push(alice, bob, admin);
  assert.ok(alice.bootstrap.portal_id === bob.bootstrap.portal_id && alice.bootstrap.portal_id === admin.bootstrap.portal_id,
    'accounts did not share the same Documents portal');
  const owner = await enroll(alice, 'alice'), recipient = await enroll(bob, 'bob');
  let sharedID;
  for (const empty of [false, true]) {
    const file = await step(alice, 'allocate', { empty });
    secret(file.key, 'base64url', true);
    record({ kind: 'file', fileID: file.id, empty });
    if (!empty) sharedID = file.id;
    await step(bob, 'deny', { operation: 'fetch', params: { id: file.id } });
    await step(alice, 'upload', { id: file.id });
    const restored = await step(alice, 'decrypt', { id: file.id, empty });
    secret(restored.key, 'base64url', true);
    assert.ok(restored.key === file.key && restored.chunks === (empty ? 1 : 2), 'owner unwrap or chunk count changed');
  }
  const listed = await step(alice, 'list');
  assert.ok(listed.includes(sharedID), 'committed document absent from owner list');
  const publicKey = await step(alice, 'lookup', { user: bob.bootstrap.user_id });
  assert.ok(!publicKey.vault && publicKey.key_id === recipient.registration.key_id &&
    publicKey.public_key === recipient.registration.public_key, 'recipient fingerprint or public-only lookup changed');
  const envelope = await step(alice, 'share', { id: sharedID, recipient: publicKey });
  const shared = await step(bob, 'decrypt', { id: sharedID, empty: false });
  secret(shared.key, 'base64url', true);
  await step(admin, 'deny', { operation: 'fetch', params: { id: sharedID } });
  await step(bob, 'deny', { operation: 'delete', params: { id: sharedID } });
  await step(bob, 'deny', { operation: 'share', params: { id: sharedID, user: alice.bootstrap.user_id }, body: { envelope } });
  assert.ok(await step(bob, 'tampering', { id: sharedID, recoveryKey: recipient.recoveryKey,
    wrongRecovery: owner.recoveryKey, otherUser: bob.bootstrap.user_id }) === 8, 'crypto negative controls incomplete');
  await step(alice, 'revoke', { id: sharedID, user: bob.bootstrap.user_id });
  await step(bob, 'deny', { operation: 'fetch', params: { id: sharedID } });
  await step(bob, 'deny', { operation: 'chunk', params: { id: sharedID, index: 0 } });
  await step(alice, 'decrypt', { id: sharedID, empty: false });
}

async function recover(pages) {
  const alice = await login('alice'), bob = await login('bob');
  pages.push(alice, bob);
  for (const [account, page] of [['alice', alice], ['bob', bob]]) {
    const saved = input.recovery.find(value => value.account === account);
    assert.ok(saved && saved.portalID === page.bootstrap.portal_id && saved.userID === page.bootstrap.user_id,
      'root replacement changed stable Documents identity');
    const vault = await step(page, 'unlock', { recoveryKey: saved.recoveryKey });
    assert.ok(vault.key_id === saved.keyID && vault.public_key === saved.publicKey, 'persisted vault fingerprint changed');
  }
  assert.ok(input.files.length === 2 && input.files.filter(file => file.empty).length === 1, 'recovery fixture file inventory changed');
  for (const file of input.files) {
    const restored = await step(alice, 'decrypt', { id: file.fileID, empty: file.empty });
    secret(restored.key, 'base64url', true);
    await step(bob, 'deny', { operation: 'fetch', params: { id: file.fileID } });
  }
  await step(alice, 'list');
}

async function verifyWire(pages) {
  let expected = 0;
  for (const page of pages) expected += await step(page, 'calls');
  await waitForRead(() => requests.size === expected && [...requests.values()].every(item => item.complete &&
    item.extra && (!item.hasResponseExtra || item.responseExtra)));
  await Promise.all([...captures]);
  assert.ok(!captureFailed && expected >= (config.phase === 'create' ? 40 : 12), 'Documents network observation was incomplete');
  for (const item of requests.values()) {
    assert.ok(!header(item.headers, 'authorization') && !header(item.extra, 'authorization'), 'browser injected an Authorization header');
    const headers = { ...item.headers, ...item.extra };
    assert.ok(header(headers, 'sec-fetch-site') === 'same-origin', 'Documents request lacked natural same-origin metadata');
    if (item.method !== 'GET') assert.ok(header(headers, 'origin') === config.origin, 'Documents mutation lacked its real Origin');
    assert.ok(!header(item.responseHeaders, 'set-cookie') && !header(item.responseExtra, 'set-cookie'),
      'Documents response unexpectedly issued a cookie');
    for (const value of [...cryptoSecrets, ...Object.values(input.credentials)]) {
      assert.ok(!item.url.includes(value) && !item.body.includes(value) && !item.response.includes(value),
        'plaintext or private crypto material appeared on the Documents wire');
    }
    for (const value of secrets) {
      if (cryptoSecrets.has(value)) continue;
      assert.ok(!item.url.includes(value) && !item.body.includes(value) && !item.response.includes(value),
        'authentication credential appeared in Documents URL or JSON');
    }
  }
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  const pages = [];
  try {
    assert.ok(['create', 'recover'].includes(config.phase), 'unsupported Documents browser phase');
    if (config.phase === 'create') await create(pages); else await recover(pages);
    stage = config.phase + ' wire privacy';
    await verifyWire(pages);
    assert.ok(exceptionCount === 0, 'asynchronous browser exception');
  } finally {
    try {
      await Promise.all([...captures]);
      await disposeBrowserContexts(command, contexts);
      assert.ok(exceptionCount === 0, 'browser teardown exception');
    } finally { socket.close(); }
  }
  record({ kind: 'phase', phase: config.phase });
  process.stdout.write('Documents browser ' + config.phase + ' passed\n');
})().catch(error => {
  const safe = error instanceof BrowserProtocolError || error instanceof assert.AssertionError
    ? error.message : 'browser operation failed';
  process.stderr.write(stage + ': ' + safe + '\n');
  process.exitCode = 1;
}).finally(() => { fs.closeSync(evidence); socket.close(); });
