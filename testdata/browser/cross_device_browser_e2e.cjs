// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const { origin } = config;
const passwords = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const password = passwords.alice;
const { BrowserProtocolError, waitForRead } = require("./authorization_redirect_cdp.cjs");
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";
const beginDiagnostics = [];
const paused = new Map();
const polls = new Map();
const aborted = new Set();

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Network.requestWillBeSent' && message.params.request.url.endsWith('/cross-device/begin')) {
    beginDiagnostics.push({ origin: message.params.request.headers.Origin || 'absent', method: message.params.request.method });
  }
  if (message.method === 'Network.responseReceived' && message.params.response.url.endsWith('/cross-device/begin')) beginDiagnostics.push({ status: message.params.response.status });
  if (message.method === 'Fetch.requestPaused') paused.set(message.sessionId, message.params.requestId);
  if (message.method === 'Network.requestWillBeSent' && message.params.request.url.endsWith('/cross-device/poll')) {
    polls.set(message.sessionId, (polls.get(message.sessionId) || 0) + 1);
  }
  if (message.method === 'Network.loadingFailed' && message.params.canceled) aborted.add(message.sessionId);
  if (!message.id) return;
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id);
  clearTimeout(request.timer);
  if (message.error) request.reject(new BrowserProtocolError(request.method, message.error));
  else request.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("browser command timed out")); }, 25000);
    pending.set(id, { resolve, reject, timer, method });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true, userGesture: true
  }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}
async function waitFor(fn) { await waitForRead(fn, { timeout: 25000 }); }
async function page(contextId) {
  const target = await command("Target.createTarget", { url: "about:blank", browserContextId: contextId });
  const { sessionId } = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  await command("Page.enable", {}, sessionId);
  await command("Network.enable", {}, sessionId);
  await command("Runtime.enable", {}, sessionId);
  return sessionId;
}
async function navigate(page, path, sessionClient = false) {
  const result = await command("Page.navigate", { url: origin + path }, page);
  if (result.errorText) throw new Error("portal navigation failed");
  await waitFor(() => evaluate(page, (url) => location.href === url && document.readyState === "complete", origin + path));
  if (sessionClient) await waitFor(() => evaluate(page, () => !!window.AuthCrunchSession));
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  const contexts = [];
  try {
    const first = await command('Target.createBrowserContext'); contexts.push(first.browserContextId);
    const second = await command('Target.createBrowserContext'); contexts.push(second.browserContextId);
    const requester = await page(first.browserContextId);
    const approver = await page(second.browserContextId);
    // Exercise the real fetch/abort protocol without the newer static helpers,
    // as on embedded browsers that have AbortController but lack these methods.
    await command('Page.addScriptToEvaluateOnNewDocument', { source: `
      Object.defineProperty(AbortSignal, 'any', { value: undefined });
      Object.defineProperty(AbortSignal, 'timeout', { value: undefined });
      const nativeAbort = AbortController.prototype.abort;
      window.crossDeviceAborts = 0;
      AbortController.prototype.abort = function (...args) {
        const result = nativeAbort.apply(this, args);
        if (this.signal.aborted) window.crossDeviceAborts++;
        return result;
      };
    ` }, requester);
    stage = 'visible login link';
    await navigate(requester, '/auth/login');
    const visibleLink = () => evaluate(requester, () => {
      const link = document.querySelector('#cross-device-link a');
      return link && link.getClientRects().length > 0;
    });
    assert.ok(await visibleLink(), 'single-realm login hid the cross-device action');
    stage = 'request on a narrow screen';
    await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, requester);
    await evaluate(requester, () => document.querySelector('#cross-device-link a').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    assert.ok(await evaluate(requester, () => !AbortSignal.any && !AbortSignal.timeout), 'compatibility fixture retained static abort helpers');
    const interaction = await evaluate(requester, () => ({
      link: document.getElementById('cross-device-link').value,
      code: document.getElementById('cross-device-code').textContent,
      qr: document.getElementById('cross-device-qr').complete && document.getElementById('cross-device-qr').naturalWidth === 256,
      fits: document.documentElement.scrollWidth <= window.innerWidth,
    }));
    assert.ok(interaction.qr, 'QR code did not render');
    assert.ok(interaction.fits, 'request page overflowed the phone viewport');
    assert.ok(interaction.link.startsWith(origin + '/auth/cross-device/activate?code='));
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'copyable activation link';
    await command('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'], origin, browserContextId: first.browserContextId });
    await evaluate(requester, () => document.getElementById('cross-device-copy').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-status').textContent.includes('copied')));
    assert.equal(await evaluate(requester, () => navigator.clipboard.readText()), interaction.link);
    stage = 'activate on isolated second device';
    await navigate(approver, interaction.link.slice(origin.length));
    assert.equal(await evaluate(approver, () => document.getElementById('cross-device-code').textContent), interaction.code);
    stage = 'fresh login form';
    await evaluate(approver, () => document.querySelector('form button').click());
    await waitFor(() => evaluate(approver, () => location.pathname === '/auth/login' && document.readyState === 'complete'));
    stage = 'username submission';
    await evaluate(approver, () => { document.getElementById('username').value = 'alice'; document.querySelector('#loginform form').requestSubmit(); });
    await waitFor(() => evaluate(approver, () => !!document.querySelector('input[name="secret"]')));
    stage = 'password verification';
    await evaluate(approver, password => {
      const input = document.querySelector('input[name="secret"]'); input.value = password; input.form.requestSubmit();
    }, password);
    await waitFor(() => evaluate(approver, () => location.pathname === '/auth/cross-device/confirm' && document.readyState === 'complete'));
    assert.equal(await evaluate(approver, () => document.getElementById('cross-device-code').textContent), interaction.code);
    // At least one real scheduled poll observes pending before explicit approval.
    await new Promise(resolve => setTimeout(resolve, 2200));
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'explicit approval and requester polling';
    await evaluate(approver, () => document.querySelector('button[value="approve"]').click());
    await waitFor(() => evaluate(requester, () => location.pathname === '/auth/portal' && document.readyState === 'complete'));
    const requesterCookies = (await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies;
    const approverCookies = (await command('Storage.getCookies', { browserContextId: second.browserContextId })).cookies;
    for (const name of ['AUTHP_ACCESS_TOKEN', 'AUTHP_REFRESH_TOKEN', 'AUTHP_OIDC_SESSION_ID']) {
      const own = requesterCookies.find(c => c.name === name);
      const remote = approverCookies.find(c => c.name === name);
      assert.ok(own && remote && own.value !== remote.value, 'devices did not receive independent ' + name);
      assert.ok(own.secure && own.httpOnly, 'requester credential is not secure/HttpOnly');
    }
    assert.ok(!approverCookies.some(c => c.name === '__Secure-DEVICE'), 'approval cookie was not deleted');
    stage = 'protected application access';
    await navigate(requester, '/resource');
    assert.equal(await evaluate(requester, () => document.body.textContent.trim()), 'identity resource');
    stage = 'cancel stops polling';
    await navigate(requester, '/auth/cross-device');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-status')?.textContent === 'Sign-in cancelled.'));
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-details').hidden), true);
    stage = 'navigation ends the visible request';
    await navigate(requester, '/auth/cross-device');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    const abandoned = await evaluate(requester, () => {
      // Observe the actual pagehide event after the production listener. Store
      // only display state; capabilities must never enter browser storage.
      window.addEventListener('pagehide', () => sessionStorage.setItem('cross-device-left', JSON.stringify({
        hidden: document.getElementById('cross-device-details').hidden,
        status: document.getElementById('cross-device-status').textContent,
      })), { once: true });
      return document.getElementById('cross-device-link').value;
    });
    await navigate(requester, '/auth/portal');
    const left = await evaluate(requester, () => JSON.parse(sessionStorage.getItem('cross-device-left')));
    assert.equal(left.hidden, true);
    assert.match(left.status, /ended/);
    stage = 'back navigation never revives a stopped request';
    await evaluate(requester, () => history.back());
    await waitFor(() => evaluate(requester, previous => {
      if (location.pathname !== '/auth/cross-device' || document.readyState !== 'complete') return false;
      const details = document.getElementById('cross-device-details');
      if (!details) return false;
      // Chrome may restore a cached document or fetch a new no-store page.
      // A restored document is terminal; a fresh one gets a new capability.
      return details.hidden
        ? document.getElementById('cross-device-status').textContent.includes('ended')
        : document.getElementById('cross-device-link').value !== previous;
    }, abandoned));
    stage = 'late clipboard cannot replace cancellation';
    await navigate(requester, '/auth/cross-device');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    await evaluate(requester, () => {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
        writeText() { return new Promise(resolve => { window.finishClipboard = resolve; }); }
      }});
      document.getElementById('cross-device-copy').click();
    });
    await waitFor(() => evaluate(requester, () => typeof window.finishClipboard === 'function'));
    await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-status').textContent === 'Sign-in cancelled.'));
    await evaluate(requester, () => window.finishClipboard());
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.ok(await evaluate(requester, () => document.getElementById('cross-device-details').hidden && document.getElementById('cross-device-status').textContent === 'Sign-in cancelled.'));

    for (const action of ['cancel', 'navigate']) {
      stage = action + ' aborts an in-flight poll without AbortSignal static helpers';
      paused.delete(requester); aborted.delete(requester);
      await command('Fetch.enable', { patterns: [{ urlPattern: '*/cross-device/poll', requestStage: 'Response' }] }, requester);
      await navigate(requester, '/auth/cross-device');
      stage = action + ' waits for an intercepted poll';
      await waitFor(() => paused.has(requester));
      stage = action + ' leaves the intercepted request';
      if (action === 'cancel') {
        await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
        await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-status').textContent === 'Sign-in cancelled.'));
      } else {
        await evaluate(requester, () => {
          window.addEventListener('pagehide', () => sessionStorage.setItem('cross-device-aborts', String(window.crossDeviceAborts)), { once: true });
        });
        await navigate(requester, '/auth/portal');
      }
      await command('Fetch.disable', {}, requester);
      stage = action + ' observes the network abort';
      if (action === 'cancel') {
        await waitFor(() => aborted.has(requester));
      } else {
        // Chrome can drop Network.loadingFailed when the intercepted response's
        // document is destroyed. Observe real native signal abortion before
        // pagehide finishes, and independently ensure no polling resumes.
        assert.ok(await evaluate(requester, () => Number(sessionStorage.getItem('cross-device-aborts')) >= 2));
      }
      const count = polls.get(requester);
      await new Promise(resolve => setTimeout(resolve, 2200));
      assert.equal(polls.get(requester), count, 'stopped page restarted polling');
    }

    stage = 'two accounts cannot approve a stale form in another tab';
    const requestContexts = [];
    const requestPages = [];
    const links = [];
    for (let i = 0; i < 2; i++) {
      const context = await command('Target.createBrowserContext');
      contexts.push(context.browserContextId); requestContexts.push(context.browserContextId);
      const tab = await page(context.browserContextId); requestPages.push(tab);
      await navigate(tab, '/auth/cross-device');
      await waitFor(() => evaluate(tab, () => document.getElementById('cross-device-details')?.hidden === false));
      links.push(await evaluate(tab, () => document.getElementById('cross-device-link').value));
    }
    const aliceTab = await page(second.browserContextId);
    const bobTab = await page(second.browserContextId);
    async function signIn(tab, link, username) {
      await navigate(tab, link.slice(origin.length));
      await evaluate(tab, () => document.querySelector('form button').click());
      await waitFor(() => evaluate(tab, () => location.pathname === '/auth/login' && document.readyState === 'complete'));
      await evaluate(tab, name => { document.getElementById('username').value = name; document.querySelector('#loginform form').requestSubmit(); }, username);
      await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="secret"]')));
      await evaluate(tab, pwd => { const field = document.querySelector('input[name="secret"]'); field.value = pwd; field.form.requestSubmit(); }, passwords[username]);
      await waitFor(() => evaluate(tab, () => location.pathname === '/auth/cross-device/confirm' && document.readyState === 'complete'));
      assert.ok(await evaluate(tab, name => document.body.textContent.includes(name + '@example.test'), username));
    }
    await signIn(aliceTab, links[0], 'alice');
    await signIn(bobTab, links[1], 'bob');
    await evaluate(aliceTab, () => document.querySelector('button[value="approve"]').click());
    await waitFor(() => evaluate(aliceTab, () => !document.querySelector('button[value="approve"]') && document.readyState === 'complete'));
    await new Promise(resolve => setTimeout(resolve, 2200));
    for (const browserContextId of requestContexts) {
      assert.ok(!(await command('Storage.getCookies', { browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), 'stale form approved a requester');
    }
    await evaluate(bobTab, () => document.querySelector('button[value="approve"]').click());
    await waitFor(() => evaluate(requestPages[1], () => location.pathname === '/auth/portal' && document.readyState === 'complete'));
    const bobCookies = (await command('Storage.getCookies', { browserContextId: requestContexts[1] })).cookies;
    const bobAccess = bobCookies.find(c => c.name === 'AUTHP_ACCESS_TOKEN');
    assert.ok(bobAccess, 'valid new approval omitted requester credentials');
    assert.equal(JSON.parse(Buffer.from(bobAccess.value.split('.')[1], 'base64url')).email, 'bob@example.test');
    await navigate(requestPages[1], '/resource');
    assert.equal(await evaluate(requestPages[1], () => document.body.textContent.trim()), 'identity resource');
    assert.ok(!(await command('Storage.getCookies', { browserContextId: requestContexts[0] })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), 'Bob reached the wrong requester');
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    for (const browserContextId of contexts) await command('Target.disposeBrowserContext', { browserContextId });
    socket.close();
  }
})().catch(error => { console.error('Stage: ' + stage + '\n' + error.message + '\n' + JSON.stringify(beginDiagnostics)); socket.close(); process.exitCode = 1; });
