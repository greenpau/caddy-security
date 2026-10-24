// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const { origin } = config;
const mount = (config.mount || '/auth').replace(/\/$/, '');
const route = suffix => mount + suffix;
const smoke = config.mode === 'smoke';
const passwords = JSON.parse(fs.readFileSync(0, "utf8"));
const { BrowserProtocolError, waitForRead } = require("./authorization_redirect_cdp.cjs");
const { disposeBrowserContexts } = require("./browser_contexts.cjs");
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";
const beginDiagnostics = [];
const paused = new Map();
const polls = new Map();
const aborted = new Set();
const assets = new Map();
const runtimeErrors = [];
let runtimeErrorCount = 0;
const cancelReplies = new Map();

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Runtime.exceptionThrown') {
    runtimeErrorCount++;
    if (runtimeErrors.length < 10) {
      const details = message.params.exceptionDetails;
      // Descriptions, scripts, stacks and URLs may contain activation secrets.
      runtimeErrors.push({ stage, category: 'uncaught-script', line: details.lineNumber, column: details.columnNumber });
    }
  }
  if (message.method === 'Network.responseReceived') {
    const response = message.params.response;
    if (response.url === origin + route('/cross-device/cancel')) {
      const previous = cancelReplies.get(message.sessionId)?.count || 0;
      cancelReplies.set(message.sessionId, { count: previous + 1, status: response.status });
    }
    for (const asset of ['css/basic.css', 'js/cross_device.js']) {
      if (response.url === origin + route('/assets/' + asset)) {
        if (!assets.has(message.sessionId)) assets.set(message.sessionId, new Map());
        assets.get(message.sessionId).set(asset, response.status);
      }
    }
  }
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
async function isCancelled(page) {
  return evaluate(page, () =>
    document.getElementById('cross-device-title').textContent === 'Sign-in cancelled' &&
    document.getElementById('cross-device-status').textContent === 'This sign-in request has been cancelled. Start again when you’re ready.' &&
    document.getElementById('cross-device-details').hidden &&
    document.getElementById('cross-device-controls').hidden &&
    !document.getElementById('cross-device-recovery').hidden);
}
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

function assertNoRuntimeErrors() {
  assert.ok(runtimeErrorCount === 0, 'asynchronous browser exceptions: ' + JSON.stringify(runtimeErrors));
}

async function pressKey(page, key) {
  await command('Page.bringToFront', {}, page);
  const keys = { Tab: ['Tab', 9, ''], Enter: ['Enter', 13, '\r'], ' ': ['Space', 32, ' '] };
  const [code, windowsVirtualKeyCode, text] = keys[key];
  for (const type of ['keyDown', 'keyUp']) {
    const params = { type, key, code, windowsVirtualKeyCode };
    // Blink activates Enter buttons on the character event, not keydown alone.
    if (type === 'keyDown' && text) Object.assign(params, { text, unmodifiedText: text });
    await command('Input.dispatchKeyEvent', params, page);
  }
}

async function headingFocus(page) {
  await command('Page.bringToFront', {}, page);
  await evaluate(page, () => document.getElementById('cross-device-title').focus());
}

async function assertFocus(page, selector, name) {
  assert.ok(await evaluate(page, selector => {
    const element = document.querySelector(selector);
    if (!element || document.activeElement !== element || !element.getClientRects().length) return false;
    const style = getComputedStyle(element);
    return element.matches(':focus-visible') && style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) >= 2;
  }, selector), name + ' did not receive visible keyboard focus');
  const node = await accessibilityNode(page, selector);
  assert.ok(!node.ignored && node.name?.value === name, name + ' accessibility name changed');
  assert.equal(node.role?.value, selector.includes(' a') ? 'link' : 'button', name + ' accessibility role');
}

async function accessibilityNode(page, selector) {
  const { root } = await command('DOM.getDocument', {}, page);
  const { nodeId } = await command('DOM.querySelector', { nodeId: root.nodeId, selector }, page);
  assert.ok(nodeId, 'expected accessibility element missing');
  const { nodes } = await command('Accessibility.getPartialAXTree', { nodeId, fetchRelatives: false }, page);
  assert.ok(nodes.length, 'expected accessibility node missing');
  return nodes[0];
}

async function copyStatusRegion(page) {
  const region = await accessibilityNode(page, '#cross-device-copy-status');
  assert.ok(!region.ignored, 'copy feedback is absent from the accessibility tree');
  assert.equal(region.role?.value, 'status');
  assert.equal(region.properties.find(p => p.name === 'live')?.value.value, 'polite');
  assert.equal(region.properties.find(p => p.name === 'atomic')?.value.value, true);
  return region.backendDOMNodeId;
}

async function capture(page, name) {
  if (!config.screenshotDir) return;
  assert.match(name, /^[a-z0-9-]+$/, 'screenshot filename must be static');
  await evaluate(page, async () => { await document.fonts.ready; });
  const { cssContentSize } = await command('Page.getLayoutMetrics', {}, page);
  const { data } = await command('Page.captureScreenshot', {
    format: 'png', captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: cssContentSize.width, height: cssContentSize.height, scale: 1 },
  }, page);
  // Go supplies a fresh private directory under this checkout's ignored tmp.
  fs.writeFileSync(path.join(config.screenshotDir, name + '.png'), Buffer.from(data, 'base64'), { mode: 0o600, flag: 'wx' });
}

async function layout(page, name, title, expectedButtons, matchingCode = '', widths = [320, 390, 639, 640, 768, 1280]) {
  const previousStage = stage;
  for (const width of widths) {
    stage = previousStage + ' layout ' + width;
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 }, page);
    const result = await evaluate(page, async codeValue => {
      await document.fonts.ready;
      const visible = el => !!el && el.getClientRects().length > 0;
      const rect = el => {
        const r = el.getBoundingClientRect();
        return { x: r.x, y: r.y, width: r.width, height: r.height, right: r.right, bottom: r.bottom };
      };
      const main = document.querySelector('main');
      const bounds = rect(main);
      const style = getComputedStyle(main);
      const left = bounds.x + parseFloat(style.borderLeftWidth) + parseFloat(style.paddingLeft);
      const right = bounds.right - parseFloat(style.borderRightWidth) - parseFloat(style.paddingRight);
      const fits = el => {
        const r = rect(el);
        return r.x >= left - 0.5 && r.right <= right + 0.5 && el.scrollWidth <= el.clientWidth + 1;
      };
      const code = document.getElementById('cross-device-code');
      const panel = document.querySelector('.cross-device-code-panel');
      const qr = document.getElementById('cross-device-qr');
      const controls = document.getElementById('cross-device-controls');
      const actions = document.querySelector('.cross-device-actions');
      const buttons = [...document.querySelectorAll('.cross-device-actions button')].filter(visible);
      return {
        title: document.querySelector('h1').textContent, documentTitle: document.title,
        fits: document.documentElement.scrollWidth <= innerWidth + 1 &&
          [...main.querySelectorAll('button, textarea, .cross-device-code-panel')].filter(visible).every(fits),
        code: visible(code) ? {
          matches: code.textContent === codeValue, size: parseFloat(getComputedStyle(code).fontSize),
          centered: getComputedStyle(code).textAlign === 'center' &&
            Math.abs(rect(code).x + rect(code).width / 2 - rect(panel).x - rect(panel).width / 2) < 1,
        } : null,
        qr: visible(qr) ? {
          loaded: qr.complete && qr.naturalWidth === 256 && qr.naturalHeight === 256,
          fits: fits(qr) && Math.abs(rect(qr).width - rect(qr).height) < 1,
          centered: Math.abs(rect(qr).x + rect(qr).width / 2 - bounds.x - bounds.width / 2) < 1,
        } : null,
        buttons: buttons.map(el => ({ ...rect(el), label: el.textContent.trim() })),
        rawLinkVisible: visible(document.getElementById('cross-device-link')),
        emptyFeedback: visible(controls) && visible(actions) && Math.abs(rect(controls).height - rect(actions).height) < 1,
      };
    }, matchingCode);
    assert.equal(result.title, title, name + ' heading');
    assert.ok(result.documentTitle.endsWith(title), name + ' browser title');
    assert.ok(result.fits, name + ' overflowed its content area');
    if (matchingCode) assert.ok(result.code?.matches && result.code.size >= 28 && result.code.centered, 'matching code changed or is not prominent and centered');
    if (result.qr) assert.ok(result.qr.loaded && result.qr.fits && result.qr.centered, 'QR is not fully loaded, square and centered');
    if (name === 'request') {
      assert.ok(result.qr, 'request page omitted QR');
      assert.ok(!result.rawLinkVisible && result.emptyFeedback, 'empty copy feedback added visible content or blank space');
    }
    assert.deepEqual(result.buttons.map(button => button.label), expectedButtons, name + ' actions');
    assert.ok(result.buttons.every(button => button.height >= 44), 'actions lost their minimum touch-target height');
    if (result.buttons.length === 2) {
      const [first, second] = result.buttons;
      assert.ok(Math.abs(first.width - second.width) < 1 && Math.abs(first.height - second.height) < 1, 'actions have unequal dimensions');
      const oneRow = Math.abs(first.y - second.y) < 1;
      assert.ok(oneRow ? second.x - first.right >= 11 : second.y - first.bottom >= 11 && Math.abs(first.x - second.x) < 1,
        'actions overlap or lost their visible separation/order');
    }
    if (width === 390 || width === 1280 || name === 'request' && width === 320) await capture(page, name + '-' + width);
  }
  await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, page);
  stage = previousStage;
}

async function requestDetails(page) {
  await waitFor(() => evaluate(page, () => document.getElementById('cross-device-details')?.hidden === false &&
    document.getElementById('cross-device-qr').complete && document.getElementById('cross-device-qr').naturalWidth === 256));
  const interaction = await evaluate(page, () => ({ link: document.getElementById('cross-device-link').value, code: document.getElementById('cross-device-code').textContent }));
  let activation;
  try { activation = new URL(interaction.link); }
  catch (_) { throw new Error('activation link is not a valid mounted URL'); }
  assert.ok(activation.origin === origin && activation.pathname === route('/cross-device/activate') &&
    !activation.username && !activation.password && !activation.hash && activation.searchParams.size === 1 &&
    !!activation.searchParams.get('code')?.trim(), 'activation link changed its origin, mount or exact code-only query');
  return interaction;
}

async function noCredentials(contextId) {
  const { cookies } = await command('Storage.getCookies', { browserContextId: contextId });
  assert.ok(!cookies.some(cookie => ['AUTHP_ACCESS_TOKEN', 'AUTHP_REFRESH_TOKEN', 'AUTHP_OIDC_SESSION_ID'].includes(cookie.name)),
    'unfinished requester received authentication credentials');
}

async function cancelAndRecover(page, previous) {
  const canceledBefore = cancelReplies.get(page)?.count || 0;
  await headingFocus(page);
  await pressKey(page, 'Tab');
  await assertFocus(page, '#cross-device-copy', 'Copy link');
  await pressKey(page, 'Tab');
  await assertFocus(page, '#cross-device-cancel', 'Cancel');
  await pressKey(page, ' ');
  await waitFor(() => isCancelled(page));
  await waitFor(() => (cancelReplies.get(page)?.count || 0) > canceledBefore);
  assert.equal(cancelReplies.get(page).status, 200, 'server did not confirm cancellation before recovery');
  assert.equal(await evaluate(page, () => document.activeElement.id), 'cross-device-title', 'cancellation left focus on a hidden control');
  await layout(page, 'cancelled', 'Sign-in cancelled', [], '', smoke ? [390] : [390, 1280]);
  await pressKey(page, 'Tab');
  await assertFocus(page, '#cross-device-recovery a', 'Start again');
  await pressKey(page, 'Tab');
  await assertFocus(page, '.brand-actions a', 'Back to sign in');
  await headingFocus(page);
  await pressKey(page, 'Tab');
  await assertFocus(page, '#cross-device-recovery a', 'Start again');
  await pressKey(page, 'Enter');
  const fresh = await requestDetails(page);
  assert.ok(fresh.link !== previous.link && fresh.code !== previous.code, 'recovery revived the previous activation capability');
  assert.ok(await evaluate(page, expected => location.pathname === expected, route('/cross-device')), 'recovery changed portal mount');
  return fresh;
}

async function continueSignIn(page, username) {
  await headingFocus(page);
  await pressKey(page, 'Tab');
  await assertFocus(page, 'form button', 'Continue');
  await pressKey(page, 'Enter');
  await waitFor(() => evaluate(page, expected => location.pathname === expected && document.readyState === 'complete', route('/login')));
  await evaluate(page, name => {
    document.getElementById('username').value = name;
    document.querySelector('#loginform form').requestSubmit();
  }, username);
  await waitFor(() => evaluate(page, () => !!document.querySelector('input[name="secret"]')));
  await evaluate(page, pwd => {
    const field = document.querySelector('input[name="secret"]'); field.value = pwd; field.form.requestSubmit();
  }, passwords[username]);
  await waitFor(() => evaluate(page, expected => location.pathname === expected && document.readyState === 'complete', route('/cross-device/confirm')));
  assert.ok(await evaluate(page, name => document.querySelector('.cross-device-account')?.textContent.includes(name + '@example.test'), username),
    'confirmation did not identify the freshly authenticated account');
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  const contexts = new Set();
  try {
    const first = await command('Target.createBrowserContext'); contexts.add(first.browserContextId);
    const second = await command('Target.createBrowserContext'); contexts.add(second.browserContextId);
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
    await navigate(requester, route('/login'));
    const visibleLink = () => evaluate(requester, () => {
      const link = document.querySelector('#cross-device-link a');
      return link && link.getClientRects().length > 0;
    });
    assert.ok(await visibleLink(), 'single-realm login hid the cross-device action');
    stage = 'request on a narrow screen';
    await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, requester);
    await evaluate(requester, () => document.querySelector('#cross-device-link a').click());
    const interaction = await requestDetails(requester);
    assert.ok(await evaluate(requester, () => !AbortSignal.any && !AbortSignal.timeout), 'compatibility fixture retained static abort helpers');
    assert.ok(interaction.link.startsWith(origin + route('/cross-device/activate?code=')), 'activation link changed origin or mount');
    for (const asset of ['css/basic.css', 'js/cross_device.js']) {
      assert.equal(assets.get(requester)?.get(asset), 200, 'mounted embedded asset did not load: ' + asset);
    }
    await layout(requester, 'request', 'Sign in on another device', ['Copy link', 'Cancel'], interaction.code, smoke ? [390] : undefined);
    await noCredentials(first.browserContextId);
    const copyStatusNode = await copyStatusRegion(requester);
    if (smoke) {
      stage = 'nested activation and keyboard recovery';
      await navigate(approver, interaction.link.slice(origin.length));
      await layout(approver, 'activate', 'Sign in to continue', ['Continue'], interaction.code, [390]);
      await cancelAndRecover(requester, interaction);
      await noCredentials(first.browserContextId);
      await noCredentials(second.browserContextId);
      assertNoRuntimeErrors();
      process.stdout.write(JSON.stringify({ passed: true }));
      return;
    }
    stage = 'copyable activation link';
    const waitingStatus = await evaluate(requester, () => document.getElementById('cross-device-status').textContent);
    await command('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'], origin, browserContextId: first.browserContextId });
    await headingFocus(requester);
    await pressKey(requester, 'Tab');
    await assertFocus(requester, '#cross-device-copy', 'Copy link');
    await pressKey(requester, 'Enter');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-copy-status').textContent === 'Link copied. Open it on a device you trust.'));
    assert.ok(await evaluate(requester, async link => await navigator.clipboard.readText() === link, interaction.link), 'clipboard did not contain the complete activation link');
    assert.equal(await copyStatusRegion(requester), copyStatusNode, 'copy replaced the exposed live region');
    assert.ok(await evaluate(requester, () => {
      const feedback = document.getElementById('cross-device-copy-status').getBoundingClientRect();
      const actions = document.querySelector('.cross-device-actions').getBoundingClientRect();
      return Math.abs(feedback.top - actions.bottom - 24) < 1 && document.getElementById('cross-device-link-fallback').hidden;
    }), 'copy feedback spacing or hidden fallback changed');
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-status').textContent), waitingStatus);
    await capture(requester, 'copied-390');

    stage = 'delayed native clipboard denial preserves keyboard focus';
    await command('Browser.grantPermissions', { permissions: [], origin, browserContextId: first.browserContextId });
    await evaluate(requester, () => {
      const original = navigator.clipboard.writeText;
      let release;
      const gate = new Promise(resolve => { release = resolve; });
      window.nativeClipboardDenied = false;
      window.releaseClipboardDenial = () => {
        navigator.clipboard.writeText = original;
        delete window.releaseClipboardDenial;
        release();
      };
      // Only delay delivery of the browser's genuine permission rejection.
      navigator.clipboard.writeText = async function(value) {
        try { return await original.call(this, value); }
        catch (error) { window.nativeClipboardDenied = true; await gate; throw error; }
      };
    });
    await headingFocus(requester);
    await pressKey(requester, 'Tab');
    await assertFocus(requester, '#cross-device-copy', 'Copy link');
    await pressKey(requester, 'Enter');
    await waitFor(() => evaluate(requester, () => window.nativeClipboardDenied));
    await pressKey(requester, 'Tab');
    await assertFocus(requester, '#cross-device-cancel', 'Cancel');
    await evaluate(requester, () => window.releaseClipboardDenial());
    await waitFor(() => evaluate(requester, () => !document.getElementById('cross-device-link-fallback').hidden));
    await assertFocus(requester, '#cross-device-cancel', 'Cancel');
    assert.ok(await evaluate(requester, () => !document.getElementById('cross-device-copy-status').textContent.includes('selected')),
      'delayed denial incorrectly announced selected text');
    assert.equal(await copyStatusRegion(requester), copyStatusNode, 'denial replaced the exposed live region');
    await capture(requester, 'delayed-copy-390');

    stage = 'immediate native clipboard denial selects the manual link';
    await headingFocus(requester);
    await pressKey(requester, 'Tab');
    await assertFocus(requester, '#cross-device-copy', 'Copy link');
    await pressKey(requester, 'Enter');
    await waitFor(() => evaluate(requester, () => document.activeElement.id === 'cross-device-link'));
    assert.ok(await evaluate(requester, expected => {
      const link = document.getElementById('cross-device-link');
      const fallback = document.getElementById('cross-device-link-fallback');
      const feedback = document.getElementById('cross-device-copy-status');
      return !fallback.hidden && link.readOnly && link.value === expected &&
        link.selectionStart === 0 && link.selectionEnd === link.value.length && link.scrollWidth <= link.clientWidth &&
        Math.abs(fallback.getBoundingClientRect().top - feedback.getBoundingClientRect().bottom - 24) < 1;
    }, interaction.link), 'manual copy did not expose and select the complete readonly wrapping link');
    const manualLink = await accessibilityNode(requester, '#cross-device-link');
    assert.ok(!manualLink.ignored && manualLink.role?.value === 'textbox' && manualLink.name?.value === 'Sign-in link',
      'manual link lost its accessible label or textbox role');
    assert.equal(await copyStatusRegion(requester), copyStatusNode, 'manual copy replaced the exposed live region');
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-status').textContent), waitingStatus);
    await capture(requester, 'manual-copy-390');
    await noCredentials(first.browserContextId);

    stage = 'activate on isolated second device';
    await navigate(approver, interaction.link.slice(origin.length));
    await layout(approver, 'activate', 'Sign in to continue', ['Continue'], interaction.code);
    stage = 'fresh login form';
    await continueSignIn(approver, 'alice');
    await layout(approver, 'confirm', 'Approve sign in', ['Approve', 'Deny'], interaction.code);
    await headingFocus(approver);
    await pressKey(approver, 'Tab');
    await assertFocus(approver, 'button[value="approve"]', 'Approve');
    await capture(approver, 'confirm-keyboard-390');
    await pressKey(approver, 'Tab');
    await assertFocus(approver, 'button[value="deny"]', 'Deny');
    // At least one real scheduled poll observes pending before explicit approval.
    await new Promise(resolve => setTimeout(resolve, 2200));
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'explicit approval and requester polling';
    await headingFocus(approver);
    await pressKey(approver, 'Tab');
    await assertFocus(approver, 'button[value="approve"]', 'Approve');
    await pressKey(approver, ' ');
    await waitFor(() => evaluate(requester, expected => location.pathname === expected && document.readyState === 'complete', route('/portal')));
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
    await navigate(requester, route('/cross-device'));
    const beforeRecovery = await requestDetails(requester);
    await cancelAndRecover(requester, beforeRecovery);
    stage = 'navigation ends the visible request';
    // Reuse the recovery request so this journey does not spend another quota slot.
    const abandoned = await evaluate(requester, () => {
      // Observe the actual pagehide event after the production listener. Store
      // only display state; capabilities must never enter browser storage.
      window.addEventListener('pagehide', () => sessionStorage.setItem('cross-device-left', JSON.stringify({
        hidden: document.getElementById('cross-device-details').hidden,
        status: document.getElementById('cross-device-status').textContent,
      })), { once: true });
      return document.getElementById('cross-device-link').value;
    });
    await navigate(requester, route('/portal'));
    const left = await evaluate(requester, () => JSON.parse(sessionStorage.getItem('cross-device-left')));
    assert.equal(left.hidden, true);
    assert.match(left.status, /ended/);
    stage = 'back navigation never revives a stopped request';
    await evaluate(requester, () => history.back());
    await waitFor(() => evaluate(requester, ({ previous, expected }) => {
      if (location.pathname !== expected || document.readyState !== 'complete') return false;
      const details = document.getElementById('cross-device-details');
      if (!details) return false;
      // Chrome may restore a cached document or fetch a new no-store page.
      // A restored document is terminal; a fresh one gets a new capability.
      return details.hidden
        ? document.getElementById('cross-device-status').textContent.includes('ended')
        : document.getElementById('cross-device-link').value !== previous;
    }, { previous: abandoned, expected: route('/cross-device') }));
    stage = 'late clipboard cannot replace cancellation';
    await navigate(requester, route('/cross-device'));
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    await evaluate(requester, () => {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
        writeText() { return new Promise(resolve => { window.finishClipboard = resolve; }); }
      }});
      document.getElementById('cross-device-copy').click();
    });
    await waitFor(() => evaluate(requester, () => typeof window.finishClipboard === 'function'));
    await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
    await waitFor(() => isCancelled(requester));
    await evaluate(requester, () => window.finishClipboard());
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.ok(await isCancelled(requester));
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-copy-status').textContent), '');

    for (const action of ['cancel', 'navigate']) {
      stage = action + ' aborts an in-flight poll without AbortSignal static helpers';
      paused.delete(requester); aborted.delete(requester);
      await command('Fetch.enable', { patterns: [{ urlPattern: '*/cross-device/poll', requestStage: 'Response' }] }, requester);
      await navigate(requester, route('/cross-device'));
      stage = action + ' waits for an intercepted poll';
      await waitFor(() => paused.has(requester));
      stage = action + ' leaves the intercepted request';
      if (action === 'cancel') {
        await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
        await waitFor(() => isCancelled(requester));
      } else {
        await evaluate(requester, () => {
          window.addEventListener('pagehide', () => sessionStorage.setItem('cross-device-aborts', String(window.crossDeviceAborts)), { once: true });
        });
        await navigate(requester, route('/portal'));
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

    stage = 'release completed scenario devices';
    // The stale-form scenario needs four simultaneous tabs of its own. Keeping
    // the completed devices alive exceeds the CI process-tree memory budget.
    assertNoRuntimeErrors();
    await disposeBrowserContexts(command, contexts);
    assert.deepEqual((await command('Target.getBrowserContexts')).browserContextIds, []);
    const remaining = (await command('Target.getTargets')).targetInfos;
    assert.ok(!remaining.some(target => [first.browserContextId, second.browserContextId].includes(target.browserContextId)),
      'completed scenario retained a browser target');

    stage = 'fresh isolated devices explicitly deny approval';
    const deniedRequesterContext = await command('Target.createBrowserContext'); contexts.add(deniedRequesterContext.browserContextId);
    const deniedApproverContext = await command('Target.createBrowserContext'); contexts.add(deniedApproverContext.browserContextId);
    const deniedRequester = await page(deniedRequesterContext.browserContextId);
    const deniedApprover = await page(deniedApproverContext.browserContextId);
    await navigate(deniedRequester, route('/cross-device'));
    const deniedInteraction = await requestDetails(deniedRequester);
    await navigate(deniedApprover, deniedInteraction.link.slice(origin.length));
    await continueSignIn(deniedApprover, 'alice');
    assert.ok(await evaluate(deniedApprover, code => document.getElementById('cross-device-code').textContent === code, deniedInteraction.code),
      'Deny confirmation changed the device-matching code');
    await noCredentials(deniedRequesterContext.browserContextId);
    // Keep focus on navigation that survives the background polling transition.
    await headingFocus(deniedRequester);
    for (const [selector, label] of [
      ['#cross-device-copy', 'Copy link'], ['#cross-device-cancel', 'Cancel'], ['.brand-actions a', 'Back to sign in'],
    ]) {
      await pressKey(deniedRequester, 'Tab');
      await assertFocus(deniedRequester, selector, label);
    }
    await headingFocus(deniedApprover);
    await pressKey(deniedApprover, 'Tab');
    await assertFocus(deniedApprover, 'button[value="approve"]', 'Approve');
    await pressKey(deniedApprover, 'Tab');
    await assertFocus(deniedApprover, 'button[value="deny"]', 'Deny');
    await pressKey(deniedApprover, 'Enter');
    await waitFor(() => evaluate(deniedApprover, () => document.getElementById('cross-device-title')?.textContent === 'Sign-in denied'));
    await layout(deniedApprover, 'denied', 'Sign-in denied', [], '', [390, 1280]);
    await waitFor(() => evaluate(deniedRequester, () => document.getElementById('cross-device-title')?.textContent === 'Sign-in unavailable'));
    assert.ok(await evaluate(deniedRequester, () =>
      document.getElementById('cross-device-details').hidden && document.getElementById('cross-device-controls').hidden &&
      !document.getElementById('cross-device-recovery').hidden && document.activeElement === document.querySelector('.brand-actions a')),
      'background denial hid navigation focus or left request controls active');
    await layout(deniedRequester, 'unavailable', 'Sign-in unavailable', [], '', [390, 1280]);
    await noCredentials(deniedRequesterContext.browserContextId);
    const deniedResource = await evaluate(deniedRequester, async () => {
      const response = await fetch('/resource', { credentials: 'same-origin', redirect: 'manual' });
      return { type: response.type, status: response.status, protected: (await response.text()).trim() === 'identity resource' };
    });
    assert.ok(deniedResource.type === 'opaqueredirect' && deniedResource.status === 0 && !deniedResource.protected,
      'denied requester reached the protected application instead of its authentication redirect');
    await noCredentials(deniedRequesterContext.browserContextId);
    assertNoRuntimeErrors();
    await disposeBrowserContexts(command, contexts);
    assert.deepEqual((await command('Target.getBrowserContexts')).browserContextIds, []);
    assert.ok(!(await command('Target.getTargets')).targetInfos.some(target =>
      [deniedRequesterContext.browserContextId, deniedApproverContext.browserContextId].includes(target.browserContextId)),
    'denied scenario retained a browser target');

    stage = 'two accounts cannot approve a stale form in another tab';
    const approval = await command('Target.createBrowserContext'); contexts.add(approval.browserContextId);
    const requestContexts = [];
    const requestPages = [];
    const links = [];
    for (let i = 0; i < 2; i++) {
      const context = await command('Target.createBrowserContext');
      contexts.add(context.browserContextId); requestContexts.push(context.browserContextId);
      const tab = await page(context.browserContextId); requestPages.push(tab);
      await navigate(tab, route('/cross-device'));
      await waitFor(() => evaluate(tab, () => document.getElementById('cross-device-details')?.hidden === false));
      links.push(await evaluate(tab, () => document.getElementById('cross-device-link').value));
    }
    const aliceTab = await page(approval.browserContextId);
    const bobTab = await page(approval.browserContextId);
    async function signIn(tab, link, username) {
      await navigate(tab, link.slice(origin.length));
      await continueSignIn(tab, username);
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
    await waitFor(() => evaluate(requestPages[1], expected => location.pathname === expected && document.readyState === 'complete', route('/portal')));
    const bobCookies = (await command('Storage.getCookies', { browserContextId: requestContexts[1] })).cookies;
    const bobAccess = bobCookies.find(c => c.name === 'AUTHP_ACCESS_TOKEN');
    assert.ok(bobAccess, 'valid new approval omitted requester credentials');
    assert.equal(JSON.parse(Buffer.from(bobAccess.value.split('.')[1], 'base64url')).email, 'bob@example.test');
    await navigate(requestPages[1], '/resource');
    assert.equal(await evaluate(requestPages[1], () => document.body.textContent.trim()), 'identity resource');
    assert.ok(!(await command('Storage.getCookies', { browserContextId: requestContexts[0] })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), 'Bob reached the wrong requester');
    assertNoRuntimeErrors();
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    try {
      await disposeBrowserContexts(command, contexts);
      assertNoRuntimeErrors();
    }
    finally { socket.close(); }
  }
})().catch(error => { console.error('Stage: ' + stage + '\n' + error.message + '\n' + JSON.stringify(beginDiagnostics)); socket.close(); process.exitCode = 1; });
