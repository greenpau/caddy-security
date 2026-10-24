// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// The Go fixture owns actual Caddy, trusted Chrome, and the verifying TLS RP.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { BrowserProtocolError, waitForRead } = require('./authorization_redirect_cdp.cjs');
const { disposeBrowserContexts } = require('./browser_contexts.cjs');
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const credentials = JSON.parse(fs.readFileSync(0, 'utf8'));
const socket = new WebSocket(endpoint);
const pending = new Map();
const documents = new Map();
const consentPosts = [];
const cancellations = new Map();
const exceptions = [];
let exceptionCount = 0;
let sequence = 0;
let stage = 'connect';

// Fixed browser oracles; do not import or derive expectations from the catalog.
const languages = {
  fr: {
    direction: 'ltr', proceed: 'Continuer', password: 'Veuillez saisir votre mot de passe',
    retry: 'Réessayer', invalidPassword: 'Nous n’avons pas pu vérifier vos identifiants. Vérifiez-les et réessayez.',
    logo: 'Portail d’authentification', description: 'Authentifie les utilisateurs.',
    waiting: 'En attente d’approbation. Ce lien expire dans cinq minutes.',
    cancelledTitle: 'Connexion annulée',
    cancelled: 'Cette demande de connexion a été annulée. Recommencez quand vous le souhaitez.',
    restart: 'Recommencer', consent: 'Autoriser l’application', permission: 'Identifiant du compte',
    account: 'Connecté en tant que', allow: 'Autoriser l’accès', deny: 'Refuser',
    error: 'Impossible de continuer',
    invalidRequest: 'Cette demande de connexion est invalide ou a expiré. Retournez dans l’application et reconnectez-vous.',
  },
  ar: {
    direction: 'rtl', proceed: 'متابعة', password: 'يرجى إدخال كلمة المرور',
    retry: 'إعادة المحاولة', invalidPassword: 'تعذر التحقق من بيانات اعتمادك. تحقق منها وحاول مرة أخرى.',
    logo: 'بوابة المصادقة', description: 'يُجري مصادقة المستخدمين.',
    waiting: 'في انتظار الموافقة. تنتهي صلاحية هذا الرابط خلال خمس دقائق.',
    cancelledTitle: 'تم إلغاء تسجيل الدخول',
    cancelled: 'تم إلغاء طلب تسجيل الدخول هذا. ابدأ من جديد عندما تكون مستعداً.',
    restart: 'البدء من جديد',
  },
};

function header(headers, name) {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1] || '';
}

socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Runtime.exceptionThrown') {
    exceptionCount++;
    if (exceptions.length < 10) {
      const details = message.params.exceptionDetails;
      exceptions.push({ stage, category: 'uncaught-script', line: details.lineNumber, column: details.columnNumber });
    }
  }
  if (message.method === 'Network.responseReceived') {
    const response = message.params.response;
    if (message.params.type === 'Document') {
      // Retain only the public policy fields, never response URLs or cookies.
      documents.set(message.sessionId, {
        status: response.status, type: header(response.headers, 'content-type'),
        cache: header(response.headers, 'cache-control'), csp: header(response.headers, 'content-security-policy'),
        referrer: header(response.headers, 'referrer-policy'),
      });
    }
    if (config.portals.some(portal => response.url === config.origin + portal.mount + '/cross-device/cancel')) {
      const count = cancellations.get(message.sessionId)?.count || 0;
      cancellations.set(message.sessionId, { count: count + 1, status: response.status });
    }
  }
  if (message.method === 'Network.requestWillBeSent') {
    const request = message.params.request;
    const portal = config.portals.find(portal => portal.language === config.op.language);
    if (request.url === config.origin + portal.mount + '/oidc/continue' && request.method === 'POST') {
      consentPosts.push({ method: request.method, sameOrigin: header(request.headers, 'origin') === config.origin });
    }
  }
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

async function waitFor(read) { await waitForRead(read, { timeout: 25000 }); }

async function page(contextId) {
  const { targetId } = await command('Target.createTarget', { url: 'about:blank', browserContextId: contextId });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Network', 'Runtime']) await command(domain + '.enable', {}, sessionId);
  return sessionId;
}

async function navigate(tab, url, selector) {
  await evaluate(tab, () => { window.localizationNavigating = true; });
  documents.delete(tab);
  const result = await command('Page.navigate', { url }, tab);
  if (result.errorText) throw new Error('trusted browser navigation failed');
  await waitFor(() => evaluate(tab, selector => !window.localizationNavigating && document.readyState === 'complete' &&
    !!document.querySelector(selector), selector));
}

async function click(tab, selector) {
  await command('Page.bringToFront', {}, tab);
  const point = await evaluate(tab, selector => {
    const element = document.querySelector(selector);
    if (!element) throw new Error('missing browser action');
    element.scrollIntoView({ block: 'center' });
    const box = element.getClientRects()[0];
    return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  }, selector);
  for (const type of ['mousePressed', 'mouseReleased']) {
    await command('Input.dispatchMouseEvent', { type, button: 'left', clickCount: 1, ...point }, tab);
  }
}

async function text(tab, selector) {
  return evaluate(tab, selector => document.querySelector(selector)?.textContent.trim(), selector);
}

function noExceptions() {
  assert.ok(exceptionCount === 0, 'asynchronous browser exceptions: ' + JSON.stringify(exceptions));
}

async function noCredentials(contextId) {
  const { cookies } = await command('Storage.getCookies', { browserContextId: contextId });
  assert.ok(!cookies.some(cookie => /_(ACCESS_TOKEN|REFRESH_TOKEN|OIDC_SESSION_ID)$/.test(cookie.name)),
    'unfinished localized login issued authentication credentials');
}

async function screenshot(tab, name) {
  if (!config.screenshotDir) return;
  assert.match(name, /^(fr|ar)-(login|cross-device-cancelled|consent)-(390|1280)$/);
  await evaluate(tab, async () => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  const { cssContentSize, cssLayoutViewport } = await command('Page.getLayoutMetrics', {}, tab);
  const beyondViewport = cssContentSize.height > cssLayoutViewport.clientHeight || cssContentSize.width > cssLayoutViewport.clientWidth;
  const { data } = await command('Page.captureScreenshot', {
    format: 'png', captureBeyondViewport: beyondViewport,
    ...(beyondViewport ? { clip: { ...cssContentSize, scale: 1 } } : {}),
  }, tab);
  fs.writeFileSync(path.join(config.screenshotDir, name + '.png'), Buffer.from(data, 'base64'), { mode: 0o600, flag: 'wx' });
}

async function layout(tab, portal, name, capture = false) {
  const expected = languages[portal.language];
  const previousStage = stage;
  for (const width of [390, 1280]) {
    stage = previousStage + ' layout ' + width;
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 }, tab);
    await waitFor(() => evaluate(tab, () => [...document.images].filter(image => image.getClientRects().length).every(image => image.complete)));
    const state = await evaluate(tab, async () => {
      await document.fonts.ready;
      const visible = element => element.getClientRects().length > 0;
      const input = document.querySelector('#username');
      const icon = input?.parentElement.querySelector('.app-inp-prf-img');
      const inputBox = input?.getBoundingClientRect();
      const iconBox = icon?.getBoundingClientRect();
      return {
        lang: document.documentElement.lang, dir: document.documentElement.dir,
        direction: getComputedStyle(document.body).direction,
        fits: document.documentElement.scrollWidth <= innerWidth + 1 &&
          [...document.querySelectorAll('button,input:not([type="hidden"]),textarea')].filter(visible).every(element => {
            const box = element.getBoundingClientRect();
            return box.left >= -0.5 && box.right <= innerWidth + 0.5 && element.scrollWidth <= element.clientWidth + 1 &&
              (element.tagName !== 'BUTTON' || box.height <= 112);
          }),
        images: [...document.images].filter(visible).every(image => image.naturalWidth > 0),
        iconRight: iconBox ? iconBox.x + iconBox.width / 2 > inputBox.x + inputBox.width / 2 : null,
        injectionAbsent: !document.getElementById('localization-injected') && !document.getElementById('localization-client-injected'),
      };
    });
    assert.equal(state.lang, portal.language, 'document language');
    assert.equal(state.dir, expected.direction, 'document direction');
    assert.equal(state.direction, expected.direction, 'computed text direction');
    assert.ok(state.fits && state.images, 'localized controls or images overflowed or failed to render');
    assert.ok(state.injectionAbsent, 'literal metadata or client name became markup');
    if (state.iconRight !== null) assert.equal(state.iconRight, expected.direction === 'rtl', 'username icon did not follow text direction');
    if (capture) await screenshot(tab, portal.language + '-' + name + '-' + width);
  }
  await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 900, deviceScaleFactor: 1, mobile: true }, tab);
  stage = previousStage;
}

async function crossDevice(tab, contextId, portal) {
  const expected = languages[portal.language];
  stage = portal.language + ' localized cross-device script';
  await click(tab, '#cross-device-link a');
  await waitFor(() => evaluate(tab, () => document.getElementById('cross-device-details')?.hidden === false &&
    document.getElementById('cross-device-qr').complete && document.getElementById('cross-device-qr').naturalWidth === 256));
  const before = await evaluate(tab, expected => {
    const script = document.querySelector('script[src$="/cross_device.js"]');
    const messages = JSON.parse(script.dataset.i18n);
    const code = document.getElementById('cross-device-code');
    const link = document.getElementById('cross-device-link');
    return {
      code: code.textContent, link: link.value,
      ltr: code.dir === 'ltr' && getComputedStyle(code).direction === 'ltr' && link.dir === 'ltr',
      messages: messages.cross_device_waiting === expected.waiting && messages.cross_device_cancelled === expected.cancelled &&
        messages.cross_device_cancelled_title === expected.cancelledTitle,
      waiting: document.getElementById('cross-device-status').textContent === expected.waiting,
    };
  }, expected);
  assert.ok(before.ltr && before.messages && before.waiting, 'localized script messages or LTR code/link changed');
  await layout(tab, portal, 'cross-device-request');
  await noCredentials(contextId);
  const previousCancellations = cancellations.get(tab)?.count || 0;
  await click(tab, '#cross-device-cancel');
  await waitFor(() => evaluate(tab, expected => document.getElementById('cross-device-title').textContent === expected.cancelledTitle &&
    document.getElementById('cross-device-status').textContent === expected.cancelled && document.getElementById('cross-device-details').hidden &&
    document.getElementById('cross-device-controls').hidden && !document.getElementById('cross-device-recovery').hidden, expected));
  await waitFor(() => (cancellations.get(tab)?.count || 0) > previousCancellations);
  assert.equal(cancellations.get(tab).status, 200, 'localized cancellation protocol status');
  assert.equal(await text(tab, '#cross-device-recovery a'), expected.restart, 'localized recovery action');
  assert.ok(await evaluate(tab, expected => document.title.endsWith(expected.cancelledTitle), expected), 'cancelled browser title did not update');
  await layout(tab, portal, 'cross-device-cancelled', true);
  await click(tab, '#cross-device-recovery a');
  await waitFor(() => evaluate(tab, previous => document.getElementById('cross-device-details')?.hidden === false &&
    document.getElementById('cross-device-code').textContent !== previous.code &&
    document.getElementById('cross-device-link').value !== previous.link, before));
  assert.ok(await evaluate(tab, expected => document.getElementById('cross-device-status').textContent === expected.waiting, expected),
    'recovery did not consume the configured language messages');
  await noCredentials(contextId);
}

async function login(tab, contextId, portal) {
  const expected = languages[portal.language];
  stage = portal.language + ' login presentation';
  await navigate(tab, config.origin + portal.mount + '/login', '#username');
  assert.equal(await text(tab, '#loginform button[type="submit"]'), expected.proceed, 'localized login action');
  assert.ok(await evaluate(tab, ({ expected, metaTitle }) =>
    document.querySelector('.logo-img')?.alt === expected.logo &&
    document.querySelector('meta[name="description"]')?.content === expected.description &&
    (!metaTitle || document.title.startsWith(metaTitle + ' - ')), { expected, metaTitle: portal.metaTitle }),
  'localized defaults or literal metadata title changed');
  await layout(tab, portal, 'login', true);
  await crossDevice(tab, contextId, portal);
  stage = portal.language + ' password failure and retry';
  await navigate(tab, config.origin + portal.mount + '/login', '#username');
  await evaluate(tab, () => { const input = document.getElementById('username'); input.value = 'alice'; input.form.requestSubmit(); });
  await waitFor(() => evaluate(tab, () => !!document.getElementById('secret')));
  assert.equal(await text(tab, 'label[for="secret"]'), expected.password, 'localized password instruction');
  await layout(tab, portal, 'password');
  await evaluate(tab, password => { const input = document.getElementById('secret'); input.value = password; input.form.requestSubmit(); }, credentials.wrongPassword);
  await waitFor(() => evaluate(tab, () => !!document.querySelector('.app-txt-section') && !document.getElementById('secret')));
  const failure = documents.get(tab);
  assert.ok(failure?.status === 401 && failure.type === 'text/html; charset=utf-8' && failure.cache.includes('no-store'),
    'localized password failure changed its HTTP status/media/cache policy');
  assert.ok(await evaluate(tab, expected => document.querySelector('.app-container').textContent.includes(expected.invalidPassword), expected),
    'incorrect password did not render the localized failure');
  assert.equal(await text(tab, 'a[href*="/sandbox/"]'), expected.retry, 'localized retry action');
  await noCredentials(contextId);
  await layout(tab, portal, 'password-error');
  assert.ok(await evaluate(tab, expected => {
    const retry = new URL(document.querySelector('a[href*="/sandbox/"]').href);
    return retry.origin === location.origin && retry.pathname.startsWith(expected + '/sandbox/');
  }, portal.mount), 'retry left the current portal sandbox');
  await click(tab, 'a[href*="/sandbox/"]');
  await waitFor(() => evaluate(tab, () => !!document.getElementById('secret')));
  await evaluate(tab, password => { const input = document.getElementById('secret'); input.value = password; input.form.requestSubmit(); }, credentials.password);
  await waitFor(() => evaluate(tab, expected => location.pathname === expected && document.readyState === 'complete', portal.mount + '/portal'));
  const { cookies } = await command('Storage.getCookies', { browserContextId: contextId });
  const access = cookies.find(cookie => cookie.name === portal.cookiePrefix + '_ACCESS_TOKEN');
  assert.ok(access && access.secure && access.httpOnly, 'successful localized login omitted its private access cookie');
  await navigate(tab, portal.resource, 'body');
  assert.ok(await evaluate(tab, () => document.body.textContent.trim() === 'localized resource'), 'localized login did not authorize protected access');
  noExceptions();
}

function consentPolicy(tab, expectedStatus, consent) {
  const response = documents.get(tab);
  assert.ok(response && response.status === expectedStatus && response.type === 'text/html; charset=utf-8' &&
    response.cache.includes('no-store'), 'localized OP response changed its HTTP status/media/cache policy');
  const directives = new Map(response.csp.split(';').map(value => value.trim().split(/\s+/)).filter(parts => parts[0])
    .map(([name, ...values]) => [name, values]));
  assert.deepEqual(directives.get('default-src'), ["'none'"], 'OP default CSP');
  assert.deepEqual(directives.get('frame-ancestors'), ["'none'"], 'OP frame CSP');
  assert.deepEqual(directives.get('base-uri'), ["'none'"], 'OP base CSP');
  assert.deepEqual(directives.get('img-src'), ["'self'"], 'OP image CSP');
  assert.deepEqual(directives.get('font-src'), ["'self'"], 'OP font CSP');
  const style = directives.get('style-src');
  assert.ok(style?.length === 2 && style[0] === "'self'" && /^'nonce-[A-Za-z0-9_-]+'$/.test(style[1]), 'OP style CSP lost its nonce binding');
  assert.equal(directives.size, 7, 'OP acquired an unexpected CSP directive');
  assert.deepEqual(directives.get('form-action'), consent ? ["'self'", new URL(config.op.callbackURL).origin] : ["'self'"], 'OP form CSP');
  assert.equal(response.referrer, consent ? 'same-origin' : 'no-referrer', 'OP referrer policy');
}

async function oidc(tab, portal) {
  const expected = languages[portal.language];
  for (const decision of ['deny', 'allow']) {
    stage = 'localized OP native ' + decision;
    await navigate(tab, decision === 'deny' ? config.op.authorizeDeny : config.op.authorizeAllow, 'button[value="allow"]');
    consentPolicy(tab, 200, true);
    assert.equal(await text(tab, '#oidc-title'), expected.consent, 'localized consent heading');
    assert.equal(await text(tab, '.oidc-account-label'), expected.account, 'localized consent account label');
    assert.equal(await text(tab, 'button[value="allow"]'), expected.allow, 'localized allow action');
    assert.equal(await text(tab, 'button[value="deny"]'), expected.deny, 'localized deny action');
    assert.ok(await evaluate(tab, ({ clientName, permission, mount }) => {
      const client = document.querySelector('.oidc-client');
      const account = document.querySelector('.oidc-username');
      const form = document.querySelector('form.oidc-actions');
      const csrf = form.querySelectorAll('input[name="csrf"]');
      return client.textContent === clientName && client.children.length === 0 && client.dir === 'auto' && account.dir === 'auto' &&
        !document.getElementById('localization-client-injected') && document.querySelector('.oidc-permission-list').textContent.includes(permission) &&
        form.method === 'post' && form.action === location.origin + mount + '/oidc/continue' &&
        csrf.length === 1 && !!csrf[0].value &&
        [...form.querySelectorAll('button')].every(button => button.name === 'decision' && ['allow', 'deny'].includes(button.value));
    }, { clientName: config.op.clientName, permission: expected.permission, mount: portal.mount }),
    'localized consent changed escaped literals or native protocol fields');
    await layout(tab, portal, 'consent', decision === 'deny');
    const postsBefore = consentPosts.length;
    await click(tab, 'button[value="' + decision + '"]');
    await waitFor(() => evaluate(tab, ({ callbackURL, decision }) => {
      const target = new URL(callbackURL);
      return location.origin === target.origin && location.pathname === target.pathname && document.readyState === 'complete' &&
        document.getElementById('localization-callback')?.dataset.outcome === decision;
    }, { callbackURL: config.op.callbackURL, decision }));
    assert.ok(consentPosts.length === postsBefore + 1 && consentPosts[postsBefore].sameOrigin,
      'native consent omitted the actual matching Origin or submitted more than once');
    assert.equal(documents.get(tab)?.status, 200, 'verifying relying party rejected the protocol callback');
  }
  stage = 'localized OP invalid request';
  await navigate(tab, config.op.errorURL, '#oidc-title');
  consentPolicy(tab, 400, false);
  assert.equal(await text(tab, '#oidc-title'), expected.error, 'localized OP error heading');
  assert.equal(await text(tab, '.oidc-intro'), expected.invalidRequest, 'localized OP error explanation');
  assert.ok(await evaluate(tab, () => !document.querySelector('form')), 'generic OP error unexpectedly acquired a consent form');
  await layout(tab, portal, 'oidc-error');
  noExceptions();
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  const contexts = new Set();
  const tabs = new Map();
  try {
    assert.ok(config.portals.length === 2 && config.portals.every(portal => languages[portal.language]), 'unsupported localization fixture');
    for (const portal of config.portals) {
      const { browserContextId } = await command('Target.createBrowserContext');
      contexts.add(browserContextId);
      const tab = await page(browserContextId);
      tabs.set(portal.language, tab);
      await login(tab, browserContextId, portal);
    }
    const opPortal = config.portals.find(portal => portal.language === config.op.language);
    assert.ok(opPortal, 'missing localized OP portal');
    await oidc(tabs.get(opPortal.language), opPortal);
  } finally {
    try {
      await disposeBrowserContexts(command, contexts);
      noExceptions();
    } finally { socket.close(); }
  }
  process.stdout.write(JSON.stringify({ passed: true }));
})().catch(error => {
  console.error('Stage: ' + stage + '\n' + error.message);
  socket.close();
  process.exitCode = 1;
});
