// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// The Go fixture owns real Caddy and Chrome; this driver fills rendered forms.
const assert = require("node:assert/strict");
const { BrowserProtocolError, waitForRead } = require("./authorization_redirect_cdp.cjs");
const { disposeBrowserContexts } = require("./browser_contexts.cjs");
const [endpoint, origin, untrusted] = process.argv.slice(2);
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map(), responses = [];
let sequence = 0, stage = "connect", unsafeNavigation = false;

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === "Network.responseReceived") {
    const response = message.params.response;
    // Keep only bounded diagnostic metadata; never retain headers or payloads.
    responses.push({ page: message.sessionId, path: new URL(response.url).pathname,
      status: response.status, type: message.params.type });
  }
  if (message.method === "Page.frameNavigated") {
    const url = message.params.frame.url;
    if (url.includes(password) || /[?&#](access_token|refresh_token|id_token)=|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(url)) unsafeNavigation = true;
  }
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
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("browser command timed out")); }, 15000);
    pending.set(id, { resolve, reject, timer, method });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}

async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true,
    returnByValue: true, userGesture: true,
  }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}

async function page(browserContextId) {
  const { targetId } = await command("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await command("Target.attachToTarget", { targetId, flatten: true });
  await command("Page.enable", {}, sessionId);
  await command("Runtime.enable", {}, sessionId);
  await command("Network.enable", {}, sessionId);
  return sessionId;
}

async function navigate(page, target) {
  const result = await command("Page.navigate", { url: target }, page);
  assert(!result.errorText, "verified TLS navigation failed");
  await waitForRead(() => evaluate(page, target => location.href === target && document.readyState === "complete", target));
}

async function loginForm(page, secret) {
  await navigate(page, origin + "/auth/login?fresh=1");
  // A single store renders its form directly. If a realm chooser is visible,
  // select the SQLite action itself rather than overwriting a hidden realm.
  await evaluate(page, () => {
    const username = document.querySelector('input[name="username"]');
    if (username && username.getClientRects().length) return;
    const link = [...document.querySelectorAll("#authenticators a")].find(a => a.textContent.trim() === "SQLite");
    if (!link) throw new Error("SQLite login action absent");
    link.click();
  });
  await waitForRead(() => evaluate(page, () => {
    const username = document.querySelector('input[name="username"]');
    const realm = document.querySelector('[name="realm"]');
    return !!username && username.getClientRects().length > 0 && realm?.value === "staff";
  }));
  await evaluate(page, () => {
    const username = document.querySelector('input[name="username"]');
    username.value = "ALICE@EXAMPLE.TEST";
    username.dispatchEvent(new Event("input", { bubbles: true }));
    username.form.querySelector('button[type="submit"]').click();
  });
  await waitForRead(() => evaluate(page, () => {
    const secret = document.querySelector('input[name="secret"][type="password"]');
    return location.pathname.startsWith("/auth/sandbox/") && secret?.getClientRects().length > 0;
  }));
  await evaluate(page, secret => {
    const input = document.querySelector('input[name="secret"][type="password"]');
    input.value = secret;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.form.querySelector('button[type="submit"]').click();
  }, secret);
}

async function cookiePrivacy(page, context) {
  const cookies = (await command("Storage.getCookies", { browserContextId: context })).cookies;
  // deliverRefreshCookies issues access and refresh credentials. This fixture
  // has no OP: finishOIDCLogin returns immediately when p.oidc is nil, and
  // the refresh family's session ID is independent of an OP session cookie.
  const required = ["AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN"];
  const credentials = required
    .map(name => cookies.find(cookie => cookie.name === name));
  const metadata = credentials.map((cookie, index) => ({
    name: required[index], present: !!cookie?.value,
    secure: cookie?.secure === true, httpOnly: cookie?.httpOnly === true,
  }));
  assert(credentials.every(cookie => cookie?.value && cookie.secure && cookie.httpOnly),
    "browser credentials were missing or lacked Secure/HttpOnly: " + JSON.stringify(metadata));
  assert(!cookies.some(cookie => cookie.name === "AUTHP_OIDC_SESSION_ID" && cookie.value),
    "SQLite password login unexpectedly created an OP session");
  const exposed = await evaluate(page, () => JSON.stringify({
    local: Object.entries(localStorage), session: Object.entries(sessionStorage),
    visible: document.cookie, location: location.href,
  }));
  assert(!exposed.includes(password) && !credentials.some(cookie => exposed.includes(cookie.value)),
    "password or credentials escaped into browser-accessible state");
  const claims = JSON.parse(Buffer.from(credentials[0].value.split(".")[1], "base64url"));
  assert(claims.sub === "alice" && claims.origin === "staff" &&
    Array.isArray(claims.amr) && claims.amr.length === 1 && claims.amr[0] === "pwd",
    "browser credential has incorrect SQLite identity evidence");
}

async function main() {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser connection failed")), { once: true });
  });
  const contexts = new Set();
  try {
    for (const accepted of [false, true]) {
      const { browserContextId } = await command("Target.createBrowserContext");
      contexts.add(browserContextId);
      const tab = await page(browserContextId);
      stage = "reject untrusted TLS";
      const rejected = await command("Page.navigate", { url: untrusted }, tab);
      assert(/ERR_CERT_/.test(rejected.errorText || ""), "untrusted TLS accepted");
      stage = accepted ? "rendered SQLite login" : "wrong password through rendered form";
      await loginForm(tab, accepted ? password : "Incorrect-sqlite-browser-password!");
      if (!accepted) {
        await waitForRead(() => responses.some(response => response.page === tab &&
          response.type === "Document" && response.path.startsWith("/auth/sandbox/") && response.status === 401));
        await waitForRead(() => evaluate(tab, () => document.readyState === "complete" && location.pathname.startsWith("/auth/sandbox/")));
        const cookies = (await command("Storage.getCookies", { browserContextId })).cookies;
        assert(!cookies.some(cookie => ["AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"].includes(cookie.name) && cookie.value),
          "wrong password created credentials");
        const denied = await evaluate(tab, async () => {
          const response = await fetch("/resource", { cache: "no-store" });
          return response.status === 401 || response.status === 403;
        });
        assert(denied, "wrong password reached the protected resource");
      } else {
        stage = "portal session bootstrap";
        await waitForRead(() => evaluate(tab, () => location.pathname === "/auth/portal" &&
          document.readyState === "complete" && !!window.AuthCrunchSession));
        await cookiePrivacy(tab, browserContextId);
        stage = "browser session refresh";
        assert(await evaluate(tab, async () => {
          const refreshed = await AuthCrunchSession.refresh(true);
          return typeof refreshed.session_id === "string" && refreshed.session_id.length > 0;
        }), "embedded browser client could not refresh SQLite identity");
        await cookiePrivacy(tab, browserContextId);
        stage = "protected resource with browser cookies";
        await navigate(tab, origin + "/resource");
        assert(await evaluate(tab, () => document.body.textContent.trim() === "identity resource"),
          "authenticated browser did not reach the protected resource");
      }
      await disposeBrowserContexts(command, contexts);
    }
    assert(!unsafeNavigation, "credential appeared in browser navigation");
    process.stdout.write("SQLite identity browser passed\n");
  } finally {
    await disposeBrowserContexts(command, contexts);
  }
}

main().catch(error => {
  // Controlled diagnostic messages never include expressions, HTTP bodies,
  // cookies or raw protocol errors, any of which can contain credentials.
  const safe = error instanceof BrowserProtocolError || error instanceof assert.AssertionError
    ? error.message : "browser operation failed";
  process.stderr.write(stage + ": " + safe + "\n");
  process.exitCode = 1;
}).finally(() => socket.close());
