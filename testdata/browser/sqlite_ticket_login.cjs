// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Only rendered UI issues the ticket. The Go fixture supplies private trust and
// synthetic issuer credentials; this driver never installs authentication state.
const assert = require("node:assert/strict");
const { createHmac, timingSafeEqual } = require("node:crypto");
const { BrowserProtocolError, waitForRead } = require("./authorization_redirect_cdp.cjs");
const { disposeBrowserContexts } = require("./browser_contexts.cjs");
const [endpoint, untrusted] = process.argv.slice(2);
const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const mount = input.mount.replace(/\/$/, "");
const socket = new WebSocket(endpoint);
const pending = new Map(), responses = [];
let sequence = 0, stage = "connect", unsafeNavigation = false;

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === "Network.responseReceived") {
    const response = message.params.response;
    const target = new URL(response.url);
    responses.push({ page: message.sessionId, origin: target.origin,
      path: target.pathname, status: response.status, type: message.params.type });
  }
  if (message.method === "Page.frameNavigated") {
    const target = message.params.frame.url;
    if (target.includes(input.password) || /[?&#](access_token|refresh_token|id_token)=|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(target)) unsafeNavigation = true;
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
  assert(!result.errorText, "browser navigation failed: " +
    (/^net::ERR_[A-Z0-9_]+$/.test(result.errorText || "") ? result.errorText : "unclassified"));
  await waitForRead(() => evaluate(page, target => location.href === target && document.readyState === "complete", target));
}

async function cookies(context) {
  return (await command("Storage.getCookies", { browserContextId: context })).cookies;
}

function credentialCookies(values) {
  return values.filter(cookie => ["TICKET_ACCESS_TOKEN", "TICKET_REFRESH_TOKEN", "TICKET_OIDC_SESSION_ID"].includes(cookie.name) && cookie.value);
}

async function issuerForm(tab, context, password) {
  await navigate(tab, input.origin + mount + "/login?redirect_url=" + encodeURIComponent(input.destination));
  assert(await evaluate(tab, mount => {
    const link = [...document.querySelectorAll("#authenticators a")]
      .find(a => a.textContent.trim() === "Application sign-in");
    if (!link || !link.getClientRects().length) return false;
    const target = new URL(link.href);
    if (target.pathname !== mount + "/provider/application" || target.search !== "") return false;
    link.click();
    return true;
  }, mount), "rendered ticket icon lost its canonical path or added redirect query");
  await waitForRead(() => evaluate(tab, issuer => location.origin === issuer && location.pathname === "/login" &&
    document.readyState === "complete" && !!document.querySelector('input[name="password"]'), input.issuer));
  const values = await cookies(context);
  const binding = values.filter(cookie => cookie.name === "APP_TICKET_BINDING");
  assert(binding.length === 1 && binding[0].value && binding[0].secure && binding[0].httpOnly &&
    binding[0].sameSite === "Lax" && binding[0].path === mount + "/provider/application" &&
    binding[0].domain === new URL(input.origin).hostname,
    "ticket binding cookie changed name, scope or browser protections");
  assert(!credentialCookies(values).length, "issuer was reached with premature portal credentials");
  assert(await evaluate(tab, () => !document.cookie.includes("APP_TICKET_BINDING") &&
    !document.cookie.includes("TICKET_ACCESS_TOKEN")), "portal cookie escaped its host or HttpOnly scope");
  await evaluate(tab, secret => {
    const user = document.querySelector('input[name="username"]');
    const password = document.querySelector('input[name="password"]');
    user.value = "alice";
    password.value = secret;
    user.dispatchEvent(new Event("input", { bubbles: true }));
    password.dispatchEvent(new Event("input", { bubbles: true }));
    password.form.querySelector('button[type="submit"]').click();
  }, password);
}

async function verifyAccess(tab, context) {
  const values = await cookies(context);
  const credentials = credentialCookies(values);
  assert(credentials.length === 1 && credentials[0].name === "TICKET_ACCESS_TOKEN" &&
    credentials[0].secure && credentials[0].httpOnly && credentials[0].domain === new URL(input.origin).hostname,
    "ticket login failed access-only secure host-only cookie contract: " + JSON.stringify(credentials.map(cookie => ({
      name: cookie.name, secure: cookie.secure, httpOnly: cookie.httpOnly,
      hostOnly: cookie.domain === new URL(input.origin).hostname,
      rootPath: cookie.path === "/", sameSite: cookie.sameSite,
    }))));
  assert(!values.some(cookie => cookie.name === "APP_TICKET_BINDING" && cookie.value),
    "consumed ticket retained browser binding");
  const raw = credentials[0].value;
  const parts = raw.split(".");
  assert(parts.length === 3, "browser access credential was not a JWT");
  const header = JSON.parse(Buffer.from(parts[0], "base64url"));
  assert(header.alg === "HS512", "browser credential changed signing algorithm");
  const expected = createHmac("sha512", input.signing).update(parts[0] + "." + parts[1]).digest();
  const actual = Buffer.from(parts[2], "base64url");
  assert(actual.length === expected.length && timingSafeEqual(actual, expected),
    "browser JWT failed independent signature validation");
  const claims = JSON.parse(Buffer.from(parts[1], "base64url"));
  const now = Date.now() / 1000;
  assert(claims.sub === "alice" && claims.email === "alice@example.test" && claims.name === "Alice Ticket" &&
    claims.origin === "application" && typeof claims.id === "string" && claims.id && claims.id !== claims.sub &&
    typeof claims.nonce === "string" && claims.nonce && Array.isArray(claims.amr) && claims.amr.length === 1 &&
    claims.amr[0] === "federated" && Array.isArray(claims.roles) && claims.roles.length === 2 &&
    claims.roles.includes("app/issued") && claims.roles.includes("app/verified") &&
    claims.iat <= now + 1 && claims.exp > now && claims.exp - claims.iat <= 121 &&
    claims.auth_time <= now + 1 && claims.auth_time >= now - 120,
    "browser JWT lost identity, policy, lifetime or verified authentication evidence");
  const exposed = await evaluate(tab, () => JSON.stringify({ local: Object.entries(localStorage),
    session: Object.entries(sessionStorage), visible: document.cookie, location: location.href }));
  assert(!exposed.includes(raw) && !exposed.includes(input.password),
    "ticket credentials escaped into browser-accessible state");
  return { id: claims.id, nonce: claims.nonce };
}

async function main() {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser connection failed")), { once: true });
  });
  const contexts = new Set();
  let previous;
  try {
    for (const accepted of [false, true, true]) {
      const { browserContextId } = await command("Target.createBrowserContext");
      contexts.add(browserContextId);
      const tab = await page(browserContextId);
      stage = "reject untrusted TLS";
      const rejected = await command("Page.navigate", { url: untrusted }, tab);
      assert(/ERR_CERT_/.test(rejected.errorText || ""), "browser accepted an untrusted TLS certificate");
      stage = accepted ? "rendered authenticated issuer login" : "wrong issuer password";
      await issuerForm(tab, browserContextId, accepted ? input.password : "Incorrect-ticket-issuer-password!");
      if (!accepted) {
        await waitForRead(() => responses.some(response => response.page === tab && response.type === "Document" &&
          response.origin === input.issuer && response.path === "/login" && response.status === 401));
        assert(!credentialCookies(await cookies(browserContextId)).length, "wrong issuer credentials created portal access");
        await navigate(tab, input.origin + mount + "/login");
        assert(await evaluate(tab, async () => {
          const response = await fetch("/resource", { cache: "no-store", redirect: "manual" });
          return response.status === 401;
        }), "wrong issuer credentials reached protected application");
      } else {
        stage = "ticket callback and trusted destination";
        try {
          await waitForRead(() => evaluate(tab, destination => location.href === destination &&
            document.readyState === "complete" && document.body.textContent.trim() === "ticket resource", input.destination));
        } catch (_) {
          const state = await evaluate(tab, expected => ({
            atDestination: location.href === expected.destination,
            onPortal: location.origin === expected.origin,
            atCallback: location.pathname === expected.mount + "/provider/application",
            atResource: location.pathname === "/resource",
            complete: document.readyState === "complete",
            resourceBody: document.body.textContent.trim() === "ticket resource",
          }), { destination: input.destination, origin: input.origin, mount });
          const stored = await cookies(browserContextId);
          state.accessCookies = credentialCookies(stored).length;
          state.bindingCookies = stored.filter(cookie => cookie.name === "APP_TICKET_BINDING").length;
          state.responses = responses.filter(response => response.page === tab && response.type === "Document")
            .slice(-8).map(response => ({
              origin: response.origin === input.origin ? "portal" : response.origin === input.issuer ? "issuer" : "other",
              route: response.path === "/resource" ? "resource" : response.path === mount + "/provider/application" ? "callback" :
                response.path === mount + "/login" ? "portal_login" : response.path === "/login" ? "issuer_login" : "other",
              status: response.status,
            }));
          assert.fail("ticket browser destination mismatch: " + JSON.stringify(state));
        }
        const identity = await verifyAccess(tab, browserContextId);
        if (previous) assert(identity.id === previous.id && identity.nonce !== previous.nonce,
          "fresh browser changed live implicit identity or reused its nonce");
        previous = identity;
        await navigate(tab, input.origin + "/resource");
        assert(await evaluate(tab, () => document.body.textContent.trim() === "ticket resource"),
          "browser cookie did not authorize protected resource");
        stage = "portal logout";
        const result = await command("Page.navigate", { url: input.origin + mount + "/logout" }, tab);
        assert(!result.errorText, "logout TLS navigation failed");
        await waitForRead(async () => !credentialCookies(await cookies(browserContextId)).length);
        await navigate(tab, input.origin + mount + "/login");
        assert(await evaluate(tab, async () => {
          const response = await fetch("/resource", { cache: "no-store", redirect: "manual" });
          return response.status === 401;
        }), "logout retained protected browser access");
      }
      await disposeBrowserContexts(command, contexts);
    }
    assert(!unsafeNavigation, "password or access credential appeared in navigation");
    process.stdout.write("SQLite ticket browser passed\n");
  } finally {
    await disposeBrowserContexts(command, contexts);
  }
}

main().catch(error => {
  const safe = error instanceof BrowserProtocolError || error instanceof assert.AssertionError
    ? error.message : "browser operation failed";
  process.stderr.write(stage + ": " + safe + "\n");
  process.exitCode = 1;
}).finally(() => socket.close());
