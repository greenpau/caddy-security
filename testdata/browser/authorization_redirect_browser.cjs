// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Actual Caddy navigation and HTML forms through Chrome's verified TLS stack.
const assert = require("node:assert/strict");
const { BrowserProtocolError, waitForRead } = require("./authorization_redirect_cdp.cjs");
const [endpoint, application, portal, protocol, untrusted, wrongName] = process.argv.slice(2);
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map(), responses = [];
let sequence = 0, stage = "connect";
socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === "Network.responseReceived") responses.push(message.params.response);
  if (message.method === "Network.requestWillBeSent" && message.params.redirectResponse) responses.push(message.params.redirectResponse);
  if (!message.id) return;
  const call = pending.get(message.id);
  if (!call) return;
  pending.delete(message.id); clearTimeout(call.timer);
  if (message.error) call.reject(new BrowserProtocolError(call.method, message.error)); else call.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(method+" timed out")); }, 10000);
    pending.set(id, { resolve, reject, timer, method }); socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", { expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}
async function navigationReadControl(page) {
  const initial = portal+"/login?fresh=1";
  const start = await command("Page.navigate", {url:initial}, page);
  assert(!start.errorText, "polling control navigation failed");
  await waitForRead(() => evaluate(page, url => location.href === url && document.readyState === "complete", initial));
  const destination = portal+"/login?fresh=1&polling=1";
  let first = true, interrupted = false, failure;
  // Leave a real browser read pending, then destroy its context by navigating.
  // This makes the polling race deterministic for every negotiated protocol.
  const pendingRead = waitForRead(async () => {
    if (first) {
      first = false;
      try {
        return await evaluate(page, () => (window.__redirectPendingRead = new Promise(() => { window.__redirectReadStarted = true; })));
      } catch (error) {
        interrupted = error instanceof BrowserProtocolError && error.contextUnavailable;
        throw error;
      }
    }
    return evaluate(page, url => location.href === url && document.readyState === "complete", destination);
  }).catch(error => { failure = error; });
  await waitForRead(async () => {
    if (failure) throw failure;
    return evaluate(page, () => window.__redirectReadStarted === true);
  });
  const navigation = await command("Page.navigate", {url:destination}, page);
  assert(!navigation.errorText, "polling control replacement failed");
  await pendingRead;
  if (failure) throw failure;
  assert(interrupted, "polling control did not destroy an in-flight execution context");
}
async function main() {
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, {once:true}); socket.addEventListener("error", reject, {once:true}); });
  for (const mode of ["local", "oauth", "js"]) {
    stage = mode;
    const { browserContextId } = await command("Target.createBrowserContext");
    const { targetId } = await command("Target.createTarget", {url:"about:blank", browserContextId});
    const { sessionId: page } = await command("Target.attachToTarget", {targetId, flatten:true});
    await command("Page.enable", {}, page); await command("Runtime.enable", {}, page); await command("Network.enable", {}, page);
    // Prove normal certificate and hostname validation before the journey.
    for (const url of [untrusted, wrongName]) {
      const result = await command("Page.navigate", {url}, page);
      assert.match(result.errorText || "", /ERR_CERT_/, "invalid TLS was accepted");
    }
    if (mode === "local") {
      stage = "navigation polling control";
      await navigationReadControl(page);
      stage = mode;
    }
    responses.length = 0;
    await command("Network.setExtraHTTPHeaders", {headers:{"X-Test-Policy":mode}}, page);
    const path = "/files/a%2fb?x=one%26two&x=three+four";
    const expected = application+path+(mode === "js" ? "#part%202" : "");
    const navigation = await command("Page.navigate", {url:expected}, page);
    assert(!navigation.errorText, "application navigation failed: "+navigation.errorText);
    if (mode !== "oauth") {
      stage = mode+": wait for username";
      await waitForRead(() => evaluate(page, () => !!document.querySelector('input[name="username"]')));
      const loginURL = await evaluate(page, () => location.href);
      assert.equal(new URL(loginURL).origin, portal);
      assert.equal(new URL(loginURL).searchParams.get("redirect_url"), expected);
      stage = mode+": submit username";
      await evaluate(page, () => {
        document.querySelector('[name="username"]').value = "alice";
        document.querySelector('[name="realm"]').value = "local";
        document.querySelector('[name="username"]').form.requestSubmit();
      });
      stage = mode+": wait for password";
      await waitForRead(() => evaluate(page, () => !!document.querySelector('input[name="secret"][type="password"]')));
      stage = mode+": submit password";
      await evaluate(page, password => {
        const secret = document.querySelector('input[name="secret"][type="password"]');
        secret.value = password; secret.form.requestSubmit();
      }, password);
    }
    stage = mode+": wait for protected resource";
    await waitForRead(() => evaluate(page, expected => location.href === expected && document.readyState === "complete", expected));
    assert.equal(await evaluate(page, () => document.body.textContent), path, "protected resource not returned");
    const appResponses = responses.filter(r => r.url.startsWith(application+"/"));
    const redirect = appResponses.find(r => r.status === 302);
    assert(redirect, "missing actual unauthorized response");
    const location = Object.entries(redirect.headers).find(([k]) => k.toLowerCase() === "location")?.[1];
    if (mode !== "js") {
      const destination = new URL(location);
      assert.equal(destination.origin, portal);
      assert.equal(destination.pathname, mode === "oauth" ? "/oauth2/upstream/authorization-code-callback" : "/login");
      assert.equal(destination.searchParams.get("redirect_url"), expected);
    }
    const authorized = appResponses.find(r => r.status === 200);
    assert(authorized && Object.entries(authorized.headers).some(([k,v]) => k.toLowerCase() === "x-protected-user" && v), "missing authorization evidence");
    const expectedProtocol = {1:"http/1.1",2:"h2",3:"h3"}[protocol];
    const serving = responses.filter(r => r.url.startsWith(application+"/") || r.url.startsWith(portal+"/"));
    assert(serving.some(r => r.url.startsWith(portal+"/")), "portal flow missing");
    for (const r of serving) assert.equal(r.protocol, expectedProtocol, "browser fell back to another protocol");
    await command("Target.disposeBrowserContext", {browserContextId});
  }
  process.stdout.write("redirect browser passed\n");
}
main().catch(error => { process.stderr.write(stage+": "+error.message+"\n"); process.exitCode = 1; }).finally(() => socket.close());
