// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Actual Caddy navigation and HTML forms through Chrome's verified TLS stack.
const assert = require("node:assert/strict");
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
  if (message.error) call.reject(new Error("CDP command failed")); else call.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("CDP timeout")); }, 10000);
    pending.set(id, { resolve, reject, timer }); socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", { expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}
async function until(fn) {
  const deadline = Date.now()+15000;
  while (Date.now()<deadline) { if (await fn()) return; await new Promise(resolve => setTimeout(resolve, 25)); }
  throw new Error("browser condition timed out");
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
    responses.length = 0;
    await command("Network.setExtraHTTPHeaders", {headers:{"X-Test-Policy":mode}}, page);
    const path = "/files/a%2fb?x=one%26two&x=three+four";
    const expected = application+path+(mode === "js" ? "#part%202" : "");
    const navigation = await command("Page.navigate", {url:expected}, page);
    assert(!navigation.errorText, "application navigation failed: "+navigation.errorText);
    if (mode !== "oauth") {
      await until(() => evaluate(page, () => !!document.querySelector('input[name="username"]')));
      const loginURL = await evaluate(page, () => location.href);
      assert.equal(new URL(loginURL).origin, portal);
      assert.equal(new URL(loginURL).searchParams.get("redirect_url"), expected);
      await evaluate(page, () => {
        document.querySelector('[name="username"]').value = "alice";
        document.querySelector('[name="realm"]').value = "local";
        document.querySelector('[name="username"]').form.requestSubmit();
      });
      await until(() => evaluate(page, () => !!document.querySelector('input[name="secret"][type="password"]')));
      await evaluate(page, password => {
        const secret = document.querySelector('input[name="secret"][type="password"]');
        secret.value = password; secret.form.requestSubmit();
      }, password);
    }
    await until(() => evaluate(page, expected => location.href === expected && document.readyState === "complete", expected));
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
