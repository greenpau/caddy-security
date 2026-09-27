// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Actual Caddy navigation and HTML forms through Chrome's verified TLS stack.
const assert = require("node:assert/strict");
const [endpoint, application, basePath, untrusted] = process.argv.slice(2);
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
 await new Promise((resolve,reject)=>{socket.addEventListener("open",resolve,{once:true});socket.addEventListener("error",reject,{once:true});});
 const {browserContextId}=await command("Target.createBrowserContext");
 const {targetId}=await command("Target.createTarget",{url:"about:blank",browserContextId});
 const {sessionId:page}=await command("Target.attachToTarget",{targetId,flatten:true});
 for(const method of ["Page.enable","Runtime.enable","Network.enable"]) await command(method,{},page);
 stage="TLS rejection";
 const rejected=await command("Page.navigate",{url:untrusted},page);
 assert.match(rejected.errorText||"",/ERR_CERT_/);
 stage="login";
 const path="/files/a%20b?x=one%26two&x=three+four";
 const nav=await command("Page.navigate",{url:application+path},page);
 assert(!nav.errorText,"navigation failed");
 await until(()=>evaluate(page,expected=>location.href===expected && document.readyState==="complete" && document.body.textContent.includes('"email"'),application+path));
 const identity=JSON.parse(await evaluate(page,()=>document.body.textContent));
 assert.equal(identity.uri,path);assert(identity.email);assert(identity.user);assert.match(identity.roles,/authp\/user/);
 const cookies=await command("Network.getCookies",{urls:[application]},page);
 assert.equal(cookies.cookies.length,1);const session=cookies.cookies[0];
 assert.equal(session.name,"AUTHZ_direct_SESSION");assert(session.secure && session.httpOnly);assert.equal(session.sameSite,"Lax");assert.equal(session.path,"/");
 assert.equal(await evaluate(page,()=>document.cookie),"");
 assert(!identity.cookies.includes("AUTHZ_direct_SESSION="));
 assert(responses.some(r=>r.url.includes(basePath+"/authorization-code-callback") && r.status===303));
 stage="logout";
 const status=await evaluate(page,async base=>(await fetch(base+"/logout",{method:"POST"})).status,basePath);
 assert.equal(status,204);
 assert.equal(await evaluate(page,async()=> (await fetch("/files",{method:"POST"})).status),401);
 const remaining=await command("Network.getCookies",{urls:[application]},page);assert.equal(remaining.cookies.length,0);
 await command("Target.disposeBrowserContext",{browserContextId});
 process.stdout.write("direct OAuth browser passed\n");
}
main().catch(error=>{process.stderr.write(stage+": "+error.message+"\n");process.exitCode=1;}).finally(()=>socket.close());
