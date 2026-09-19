// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the real Caddy TLS listener.
const assert = require("node:assert/strict");
const [endpoint, origin, mount, refreshCookie, accessCookie, scenario, untrustedOrigin, wrongHostnameOrigin] = process.argv.slice(2);
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === "Page.frameNavigated") {
    const url = message.params.frame.url;
    if (/[?&#](access_token|refresh_token|id_token)=|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(url)) {
      process.stderr.write("credential appeared in navigation URL\n"); process.exit(1);
    }
  }
  if (!message.id) return;
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id);
  clearTimeout(request.timer);
  if (message.error) request.reject(new Error("browser protocol command failed"));
  else request.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("browser command timed out")); }, 25000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true
  }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed: " + (result.exceptionDetails.exception?.description || "unknown exception"));
  return result.result.value;
}
async function waitFor(fn) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await fn()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("browser condition timed out");
}
async function page(contextId) {
  const target = await command("Target.createTarget", { url: "about:blank", browserContextId: contextId });
  const { sessionId } = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  await command("Page.enable", {}, sessionId);
  await command("Runtime.enable", {}, sessionId);
  return sessionId;
}
async function navigate(page, path, sessionClient = false) {
  const result = await command("Page.navigate", { url: origin + path }, page);
  if (result.errorText) throw new Error("portal navigation failed");
  await waitFor(() => evaluate(page, (url) => location.href === url && document.readyState === "complete", origin + path));
  if (sessionClient) await waitFor(() => evaluate(page, () => !!window.AuthCrunchSession));
}

const storageKey = "authcrunch-session:" + mount;
async function login(page, realm = "employees", accessOnly = false) {
  return evaluate(page, async ({ realm, password, mount, accessOnly }) => {
    const send = async (body) => {
      const response = await fetch(mount + "/login", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error("fixture login rejected: " + response.status);
      return response.json();
    };
    const request = { username: "alice", realm };
    const challenge = await send(request);
    if (challenge.next_challenge !== "password") throw new Error("real password checkpoint missing");
    const result = await send({ ...request, sandbox_id: challenge.sandbox_id, sandbox_secret: challenge.sandbox_secret, challenge_kind: "password", challenge_response: password });
    if (!result.authenticated || result.refresh_token) throw new Error("invalid browser completion");
    if (!accessOnly && (!result.session_id || result.access_token)) throw new Error("browser login exposed credentials");
    if (accessOnly && result.session_id) throw new Error("unselected realm received refresh authority");
    return { sid: result.session_id, expires: result.access_expires_at };
  }, { realm, password, mount, accessOnly });
}
async function control(page, operation) {
  return evaluate(page, async ({ operation, mount }) => {
    const response = await fetch(mount + "/_test/" + operation, { method: operation === "status" ? "GET" : "POST", cache: "no-store" });
    return operation === "status" ? response.json() : response.ok;
  }, {operation, mount});
}
const state = (page) => evaluate(page, (key) => JSON.parse(localStorage.getItem(key)), storageKey);
const refresh = (page, force = false) => evaluate(page, async (force) => {
  try { const result = await AuthCrunchSession.refresh(force); return { ok: true, session: result.session_id }; }
  catch (_) { return { ok: false }; }
}, force);
const logout = (page) => evaluate(page, async () => (await AuthCrunchSession.logout()).logged_out);
const snapshot = (page) => control(page, "status");
const cookieJar = async (context) => (await command("Storage.getCookies", {browserContextId: context})).cookies;
async function assertPrivacy(page, context) {
  const cookies = await cookieJar(context);
  const secrets = cookies.filter(c => c.name === refreshCookie || c.name === accessCookie).map(c => c.value).filter(Boolean);
  const values = await evaluate(page, () => ({ storage: Object.entries(localStorage), url: location.href, visible: document.cookie }));
  const text = JSON.stringify(values);
  assert(!secrets.some(value => text.includes(value)), "credentials escaped HttpOnly cookies");
  for (const [key, raw] of values.storage) {
    if (!key.startsWith("authcrunch-session:")) continue;
    const record = JSON.parse(raw);
    assert(Object.keys(record).every(key => ["session_id", "access_expires_at", "session_expires_at", "pending", "blocked"].includes(key)), "storage contains non-metadata state");
  }
}
async function seedLegacyCookie(context) {
  await command("Storage.setCookies", {browserContextId: context, cookies: [{name:refreshCookie, value:"legacy-fixture", url:origin, path:mount+"/api/refresh_token", secure:true,httpOnly:true,sameSite:"Lax"}]});
}
async function assertDeleted(context, all = true) {
  const cookies = await cookieJar(context);
  assert(!cookies.some(c => c.name === refreshCookie && (all || c.path === mount+"/api/refresh_token")), "refresh cookie path not cleared");
}
async function metadataReady(page, sid) {
  await waitFor(async () => (await state(page))?.session_id === sid);
}
async function queuedSessionOperation(page) {
  // Observe the actual Web Lock queue before releasing the server fault. Merely
  // issuing two CDP commands does not prove that their operations overlapped.
  await waitFor(() => evaluate(page, async key => {
    const locks = await navigator.locks.query();
    return locks.held.some(lock => lock.name === key) && locks.pending.some(lock => lock.name === key);
  }, storageKey));
}
async function coordinatedRefresh(first, second) {
  // Finish both bootstraps so the queued lock below belongs to the exchange.
  assert.equal((await refresh(first)).ok, true);
  assert.equal((await refresh(second)).ok, true);
  const before = await snapshot(first);
  // Simulate an expired metadata deadline, under the same real Web Lock. The
  // separate continuation scenario waits for actual server-side JWT expiry.
  await evaluate(first, async (key) => navigator.locks.request(key, () => {
    const s=JSON.parse(localStorage.getItem(key));s.access_expires_at=0;localStorage.setItem(key,JSON.stringify(s));
  }), storageKey);
  await control(first, "hold");
  const one = refresh(first);
  await waitFor(async () => (await snapshot(second)).held);
  assert.equal(await evaluate(first, () => {
    const one=AuthCrunchSession.refresh();
    return one===AuthCrunchSession.refresh();
  }),true,"same-page calls did not share their in-flight promise");
  const two = refresh(second);
  await queuedSessionOperation(second);
  assert.equal((await snapshot(second)).requests,before.requests+1,"waiting tab sent a competing rotation");
  await control(second, "release_rotation");
  const [a,b]=await Promise.all([one,two]);
  assert(a.ok && b.ok && a.session===b.session, "tabs did not share a successful rotation");
  const after=await snapshot(first);
  assert.equal(after.rotations-before.rotations,1,"concurrent tabs repeated rotation");
  assert.equal(after.requests-before.requests,1,"concurrent tabs sent another rotation");
  assert.equal(after.max_active,1,"refresh operations overlapped");
}
async function continuation(context) {
  const first=await page(context), second=await page(context);
  await navigate(first,mount+"/login?fresh=1");
  const session=await login(first);
  // No coordinator is loaded while the real signed access token expires.
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,session.expires*1000-Date.now()+1100)));
  const before=await snapshot(first);
  await navigate(first,mount+"/portal");
  await waitFor(()=>evaluate(first,()=>document.querySelector('script[data-session]')!==null));
  await metadataReady(first,session.sid);
  const after=await snapshot(first);
  assert(after.lookups>before.lookups && after.rotations>before.rotations,"expired access did not use lookup and continuation");
  await assertPrivacy(first,context);
  await navigate(second,mount+"/login?fresh=1");
  assert.equal(await evaluate(second,()=>!!document.querySelector('script[data-action="continue"]')),false,"fresh=1 renewed instead of showing login");
  assert.equal(await logout(first),true);
  for (const trusted of [true,false]) {
    stage=trusted?"trusted continuation return":"untrusted continuation return";
    await navigate(first,mount+"/login?fresh=1");
    const session=await login(first);
    // Confirm the new signed identity while it is fresh before later expiry.
    // An old blocked marker cannot be cleared using an expired new access token.
    await navigate(first,mount+"/portal",true);
    await metadataReady(first,session.sid);
    await navigate(first,mount+"/login?fresh=1");
    await new Promise(resolve=>setTimeout(resolve,Math.max(0,session.expires*1000-Date.now()+1100)));
    const target=trusted?origin+mount+"/_test/signed-out":"https://foreign.example/";
    await command("Page.navigate",{url:origin+mount+"/login?redirect_url="+encodeURIComponent(target)},first);
    const expected=trusted?target:origin+mount+"/portal";
    await waitFor(()=>evaluate(first,url=>location.href===url && document.readyState==="complete",expected));
    await navigate(first,mount+"/portal",true);
    await assertPrivacy(first,context);
    assert.equal(await logout(first),true);
  }
  stage="logout after actual access expiry";
  await navigate(first,mount+"/login?fresh=1");
  const final=await login(first);
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,final.expires*1000-Date.now()+1100)));
  await navigate(first,mount+"/logout",true);
  assert.equal(await logout(first),true);
  await assertDeleted(context);
}
async function unsupported(context, kind) {
  const tab=await page(context);
  await navigate(tab,mount+"/login?fresh=1");
  await login(tab);
  // Enter the real continuation UI without access credentials. Actual expiry
  // is tested separately; removing this cookie isolates unavailable primitives.
  const access=(await cookieJar(context)).filter(c=>c.name===accessCookie);
  for (const cookie of access) {
    await command("Storage.setCookies",{browserContextId:context,cookies:[{name:accessCookie,value:"",url:origin,path:cookie.path,expires:1,secure:true,httpOnly:true}]});
  }
  assert(!(await cookieJar(context)).some(c=>c.name===accessCookie));
  const source=kind==="locks"
    ? 'Object.defineProperty(navigator,"locks",{value:undefined,configurable:true});'
    : 'Object.defineProperty(window,"localStorage",{get(){throw new Error("storage unavailable")},configurable:true});';
  await command("Page.addScriptToEvaluateOnNewDocument",{source:source+'window.__loginRequired=[];window.addEventListener("authcrunch:reauthenticate",e=>window.__loginRequired.push(e.detail.login));'},tab);
  const before=await snapshot(tab);
  await navigate(tab,mount+"/portal",true);
  assert.deepEqual(await refresh(tab,true),{ok:false});
  await waitFor(()=>evaluate(tab,()=>window.__loginRequired.length>0));
  assert.equal(await evaluate(tab,()=>window.__loginRequired[0]),mount+"/login?fresh=1");
  const after=await snapshot(tab);
  assert.equal(after.requests,before.requests,"unsupported browser rotated");
  assert.equal(after.lookups,before.lookups,"unsupported browser looked up refresh session");
  assert.equal(await evaluate(tab,()=>document.querySelector('script[data-action]').dataset.action),"continue");
  await evaluate(tab,()=>document.querySelector('a[href$="/login?fresh=1"]').click());
  await waitFor(()=>evaluate(tab,url=>location.href===url && document.readyState==="complete",origin+mount+"/login?fresh=1"));
  assert.equal(await evaluate(tab,()=>!!window.AuthCrunchSession),false,"fresh-login fallback looped through renewal");
}
async function coordination(context) {
  const first=await page(context),second=await page(context);
  stage="password login and cookie paths";
  await navigate(first,mount+"/login?fresh=1");
  await seedLegacyCookie(context);
  const original=(await login(first)).sid;
  await assertDeleted(context,false);
  await navigate(first,mount+"/portal",true);
  await navigate(second,mount+"/portal",true);
  await metadataReady(first,original);
  await assertPrivacy(first,context);
  stage="two-tab rotation";
  await coordinatedRefresh(first,second);
  stage="deferred old HTML";
  const delayed=command("Page.navigate",{url:origin+mount+"/portal?deferred=1"},second);
  await waitFor(async()=> (await snapshot(first)).stale_rendered);
  stage="account replacement at capacity";
  const replacement=(await login(first,"contractors")).sid;
  assert.notEqual(replacement,original);
  await navigate(first,mount+"/portal",true);
  assert.deepEqual(await refresh(first),{ok:true,session:replacement});
  stage="old SID cannot consume new family cookie";
  const beforeWrong=await snapshot(first);
  const denied=await evaluate(first,async({mount,sid})=>{
    const response=await fetch(mount+"/api/refresh_token",{method:"POST",headers:{"Content-Type":"application/json","X-Authcrunch-Refresh":"1","X-Authcrunch-Refresh-Session":sid},body:"{}"});return response.status;
  },{mount,sid:original});
  assert.equal(denied,401);
  assert.equal((await snapshot(first)).rotations,beforeWrong.rotations);
  stage="lost committed response";
  const beforeLoss=(await cookieJar(context)).find(c=>c.name===refreshCookie && c.path===(mount||"/"));
  await control(first,"cut");
  const before=await snapshot(first);
  assert.deepEqual(await refresh(first,true),{ok:false});
  const uncertain=await state(first);
  assert.equal(uncertain.session_id,replacement);assert.equal(uncertain.pending,true);
  const committed=await snapshot(first);
  assert.equal(committed.rotations,before.rotations+1,"lost response did not commit");
  const afterLoss=(await cookieJar(context)).find(c=>c.name===refreshCookie && c.path===(mount||"/"));
  assert(beforeLoss && afterLoss && beforeLoss.value!==afterLoss.value,"Chrome did not apply the committed cookie before response loss");
  stage="stale HTML cannot reset pending state";
  await control(first,"release");await delayed;
  await waitFor(()=>evaluate(second,url=>location.href===url && document.readyState==="complete" && !!window.AuthCrunchSession,origin+mount+"/portal?deferred=1"));
  assert.equal(await evaluate(second,()=>document.querySelector('script[data-session]').dataset.session),original);
  assert.deepEqual(await refresh(second,true),{ok:false});
  assert.deepEqual(await state(second),uncertain);
  stage="stored pending state survives navigation";
  await navigate(first,mount+"/portal",true);
  assert.deepEqual(await refresh(first,true),{ok:false});
  await evaluate(second,()=>window.dispatchEvent(new Event("focus")));
  assert.deepEqual(await refresh(second,true),{ok:false});
  assert.equal((await snapshot(first)).requests,committed.requests,"uncertain rotation retried");
  assert.equal((await snapshot(first)).lookups,committed.lookups,"lookup recovered uncertainty");
  await assertPrivacy(first,context);
  stage="fresh login recovers both tabs";
  await navigate(first,mount+"/login?fresh=1");
  const fresh=(await login(first)).sid;assert.notEqual(fresh,replacement);
  await navigate(first,mount+"/portal",true);
  assert.deepEqual(await refresh(first),{ok:true,session:fresh});
  await metadataReady(second,fresh);
  assert.deepEqual(await refresh(second,true),{ok:true,session:fresh});
  assert.equal((await state(first)).pending,undefined);
  stage="rotation and logout share a lock";
  const beforeSignout=await snapshot(first);
  await control(first,"hold");
  const pending=refresh(first,true);
  await waitFor(async()=> (await snapshot(second)).held);
  const signout=logout(second);
  await queuedSessionOperation(second);
  assert.equal((await snapshot(second)).logouts,beforeSignout.logouts,"logout reached the server before rotation completed");
  await control(second,"release_rotation");
  assert.equal((await pending).ok,true);assert.equal(await signout,true);
  assert.deepEqual(await refresh(first,true),{ok:false});
  await assertDeleted(context);
  assert.equal((await snapshot(first)).max_active,1);
  stage="max sessions one logout and relogin";
  const next=(await login(first)).sid;assert.notEqual(next,fresh);
  await navigate(first,mount+"/portal",true);
  stage="GET logout confirms without revocation";
  const beforeLogout=await snapshot(first);
  await navigate(second,mount+"/logout?redirect_uri="+encodeURIComponent("https://foreign.example/"),true);
  assert.equal(await evaluate(second,()=>document.querySelector('script[data-action]').dataset.next),mount+"/login");
  assert.equal((await snapshot(first)).logouts,beforeLogout.logouts);
  assert.deepEqual(await refresh(first,true),{ok:true,session:next});
  await seedLegacyCookie(context);
  const destination=origin+mount+"/_test/signed-out";
  await navigate(second,mount+"/logout?redirect_uri="+encodeURIComponent(destination),true);
  assert.equal(await evaluate(second,()=>document.querySelector('script[data-action]').dataset.next),destination);
  await evaluate(second,()=>document.querySelector("#session-logout").click());
  await waitFor(()=>evaluate(second,url=>location.href===url,destination));
  await assertDeleted(context);
  stage="browser replacement into access-only realm";
  await login(first);
  await navigate(first,mount+"/portal",true);
  const previous=(await cookieJar(context)).find(c=>c.name===refreshCookie && c.path===(mount||"/"));
  assert(previous,"active refresh cookie missing");
  await seedLegacyCookie(context);
  await login(first,"guests",true);
  await assertDeleted(context);
  const identity=await evaluate(first,async(mount)=>{
    const r=await fetch(mount+"/whoami?probe=true",{headers:{Accept:"application/json"}});const u=await r.json();return {authenticated:u.authenticated,origin:u.origin,sid:u.sid};
  },mount);
  assert.deepEqual(identity,{authenticated:true,origin:"guests"});
  await navigate(first,mount+"/portal");
  assert.equal(await evaluate(first,()=>!!document.querySelector('script[src$="/assets/js/refresh.js"]')),false,"access-only portal loaded the refresh coordinator");
  // Replay the previous credential in an isolated real cookie jar, never JS
  // storage or a URL, to prove account replacement retired its authority.
  const other=(await command("Target.createBrowserContext")).browserContextId;
  await command("Storage.setCookies",{browserContextId:other,cookies:[{name:refreshCookie,value:previous.value,url:origin,path:mount||"/",secure:true,httpOnly:true,sameSite:"Lax"}]});
  const retired=await page(other);await navigate(retired,mount+"/_test/signed-out");
  const status=await evaluate(retired,async mount=>(await fetch(mount+"/api/refresh_token",{method:"POST",headers:{"Content-Type":"application/json","X-Authcrunch-Refresh":"1"},body:"{}"})).status,mount);
  assert.equal(status,401,"access-only replacement retained old family authority");
  await command("Target.disposeBrowserContext",{browserContextId:other});
  await assertPrivacy(first,context);
}

async function composition(context) {
  const first=await page(context),second=await page(context);
  stage="composed browser login and OP cookie isolation";
  await navigate(first,mount+"/login?fresh=1");
  await seedLegacyCookie(context);
  const original=(await login(first)).sid;
  await assertDeleted(context,false);
  const opName="COMPOSED_OIDC_SESSION_ID";
  const originalOP=(await cookieJar(context)).find(c=>c.name===opName);
  assert(originalOP && originalOP.secure && originalOP.httpOnly && originalOP.path===mount);
  await navigate(first,mount+"/portal",true);
  await navigate(second,mount+"/portal",true);
  await assertPrivacy(first,context);
  assert.equal(await evaluate(first,secret=>document.cookie.includes(secret),originalOP.value),false);
  assert.equal(await evaluate(first,async mount=>{
    const r=await fetch(mount+"/resource");
    return r.status===204 && r.headers.get("X-Protected-Upstream")==="reached";
  },mount),true,"real browser cookie did not authorize protected upstream");
  stage="composed two-tab rotation";
  await coordinatedRefresh(first,second);
  stage="composed realm replacement at capacity";
  const replacement=(await login(first,"contractors")).sid;
  assert.notEqual(replacement,original);
  const replacementOP=(await cookieJar(context)).find(c=>c.name===opName);
  assert(replacementOP && replacementOP.value!==originalOP.value,"realm switch retained OP session");
  await navigate(first,mount+"/portal",true);
  await navigate(second,mount+"/portal",true);
  assert.deepEqual(await refresh(first),{ok:true,session:replacement});
  stage="composed committed-response loss";
  await control(first,"cut");
  assert.deepEqual(await refresh(first,true),{ok:false});
  const uncertain=await state(first);
  assert.equal(uncertain.pending,true);
  const committed=await snapshot(first);
  await navigate(second,mount+"/portal",true);
  assert.deepEqual(await refresh(second,true),{ok:false});
  assert.equal((await snapshot(first)).requests,committed.requests,"uncertain composition retried rotation");
  assert.equal((await snapshot(first)).lookups,committed.lookups,"uncertain composition used session lookup");
  stage="composed recovery and coordinated logout";
  const recovered=(await login(first)).sid;
  assert.notEqual(recovered,replacement);
  await navigate(first,mount+"/portal",true);
  await navigate(second,mount+"/portal",true);
  await coordinatedRefresh(first,second);
  await seedLegacyCookie(context);
  assert.equal(await logout(first),true);
  await assertDeleted(context);
  assert(!(await cookieJar(context)).some(c=>c.name===opName),"browser logout retained OP evidence");
  await assertPrivacy(first,context);
}

(async()=>{
 await new Promise((resolve,reject)=>{socket.addEventListener("open",resolve,{once:true});socket.addEventListener("error",()=>reject(new Error("browser socket failed")),{once:true})});
 try{
  stage="browser TLS negative controls";
  const tlsContext=(await command("Target.createBrowserContext")).browserContextId;
  try {
   const probe=await page(tlsContext);
   const untrusted=await command("Page.navigate",{url:untrustedOrigin},probe);
   assert.equal(untrusted.errorText,"net::ERR_CERT_AUTHORITY_INVALID","untrusted certificate control did not reach trust validation");
   const mismatch=await command("Page.navigate",{url:wrongHostnameOrigin},probe);
   assert.equal(mismatch.errorText,"net::ERR_CERT_COMMON_NAME_INVALID","wrong-host control did not reach hostname validation");
  } finally {
   await command("Target.disposeBrowserContext",{browserContextId:tlsContext});
  }
  const context=(await command("Target.createBrowserContext")).browserContextId;
  if(scenario==="continuation") await continuation(context);
  else if(scenario==="composition") await composition(context);
  else {
   await coordination(context);
   // Close active tabs before checking unsupported environments; each login
   // replaces the same single-capacity portal's previous family.
   await command("Target.disposeBrowserContext",{browserContextId:context});
   for(const kind of ["locks","storage"]){
    stage="missing "+kind;
    const context=(await command("Target.createBrowserContext")).browserContextId;
    await unsupported(context,kind);
    // Explicit logout is still a protected server operation when the UI cannot
    // run. Use this fixture cleanup only to free the single family slot.
    const tab=await page(context);await navigate(tab,mount+"/_test/signed-out");
    assert.equal(await evaluate(tab,async mount=>(await fetch(mount+"/api/logout",{method:"POST",headers:{"Content-Type":"application/json","X-Authcrunch-Refresh":"1"},body:"{}"})).status,mount),200);
    await command("Target.disposeBrowserContext",{browserContextId:context});
   }
  }
  process.stdout.write(JSON.stringify({passed:true,scenario})+"\n");
 }finally{
  await command("Browser.close").catch(()=>{});socket.close();for(const r of pending.values())clearTimeout(r.timer);
 }
})().catch(error=>{process.stderr.write(stage+": "+error.message+"\n");process.exitCode=1;socket.close()});
