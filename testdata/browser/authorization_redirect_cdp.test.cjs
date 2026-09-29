// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require("node:assert/strict");
const test = require("node:test");
const { BrowserProtocolError, waitForRead } = require("./authorization_redirect_cdp.cjs");

function clock() {
  let elapsed = 0;
  return { timeout: 75, interval: 25, now: () => elapsed,
    sleep: async ms => { elapsed += ms; } };
}

for (const message of ["Execution context was destroyed.",
  "Cannot find default execution context", "Cannot find context with specified id",
  "Inspected target navigated or closed"]) {
  test(`read observation survives navigation: ${message}`, async () => {
    let calls = 0;
    await waitForRead(async () => {
      calls++;
      if (calls === 1) throw new BrowserProtocolError("Runtime.evaluate", { code: -32000, message });
      return calls === 3;
    }, clock());
    assert.equal(calls, 3);
  });
}

test("persistent context loss is bounded by the original deadline", async () => {
  let calls = 0;
  await assert.rejects(waitForRead(async () => {
    calls++;
    throw new BrowserProtocolError("Runtime.evaluate", { code: -32000, message: "Execution context was destroyed." });
  }, clock()), /browser condition timed out/);
  assert.equal(calls, 3);
});

test("a false predicate does not satisfy readiness", async () => {
  let calls = 0;
  await assert.rejects(waitForRead(async () => { calls++; return false; }, clock()), /browser condition timed out/);
  assert.equal(calls, 3);
});

for (const [name, failure] of [
  ["DOM assertion", new Error("browser evaluation failed")],
  ["unclassified error", new Error("Execution context was destroyed.")],
  ["timeout", new Error("Runtime.evaluate timed out")],
  ["closed target", new BrowserProtocolError("Runtime.evaluate", { code: -32000, message: "Target closed" })],
  ["detached session", new BrowserProtocolError("Runtime.evaluate", { code: -32001, message: "Session with given id not found" })],
  ["other protocol failure", new BrowserProtocolError("Runtime.evaluate", { code: -32602, message: "Execution context was destroyed." })],
  ["navigation command", new BrowserProtocolError("Page.navigate", { code: -32000, message: "Execution context was destroyed." })],
]) {
  test(`${name} fails without retry`, async () => {
    let calls = 0;
    await assert.rejects(waitForRead(async () => { calls++; throw failure; }, clock()), error => error === failure);
    assert.equal(calls, 1);
  });
}

test("a closed target cannot pass as a recovered navigation", async () => {
  let calls = 0;
  const closed = new BrowserProtocolError("Runtime.evaluate", { code: -32001, message: "Session with given id not found" });
  await assert.rejects(waitForRead(async () => {
    if (++calls === 1) throw new BrowserProtocolError("Runtime.evaluate", { code: -32000, message: "Inspected target navigated or closed" });
    throw closed;
  }, clock()), error => error === closed);
  assert.equal(calls, 2);
});

test("unknown protocol diagnostics do not disclose arguments or raw error data", () => {
  const error = new BrowserProtocolError("Runtime.evaluate", {
    code: -32000, message: "synthetic-secret-value", data: "synthetic-secret-value",
  });
  assert.equal(error.message, "Runtime.evaluate failed (-32000): command rejected");
  assert(!JSON.stringify(error).includes("synthetic-secret-value"));
  assert(!error.stack.includes("synthetic-secret-value"));
});
