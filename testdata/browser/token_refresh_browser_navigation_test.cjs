// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.

const assert = require("node:assert/strict");
const {test} = require("node:test");
const vm = require("node:vm");
const {createNavigation} = require("./token_refresh_browser_navigation.cjs");

const origin = "https://portal.example.test";
function fixture(navigation, plans) {
  let document = {loader: "old", url: origin + "/auth/portal", ready: "complete", client: true};
  const navigate = createNavigation({
    origin,
    command: async (method, params, page) => {
      assert.equal(page, "tab");
      if (method === "Page.getFrameTree") return {frameTree: {frame: {loaderId: document.loader}}};
      assert.equal(method, "Page.navigate");
      assert.equal(typeof params.url, "string");
      return navigation;
    },
    evaluate: async (page, fn, args) => {
      assert.equal(page, "tab");
      return vm.runInNewContext(`(${fn.toString()})(${JSON.stringify(args)})`, {
        location: {href: document.url}, document: {readyState: document.ready},
        window: {AuthCrunchSession: document.client ? {} : undefined}
      });
    },
    waitFor: async condition => {
      const phases = plans.shift();
      assert(phases, "unexpected readiness wait");
      for (const phase of phases) {
        document = {...document, ...phase};
        const ready = await condition();
        assert.equal(ready, phase.expected, phase.message || "unexpected navigation readiness");
        if (ready) return;
      }
      assert.fail("readiness never completed");
    }
  });
  return {navigate, finished: () => assert.equal(plans.length, 0)};
}

test("same URL reload waits for a new document and its coordinator", async () => {
  const f = fixture({loaderId: "new"}, [
    [
      {expected: false, message: "the old complete document must not satisfy a reload"},
      {loader: "new", ready: "loading", client: false, expected: false},
      {ready: "complete", expected: true}
    ],
    [
      {client: false, expected: false},
      {client: true, expected: true}
    ]
  ]);
  await f.navigate("tab", "/auth/portal", true);
  f.finished();
});

test("continuation accepts a later redirected document at the expected URL", async () => {
  const f = fixture({loaderId: "continuation"}, [[
    {loader: "continuation", expected: false},
    {loader: "redirected", url: origin + "/auth/portal?redirect_url=", expected: true}
  ]]);
  await f.navigate("tab", "/auth/portal", false, "/auth/portal?redirect_url=");
  f.finished();
});

test("same document navigation can retain its loader", async () => {
  const f = fixture({}, [[{url: origin + "/auth/portal#details", expected: true}]]);
  await f.navigate("tab", "/auth/portal#details");
  f.finished();
});

test("failed navigation retains a safe error", async () => {
  const f = fixture({errorText: "synthetic-navigation-secret"}, []);
  await assert.rejects(f.navigate("tab", "/auth/portal"), {message: "portal navigation failed"});
  f.finished();
});
