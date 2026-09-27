// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require("node:assert/strict");
const { runInNewContext } = require("node:vm");
const { body, fragment } = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const scripts = [...body.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1, "expected one redirect program");
const window = { location: { hash: fragment } };
runInNewContext(scripts[0][1], { window }, { timeout: 1000 });
assert.equal(typeof window.location, "string", "script did not navigate");
process.stdout.write(window.location);
