// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require("node:assert/strict");
const { runInNewContext } = require("node:vm");
// The Go harness parses the HTML and supplies its single inline program.
const { script, fragment } = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
assert.equal(typeof script, "string", "expected a redirect program");
const window = { location: { hash: fragment } };
runInNewContext(script, { window }, { timeout: 1000 });
assert.equal(typeof window.location, "string", "script did not navigate");
process.stdout.write(window.location);
