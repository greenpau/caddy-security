// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require('node:assert/strict');
const test = require('node:test');
const { disposeBrowserContexts } = require('./browser_contexts.cjs');

test('scenario cleanup waits for disposal and does not close a context twice', async () => {
  const contexts = new Set(['requester', 'approver']);
  const calls = [];
  let release;
  const disposed = new Promise(resolve => { release = resolve; });
  const command = async (method, params) => {
    assert.equal(method, 'Target.disposeBrowserContext');
    calls.push(params.browserContextId);
    if (params.browserContextId === 'requester') await disposed;
  };
  const cleanup = disposeBrowserContexts(command, contexts);
  assert.deepEqual(calls, ['requester']);
  assert.equal(contexts.size, 2, 'in-flight disposal lost ownership');
  release();
  await cleanup;
  assert.equal(contexts.size, 0);
  assert.deepEqual(calls, ['requester', 'approver']);
  await disposeBrowserContexts(command, contexts);
  assert.deepEqual(calls, ['requester', 'approver']);

  contexts.add('next scenario');
  await disposeBrowserContexts(command, contexts);
  assert.deepEqual(calls, ['requester', 'approver', 'next scenario']);
});

test('cleanup attempts every context and retains failures for final cleanup', async () => {
  const contexts = new Set(['failed first', 'released', 'failed last']);
  const failures = [new Error('first failure'), new Error('last failure')];
  const calls = [];
  await assert.rejects(disposeBrowserContexts(async (_, { browserContextId }) => {
    calls.push(browserContextId);
    if (browserContextId === 'failed first') throw failures[0];
    if (browserContextId === 'failed last') throw failures[1];
  }, contexts), error => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, failures);
    return true;
  });
  assert.deepEqual(calls, ['failed first', 'released', 'failed last']);
  assert.deepEqual([...contexts], ['failed first', 'failed last']);
  await disposeBrowserContexts(async (_, { browserContextId }) => {
    calls.push(browserContextId);
  }, contexts);
  assert.equal(contexts.size, 0);
  assert.deepEqual(calls.slice(3), ['failed first', 'failed last']);
});
