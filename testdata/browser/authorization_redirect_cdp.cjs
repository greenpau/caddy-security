// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.

const contextErrors = new Set([
  "Execution context was destroyed.",
  "Cannot find default execution context",
  "Cannot find context with specified id",
  "Inspected target navigated or closed",
]);
const diagnosticErrors = new Set([...contextErrors,
  "Promise was collected", "Target closed",
]);

class BrowserProtocolError extends Error {
  constructor(method, error) {
    const contextUnavailable = method === "Runtime.evaluate" &&
      error.code === -32000 && contextErrors.has(error.message);
    // Unknown protocol messages may echo evaluated arguments. Keep credentials,
    // expressions and raw protocol data out of test output.
    super(`${method} failed (${error.code}): ${diagnosticErrors.has(error.message) ? error.message : "command rejected"}`);
    this.contextUnavailable = contextUnavailable;
  }
}

async function waitForRead(read, { timeout = 15000, interval = 25,
  now = () => performance.now(),
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
} = {}) {
  const deadline = now() + timeout;
  while (now() < deadline) {
    try {
      if (await read()) return;
    } catch (error) {
      // A navigation can remove the old page while its DOM is being read.
      // Only repeat observations, never the action that initiated navigation.
      // If the target closed, subsequent reads fail or reach the deadline;
      // a transient error alone can never establish readiness.
      if (!(error instanceof BrowserProtocolError) || !error.contextUnavailable) throw error;
    }
    await sleep(interval);
  }
  throw new Error("browser condition timed out");
}

module.exports = { BrowserProtocolError, waitForRead };
