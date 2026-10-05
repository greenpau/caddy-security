// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.

// Release completed scenarios before opening more isolated devices. Continue
// after a failed disposal so one broken context cannot strand all the others.
async function disposeBrowserContexts(command, contexts) {
  const errors = [];
  for (const browserContextId of contexts) {
    try {
      await command('Target.disposeBrowserContext', { browserContextId });
      contexts.delete(browserContextId);
    } catch (error) {
      errors.push(error);
    }
  }
  if (errors.length) throw new AggregateError(errors, 'browser context cleanup failed');
}

module.exports = { disposeBrowserContexts };
