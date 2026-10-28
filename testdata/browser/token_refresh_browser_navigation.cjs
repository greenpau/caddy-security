// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.

function createNavigation({command, evaluate, waitFor, origin}) {
  return async function navigate(page, path, sessionClient = false, expectedPath = path) {
    const previous = (await command("Page.getFrameTree", {}, page)).frameTree.frame.loaderId;
    const result = await command("Page.navigate", {url: origin + path}, page);
    if (result.errorText) throw new Error("portal navigation failed");
    await waitFor(async () => {
      // A same-URL reload can leave the old complete document visible while
      // navigation commits. Follow-up continuation redirects may commit yet
      // another loader, so require replacement rather than one exact loader.
      if (result.loaderId) {
        const current = (await command("Page.getFrameTree", {}, page)).frameTree.frame.loaderId;
        if (current === previous) return false;
      }
      return evaluate(page, (url) => location.href === url && document.readyState === "complete", origin + expectedPath);
    });
    if (sessionClient) await waitFor(() => evaluate(page, () => !!window.AuthCrunchSession));
  };
}

module.exports = {createNavigation};
