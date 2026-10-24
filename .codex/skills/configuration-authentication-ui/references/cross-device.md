# Cross-device presentation through Caddy

AuthCrunch owns the embedded `cross_device` template, CSS and client. Caddy
serves the selected module's assets beneath the complete portal mount. Use the
existing `ui { template cross_device <path> }` override for a custom page;
there is no separate cross-device theme directive. Protocol admission,
browser binding and explicit consent belong to the
[cross-device owner](../../configuration-authentication-cross-device/SKILL.md).

## Presentation contract

Keep the current step in both the visible heading and document title. Show the
same prominent matching code on the requesting, activation and confirmation
pages. Confirmation must also identify the account. Continue starts fresh login;
Approve and Deny remain separate explicit decisions, in that DOM/tab order.
Unavailable polling is a generic terminal state and does not disclose whether
denial, expiry, revocation or a network failure caused it.

The QR must fit and remain centered with its white border visible. Preserve
equal decision controls, a visible gap and intentional wrapping on small screens.
Keep the activation URL hidden until manual copying is needed. Never put the
requester secret in that URL or browser storage.

Clipboard feedback belongs in the initially empty `cross-device-copy-status`
live region, separate from waiting/terminal status. Keep that region exposed to
accessibility APIs before the first message, without an empty layout row.
Clipboard denial reveals the labeled readonly, wrapping link textarea. Select
and focus it only if focus has not moved since copying began. A delayed denial
must preserve the user's new focus and must not claim that text was selected.

Explicit cancellation hides the old details/controls, focuses the updated
heading, and offers Start again. That link creates a new request and code.
Background terminal updates preserve focus on surviving navigation; they move
focus only when the active control disappears. Late clipboard/network completion
must not replace a terminal state. Keep normal focus outlines and touch targets.

## Filesystem template boundaries

For the complete presentation, retain the focusable `cross-device-title`,
`cross-device-controls`, `cross-device-copy-status`, `cross-device-link-fallback`
and `cross-device-recovery` hooks, along with the details/status/QR/code/link/
copy/cancel IDs and the selected embedded script's base/return metadata.
Preserve explicit POST forms and hidden CSRF inputs on activation and decisions.

The runtime treats the newer presentation wrappers as optional for older
templates: original polling, copy/select, cancellation and approved navigation
remain supported, using existing status/navigation where needed. Updating a
filesystem copy acquires the full layout and recovery action. This compatibility
contract comes from the selected runtime; Caddy's embedded-template browser
suite does not qualify an arbitrary filesystem override. Exercise a custom
template through its actual Caddy declaration before claiming compatibility.

## Caddy acceptance

`TestCaddyCrossDeviceBrowserE2E` serves production assets through verified Caddy
TLS and actual Chrome. Its full journey checks request/activation/confirmation
layout at 320, 390, 639, 640, 768 and 1280 pixels, keyboard traversal/activation,
visible focus, the polite atomic clipboard status node, real clipboard success
and permission denial, explicit approval/denial, cancellation and fresh recovery.
A smaller nested-mount journey checks asset/link bases without repeating the
complete protocol matrix. Retain independent contexts, real login, code/account
checks, credential/resource outcomes, asynchronous exception checks and awaited
browser cleanup. The existing stale-form and abort regressions remain required.

Accessibility-tree assertions establish Chrome semantics, not screen-reader
speech or physical TV/VR behavior. Optional screenshots support visual review;
geometry alone cannot establish readable spacing. The test runs without them.
Keep any captured synthetic accounts/codes private and outside tracked assets.
Set `CADDY_SECURITY_CROSS_DEVICE_SCREENSHOT_DIR` to a fresh directory beneath
the repository's `tmp/` to opt in. The harness creates private full/smoke
subdirectories, rejects symlink paths and writes captures exclusively. Use a
new sink for another run to preserve earlier evidence.

```sh
make test TEST='^(TestCaddyCrossDeviceBrowserE2E|TestBrowserContextCleanup|TestCrossDeviceScreenshotDirectory)$' TEST_DIR=.
```

Language selection and translated/RTL presentation retain the UI owner's
separate localization contract; this English interaction suite is not a
multilingual qualification.
