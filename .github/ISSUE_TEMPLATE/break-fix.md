---
name: Things are not working!
about: Troubleshoot a caddy-security configuration, deployment, or runtime issue.
title: 'breakfix: CHANGE_ME'
labels: ['need triage', 'breakfix']
assignees: 'greenpau'

---

**Before opening a break-fix issue**

Documentation for this project has moved from `https://docs.authcrunch.com` to
skill-based documentation in this repository. For configuration generation,
migration, and troubleshooting, please use an AI coding agent such as Codex,
GitHub Copilot, or Claude Code together with the repository skills:

https://github.com/greenpau/caddy-security/tree/main/.codex/skills

Useful prompts:

* "Analyze the following Caddyfile using the `caddy-security` skills and explain why authentication is failing."
* "Troubleshoot the following `caddy-security` logs using the repository skills and identify the root cause."
* "Review my `caddy-security` configuration using the repository skills and recommend improvements following current best practices."

If the issue remains, please include the agent prompt, findings, and any skill
guidance that was incorrect, incomplete, or missing. Real-world reports help
make the skills more accurate for both humans and AI agents.

**Describe the issue**

A clear and concise description of what is not working.

**Skill-guided troubleshooting**

AI coding agent used, if any:

```
Codex / GitHub Copilot / Claude Code / other / none
```

Prompt used:

```
Paste prompt here ...
```

Agent findings or remaining questions:

```
Paste findings here ...
```

**Configuration**

Paste the full `Caddyfile` below. Redact secrets, but keep directive structure,
identity provider names, routes, and policy names intact.

```
Paste configuration here ...
```

**Logs and errors**

Paste relevant Caddy logs, browser errors, redirect URLs, HTTP status codes, or
other error output below. Redact tokens, passwords, cookies, and private keys.

```
Paste logs here ...
```

**Version information**

Provide output of `caddy list-modules --versions | grep -E "(auth|security)"` below:

```
Paste output here ...
```

Also include the Caddy version and operating environment:

```
caddy version
OS/container/platform:
```

**Expected behavior**

Describe expected behavior.

```
TODO
```

**Actual behavior**

Describe what happens instead.

```
TODO
```

**Skills or documentation gap**

If the repository skills could be improved based on this issue, describe the
missing use case, incorrect recommendation, or edge case below.

```
TODO
```

**Additional context**

Add any other context about the problem here.

```
TODO
```
