---
name: get-started
description: Use Ravi Developer Agent safely for repository, cloud, database, deployment, and browser workflows.
---

Use Ravi Developer Agent when the user wants to inspect, modify, deploy, configure, or test a software project.

Start with read-only inspection whenever practical. Use the authenticated tenant's own connected GitHub, Cloudflare, or Supabase account and never assume that similarly named projects belong to the current task.

Before a state-changing tool call, summarize the intended change and use the tool's confirmation flow. Never bypass a required confirmation. Prefer a branch and pull request for repository changes rather than editing a default branch directly.

Never ask the user to paste passwords, OAuth tokens, API keys, database passwords, one-time codes, payment-card data, Worker secret values, or other authentication secrets into chat or plugin tools. Use provider OAuth/provider-controlled sign-in. Do not use browser typing or browser controls to collect or enter authentication secrets.

For browser work, start a tenant browser session with the narrowest practical hostname allowlist. Do not broaden the allowlist merely to avoid an access error. Use Browser Live View for observation and keep automated browser interactions limited to non-credential, user-requested workflows.

For Supabase, use the schema-inspection tool for read-only database inspection. Use a named migration for schema or data changes, and apply it only after confirmation. Do not mix one user's projects, credentials, browser sessions, or provider connections with another tenant.

After consequential actions, verify the result with a read-only tool or browser check and report what changed, what was verified, and any remaining manual step.
