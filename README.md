# Ravi Developer Agent

Cloud-first, multi-user developer agent for ChatGPT and other MCP clients.

## Production endpoints

- MCP resource server: `https://ravi-developer-agent.rvrmvth.workers.dev/mcp`
- Resource health: `https://ravi-developer-agent.rvrmvth.workers.dev/health`
- OAuth authorization server: `https://ravi-developer-agent-auth.rvrmvth.workers.dev`
- Authorization health: `https://ravi-developer-agent-auth.rvrmvth.workers.dev/health`

The resource and authorization servers are separate Cloudflare Workers. The MCP Worker validates tokens through a private Service Binding.

## Implemented capabilities

### GitHub

- Sign in through the Ravi Developer Agent GitHub App.
- List repositories.
- Read UTF-8 repository files.
- Create branches after confirmation.
- Create/update files after confirmation.
- Open pull requests after confirmation.

GitHub provider tokens are kept inside OAuth token properties and are not emitted in MCP results.

### Cloudflare

- Per-user OAuth connection with PKCE.
- List accounts and Worker scripts.
- List Worker secret **names** without revealing values.
- Delete a named Worker secret after confirmation.
- Secret values must be created or rotated directly in Cloudflare; this public plugin never asks users to provide secret values.
- Trigger an existing Workers Build after confirmation.
- List recent builds and inspect build outcome/status.

### Supabase

- Per-user Management API OAuth connection with PKCE.
- List projects and inspect project lifecycle status.
- Inspect database schema metadata without returning application table rows.
- Apply a named migration only after explicit confirmation.
- List applied migrations.

### Cloud browser

- Tenant-isolated persistent Browser Run sessions.
- Session-level hostname allowlists enforced by Cloudflare.
- Multiple tabs, activation, closure, page text and screenshots.
- Approval-gated click/type/select/key interactions.
- Normal browser typing still blocks password, API-key, MFA/OTP, token/secret and payment-card fields.
- Optional self-hosted persistent browser profiles can retain provider login cookies/site storage across sessions.
- Optional runner-side secret aliases can fill approved password or environment-secret fields without sending the secret value to ChatGPT.
- Guarded file uploads are supported on the self-hosted runner.
- Short-lived read-only Live View is available inline in ChatGPT.

## Security model

- OAuth 2.1-style resource protection with PKCE/S256.
- Tenant identity comes from validated OAuth token properties, not caller-supplied tenant headers.
- Dedicated Durable Objects isolate browser sessions and provider connections by tenant.
- Provider OAuth tokens are stored only in the tenant-specific Durable Object. Cloudflare Durable Object storage is encrypted at rest.
- State-changing tools require `agent:write` where applicable and explicit confirmation.
- Successful state-changing tools are written to a per-tenant audit log without tool payloads or secrets.
- Audit retention is 30 days.
- MCP requests are rate limited per tenant.
- Browser Live View URLs are returned only in MCP UI metadata, not model-visible structured content.
- Browser sessions use explicit domain guardrails.
- The public plugin does not collect passwords, API keys, MFA/OTP codes, payment-card data, or other authentication secrets.
- Business OS / Propulse infrastructure is not used by Ravi Developer Agent.

### Self-service deletion

Authenticated users can call `delete_my_data`. It requires explicit destructive confirmation and deletes Ravi Developer Agent's tenant-scoped provider connections, browser-session state, audit/rate records, stored GitHub user-token state, and Ravi Developer Agent OAuth grants. It does **not** delete GitHub repositories, Cloudflare resources, Supabase projects/databases, or data held independently by visited websites.

## One-time publisher bootstrap

### 1. Create the GitHub App

Open:

`https://ravi-developer-agent-auth.rvrmvth.workers.dev/setup/github-app`

GitHub shows the requested permissions before creation. The manifest flow creates a public GitHub App owned by the publisher account and stores its generated client ID/secret in the authorization Worker's dedicated KV namespace.

Install the GitHub App on repositories that Ravi Developer Agent should be able to manage.

### 2. Configure provider OAuth clients

After the GitHub App is configured, open:

`https://ravi-developer-agent-auth.rvrmvth.workers.dev/setup/providers`

The setup page authenticates the publisher with GitHub before showing the credential form. Provider client credentials are submitted directly to the authorization Worker and are never returned to ChatGPT.

Cloudflare callback:

`https://ravi-developer-agent.rvrmvth.workers.dev/oauth/cloudflare/callback`

Supabase callback:

`https://ravi-developer-agent.rvrmvth.workers.dev/oauth/supabase/callback`

For Cloudflare, register an authorization-code + refresh-token OAuth client and grant only the Developer Platform scopes needed by the tools in this repository. For Supabase, create an OAuth App from the publisher organization and grant only the Management API permissions required by the intended workflows.

### 3. Connect the MCP app in ChatGPT

Use the production MCP endpoint:

`https://ravi-developer-agent.rvrmvth.workers.dev/mcp`

ChatGPT should discover the protected-resource metadata, redirect through the authorization Worker, request the configured `agent:read` / `agent:write` scopes, and return with a tenant-bound access token.

Connecting/installing the app and authorizing external provider accounts always requires the user's explicit action.

## Local development

```bash
npm install
npm run typecheck
npm run dev
```

Authorization Worker:

```bash
npm run dev:auth
```

## Deployment

The repository uses two isolated Cloudflare Workers:

- `ravi-developer-agent`
- `ravi-developer-agent-auth`

Both build from `main` using dedicated Workers Builds configuration. No Business OS or Propulse Worker, KV, D1, R2, token, database, or browser session is reused.


## Self-hosted browser backend

The feature branch `feature/self-hosted-browser-runner` adds an optional Playwright/Chromium runner under `runner/`. When configured, Ravi Developer Agent uses your own PC or VPS as the primary browser backend and keeps Cloudflare Browser Run as a fallback.

This avoids Cloudflare Free-plan browser-minute limits. The practical limit becomes the CPU, RAM, bandwidth, and uptime of the machine running Chromium.

### Windows PC

```powershell
cd runner
.\setup-windows.ps1 -PublicBaseUrl "https://browser.example.com"
.\start-windows.ps1
```

The setup script creates a local `.env` with a cryptographically random runner token and installs Playwright Chromium. Keep that token private.

### VPS / Docker

```bash
cd runner
cp .env.example .env
# Edit RUNNER_TOKEN and PUBLIC_BASE_URL.
docker compose up -d --build
```

Expose the runner through an HTTPS reverse proxy or secure tunnel. The runner itself should not be published as an unauthenticated raw port.

### Connect the Worker

Set these on the `ravi-developer-agent` Worker:

```text
SELF_HOSTED_BROWSER_URL=https://browser.example.com
SELF_HOSTED_BROWSER_TOKEN=<same token from runner/.env>
```

After redeploying, `browser_session_start` prefers the self-hosted runner. If it is unavailable and Cloudflare Browser Run is bound, the tool falls back automatically.

The public browser tool names do not change, so existing ChatGPT workflows continue to use `browser_session_start`, `browser_tab_open`, `browser_screenshot`, `browser_page_text`, `browser_click`, `browser_type`, and `browser_live_view`.

## Persistent authenticated browser profiles

On the self-hosted runner, start a browser session with a `profileName` such as `hostinger`. The runner can load and save cookies/local storage in `BROWSER_PROFILE_DIR` so a provider-controlled sign-in can survive browser restarts without sending the password to ChatGPT.

For Hostinger, a typical allowed-domain policy can include `hostinger.com` and `*.hostinger.com`. Complete the first sign-in in the visible local Chromium window, then call `browser_profile_save`. Future sessions using the same profile name can reuse the authenticated state while it remains valid.

Profile files contain authenticated browser state. They are ignored by Git and should be protected like a normal browser profile.

## Runner-side secret aliases

For a field that must receive a password or another secret, keep the value only on the self-hosted runner. On Windows:

```powershell
cd runner
.\set-browser-secret-windows.ps1 -Name HOSTINGER_PASSWORD
.\start-windows.ps1
```

The helper stores the local key as `BROWSER_SECRET_HOSTINGER_PASSWORD` inside the ignored `runner/.env` file and never prints the entered value. ChatGPT can list only alias names with `browser_vault_names` and can inject an alias into an approved field with `browser_fill_secret`; the secret value is never returned by the runner or included in audit payloads.

This same pattern can be used for provider environment-secret values. Non-secret environment values can continue to use ordinary browser typing. OTP/MFA values are intentionally not stored in the runner vault.

## Browser file uploads

`browser_upload_files` can attach up to eight files (maximum 5 MB each) to a browser file input on the self-hosted runner after confirmation. This is useful for authorized test flows and provider dashboards that require a file upload.
