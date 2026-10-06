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
- Trigger an existing Workers Build after confirmation.
- List recent builds and inspect build outcome/status.

### Supabase

- Per-user Management API OAuth connection with PKCE.
- List projects and inspect project lifecycle status.
- Execute Management API SQL in read-only mode.
- Apply a named migration only after explicit confirmation.
- List applied migrations.

### Cloud browser

- Tenant-isolated persistent Browser Run sessions.
- Session-level hostname allowlists enforced by Cloudflare.
- Multiple tabs, activation, closure, page text and screenshots.
- Approval-gated click/type/select/key interactions.
- Password, OTP, token/secret and payment-card fields are blocked from agent typing.
- Short-lived read-only Live View and interactive human takeover in the MCP Apps UI.

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
- Business OS / Propulse infrastructure is not used by Ravi Developer Agent.

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
