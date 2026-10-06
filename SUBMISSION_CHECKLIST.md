# Ravi Developer Agent — Public Plugin Submission Checklist

This checklist is for the production plugin at:

- MCP: `https://ravi-developer-agent.rvrmvth.workers.dev/mcp`
- OAuth issuer: `https://ravi-developer-agent-auth.rvrmvth.workers.dev`
- Product page: `https://ravi-developer-agent.rvrmvth.workers.dev/`
- Privacy: `https://ravi-developer-agent.rvrmvth.workers.dev/privacy`
- Terms: `https://ravi-developer-agent.rvrmvth.workers.dev/terms`
- Support: `https://ravi-developer-agent.rvrmvth.workers.dev/support`

## Automated preflight

Before every production deploy:

```bash
npm run verify
```

This runs strict TypeScript checking plus the regression suite. The package regression suite checks:

- plugin/package version alignment,
- the production Streamable HTTP MCP URL,
- exactly five positive and three negative initial MCP review cases,
- HTTPS website/privacy/terms/support URLs,
- absence of packaged reviewer credentials and authentication secrets,
- browser hostname/wildcard guardrail behavior.

Cloudflare Workers Builds is configured to run `npm run verify` before both Worker deploy commands.

## Production checks before submission

- [ ] Main Worker health returns `ok: true` and version `1.0.0`.
- [ ] Authorization Worker health returns `oauth: "enabled"` and `upstreamLogin: "github-app"`.
- [ ] Protected-resource discovery works at `/.well-known/oauth-protected-resource/mcp`.
- [ ] Authorization-server discovery works at `/.well-known/oauth-authorization-server`.
- [ ] An unauthenticated request to `/mcp` fails closed with an OAuth challenge.
- [ ] GitHub App sign-in works with the dedicated review account.
- [ ] Cloudflare provider OAuth is configured and a review account can connect.
- [ ] Supabase provider OAuth is configured and a review account can connect.
- [ ] Browser Live View loads with its declared CSP and does not expose its bearer-like URL in model-visible results.
- [ ] The five positive and three negative review prompts have been run against production.

Do **not** submit while `/health` reports `cloudflareConfigured: false` or `supabaseConfigured: false` if the directory listing continues to advertise those provider capabilities.

## OpenAI submission prerequisites

- [ ] Complete individual or business identity verification for the publishing name in the OpenAI Platform Dashboard.
- [ ] Use a project/organization eligible for MCP plugin submission and with global data residency.
- [ ] Confirm the submitting account has `api.apps.write` (and `api.apps.read` to inspect drafts/status).
- [ ] Prepare the plugin ZIP with `plugin.json`, `mcp.json`, `skills/`, and `assets/` at the ZIP root.
- [ ] Upload the ZIP in the plugin submission portal.
- [ ] Enter the production MCP URL and select **Scan Tools**.
- [ ] Inspect every scanned tool title, description, schema, security scheme, annotation, UI resource and CSP value.
- [ ] Add the domain-verification token from the portal to the main Worker as `OPENAI_APPS_CHALLENGE`, then verify `/.well-known/openai-apps-challenge`.
- [ ] Provide reviewer-ready credentials through the secure review form, never inside the plugin ZIP or repository.
- [ ] Reviewer credentials must work without MFA, SMS, email verification, VPN, or internal-network access.
- [ ] Provide the required reviewer-accessible demo/walkthrough recording URL.
- [ ] Complete localization/country availability and required confirmations.
- [ ] Submit for review.
- [ ] After approval, publish from the submission portal.

## Provider-publisher setup still required before review

### Cloudflare

Create a production OAuth client for Ravi Developer Agent using the callback:

`https://ravi-developer-agent.rvrmvth.workers.dev/oauth/cloudflare/callback`

Use only the current Developer Platform scopes required by the shipped tools. Save the client credentials through the publisher-only provider setup flow; never commit them.

### Supabase

Create a Supabase OAuth App using the callback:

`https://ravi-developer-agent.rvrmvth.workers.dev/oauth/supabase/callback`

Grant only the Management API permissions required by the shipped read/status and confirmed migration tools. Save the client credentials through the publisher-only provider setup flow; never commit them.

Publisher setup entry:

`https://ravi-developer-agent-auth.rvrmvth.workers.dev/setup/providers`

## Review-account preparation

Use a dedicated sample-data account for review, not a real production user. It should have:

- the Ravi Developer Agent GitHub App installed on a harmless test repository,
- a minimal Cloudflare account/project suitable for list/build-status tests,
- a minimal Supabase project suitable for metadata/schema/migration tests,
- no sensitive production data,
- no MFA or secondary verification that would block the OpenAI review team.

## Release rule

Do not claim the plugin is publicly available until the OpenAI submission is approved and the publisher explicitly selects **Publish**. A successful Cloudflare deployment means the MCP service is production-ready; it does not by itself mean the plugin is listed in the public directory.
