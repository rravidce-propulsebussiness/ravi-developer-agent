# Ravi Developer Agent publication checklist

The production MCP endpoint is:

`https://ravi-developer-agent.rvrmvth.workers.dev/mcp`

The separate authorization server is:

`https://ravi-developer-agent-auth.rvrmvth.workers.dev`

## Publisher setup

1. Create the public GitHub App at:
   `https://ravi-developer-agent-auth.rvrmvth.workers.dev/setup/github-app`
2. Install/authorize that GitHub App for the repositories used by the developer agent.
3. Create the Cloudflare and Supabase OAuth applications with the callback URLs shown by:
   `https://ravi-developer-agent-auth.rvrmvth.workers.dev/setup/providers`
4. Enter the resulting provider client credentials only through that publisher setup page. Do not paste secrets into ChatGPT.

## ChatGPT testing

Use ChatGPT Plugins -> Add custom MCP server and connect the production `/mcp` URL with OAuth. Test in Work mode with a fresh chat after tool or UI metadata changes.

## Public review

Before submitting:

- Complete OpenAI developer/business identity verification.
- Upload the portable plugin ZIP.
- Connect and scan the production MCP server.
- Set the portal-provided domain verification value as `OPENAI_APPS_CHALLENGE`, then verify the domain.
- Provide a dedicated reviewer account with sample repositories/projects and no MFA, magic-link, SMS, email-code, or private-network dependency.
- Run all five positive and three negative cases from `plugin.json`.
- Record a reviewer-accessible walkthrough showing the real test cases.
- Enter reviewer credentials only in the secure dashboard review form.

### Browser iframe justification

The browser UI embeds `https://live.browser.run` only for Cloudflare Browser Run's short-lived Live View. The iframe is essential because it displays the live state of the tenant-isolated cloud browser inside ChatGPT and enables explicit human takeover for authentication fields that the model is prohibited from receiving or typing. The embedded origin is controlled by Cloudflare, expires after a short period, and is narrowly allowlisted in the MCP App resource CSP. No unrelated third-party frame origins are allowed.

## Security expectations

- Never expose OAuth access/refresh tokens, API keys, passwords, database passwords, one-time codes, or Worker secret values in MCP tool output.
- Use least-privilege provider authorization and tenant-scoped storage.
- Read-only tools should remain side-effect free.
- Write/destructive actions must keep their OAuth scope and confirmation gates.
- Browser navigation must remain restricted by the session's explicit allowed-domain policy.
- Re-run the production MCP tool scan after any tool name, schema, description, annotation, security scheme, or UI metadata change.
