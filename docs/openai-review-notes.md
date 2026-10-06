# OpenAI Directory review notes

Ravi Developer Agent 1.0 uses a single production remote MCP endpoint:

- MCP: `https://ravi-developer-agent.rvrmvth.workers.dev/mcp`
- OAuth issuer: `https://ravi-developer-agent-auth.rvrmvth.workers.dev`
- Website: `https://ravi-developer-agent.rvrmvth.workers.dev`
- Privacy: `https://ravi-developer-agent.rvrmvth.workers.dev/privacy`
- Terms: `https://ravi-developer-agent.rvrmvth.workers.dev/terms`
- Support: `https://ravi-developer-agent.rvrmvth.workers.dev/support`

## Frame-domain justification

The browser MCP App embeds only `https://live.browser.run`, Cloudflare Browser Run's short-lived Live View surface. This is essential to the developer-testing workflow because it lets the user observe the tenant-owned remote browser inside ChatGPT. Live View URLs are short-lived and tenant-scoped. The public plugin does not collect passwords, API keys, OTP/MFA codes, payment-card data, Worker secret values, or other authentication secrets through tool inputs or automated browser typing.

## Package/review checks

- `plugin/plugin.json` has exactly five positive and three negative review cases.
- `plugin/mcp.json` points to the universal production MCP URL.
- Public legal/support pages are served on the production origin.
- OAuth protected-resource and authorization-server discovery are public HTTPS endpoints.
- `npm run verify` runs TypeScript validation plus security regression tests before deployment.
- State-changing provider/repository/database tools use write authorization and confirmation where applicable.
- Self-service data deletion removes Ravi Developer Agent tenant data without deleting external provider resources.

## Portal-only completion items

The OpenAI submission portal still requires publisher identity verification, the generated domain-verification challenge, reviewer demo credentials/sample data, annotation justifications, the frame-domain explanation, and a reviewer-accessible demo video. Cloudflare and Supabase provider OAuth clients must be configured before reviewer cases for those providers can succeed.

## Tool annotation matrix

| Tool | readOnlyHint | openWorldHint | destructiveHint | Review justification |
|---|---:|---:|---:|---|
| `audit_recent` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `agent_status` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `agent_profile` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `delete_my_data` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `project_plan` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `github_connection_status` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `github_list_repositories` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `github_get_file` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `github_create_branch` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `github_put_file` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `github_create_pull_request` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_connection_status` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `cloudflare_connect` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_list_accounts` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_list_workers` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_list_worker_secrets` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_delete_worker_secret` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `cloudflare_trigger_build` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_list_builds` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `cloudflare_get_build` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `supabase_connection_status` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `supabase_connect` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `supabase_list_projects` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `supabase_get_project` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `supabase_schema_inspect` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `supabase_apply_migration` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `supabase_list_migrations` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `provider_disconnect` | false | false | true | May create or change state. Uses only tenant-local/service metadata. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_capabilities` | true | false | false | Does not change external state. Uses only tenant-local/service metadata. Is not inherently destructive. |
| `browser_session_start` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_tabs` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_tab_open` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_tab_activate` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_tab_close` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_session_close` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_screenshot` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_page_text` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_click` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_type` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_select` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_press` | false | true | true | May create or change state. Contacts an external provider, browser service, or website. Can delete, overwrite, close, migrate, or trigger consequential state. |
| `browser_wait` | true | true | false | Does not change external state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
| `browser_live_view` | false | true | false | May create or change state. Contacts an external provider, browser service, or website. Is not inherently destructive. |
