# OpenAI plugin review notes

These notes support the Ravi Developer Agent 1.0 submission. They contain no reviewer credentials or secrets.

## Production endpoints

- MCP: `https://ravi-developer-agent.rvrmvth.workers.dev/mcp`
- OAuth issuer: `https://ravi-developer-agent-auth.rvrmvth.workers.dev`
- Website: `https://ravi-developer-agent.rvrmvth.workers.dev`
- Privacy: `https://ravi-developer-agent.rvrmvth.workers.dev/privacy`
- Terms: `https://ravi-developer-agent.rvrmvth.workers.dev/terms`
- Support: `https://ravi-developer-agent.rvrmvth.workers.dev/support`

## UI frame-domain explanation

The browser UI embeds only `https://live.browser.run`. This is Cloudflare Browser Run's short-lived Live View surface for the tenant-owned cloud-browser session. It is essential to the developer-testing workflow because it lets the user observe the remote browser inside ChatGPT. Live View URLs are short-lived, tenant-scoped, and passed in MCP UI metadata rather than normal model-visible structured content. Read-only Live View is the default; credential collection through plugin tools/browser automation is not supported.

## Review package checks

- Exactly five positive MCP review cases and three negative cases are declared in `plugin/plugin.json`.
- The plugin uses one universal production MCP URL.
- Public legal/support URLs are hosted on the MCP origin.
- OAuth protected-resource and authorization-server discovery are hosted on production HTTPS endpoints.
- Browser security regression tests are part of `npm run verify`.
- Cloudflare Workers Builds runs `npm run verify` before deployment.

## Portal-only items still required

The submission portal must still supply the generated domain-verification challenge, verified publisher identity, reviewer demo credentials, annotation justifications, and a reviewer-accessible demo recording URL. Cloudflare and Supabase OAuth clients must be configured before review cases that exercise those providers can pass.

## Tool annotation justifications

| Tool | readOnlyHint | openWorldHint | destructiveHint | Justification |
|---|---:|---:|---:|---|
| `audit_recent` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `agent_status` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `agent_profile` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `delete_my_data` | false | true | true | Changes state or initiates an action, so it is not read-only. Interacts with an external provider, Browser Run service, or external website. Permanently removes Ravi Developer Agent tenant data and revokes its grants after explicit confirmation. |
| `project_plan` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `github_connection_status` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `github_list_repositories` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `github_get_file` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `github_create_branch` | false | false | false | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `github_put_file` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. Can overwrite repository file content on the selected branch. |
| `github_create_pull_request` | false | false | false | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_connection_status` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_connect` | false | true | false | Creates OAuth state and starts a provider authorization flow. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_list_accounts` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_list_workers` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_list_worker_secrets` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_delete_worker_secret` | false | true | true | Changes state or initiates an action, so it is not read-only. Interacts with an external provider, Browser Run service, or external website. Deletes a named Worker secret after explicit confirmation. |
| `cloudflare_trigger_build` | false | false | false | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_list_builds` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `cloudflare_get_build` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `supabase_connection_status` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `supabase_connect` | false | true | false | Creates OAuth state and starts a provider authorization flow. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `supabase_list_projects` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `supabase_get_project` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `supabase_schema_inspect` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `supabase_apply_migration` | false | true | true | Changes state or initiates an action, so it is not read-only. Interacts with an external provider, Browser Run service, or external website. Can change database schema/data through a confirmed migration. |
| `supabase_list_migrations` | true | true | false | Reads or reports data/state only; it does not change external resources. Interacts with an external provider, Browser Run service, or external website. Does not delete or irreversibly destroy provider resources. |
| `provider_disconnect` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. Can delete, overwrite, migrate, close, or otherwise make a consequential change. |
| `browser_capabilities` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_open` | true | false | false | Creates a browser tab and performs network navigation. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_session_start` | true | false | false | Creates a persistent Browser Run session. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_tabs` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_tab_open` | true | false | false | Creates a browser tab and performs network navigation. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_tab_activate` | false | false | false | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_tab_close` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. The interaction can close browser state or trigger consequential page actions, so it is treated conservatively as destructive. |
| `browser_session_close` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. The interaction can close browser state or trigger consequential page actions, so it is treated conservatively as destructive. |
| `browser_screenshot` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_page_text` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_click` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. The interaction can close browser state or trigger consequential page actions, so it is treated conservatively as destructive. |
| `browser_type` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. The interaction can close browser state or trigger consequential page actions, so it is treated conservatively as destructive. |
| `browser_select` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. The interaction can close browser state or trigger consequential page actions, so it is treated conservatively as destructive. |
| `browser_press` | false | false | true | Changes state or initiates an action, so it is not read-only. Uses only Ravi Developer Agent tenant-local metadata/state. The interaction can close browser state or trigger consequential page actions, so it is treated conservatively as destructive. |
| `browser_wait` | true | false | false | Reads or reports data/state only; it does not change external resources. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
| `browser_live_view` | true | false | false | Creates a short-lived Live View resource. Uses only Ravi Developer Agent tenant-local metadata/state. Does not delete or irreversibly destroy provider resources. |
