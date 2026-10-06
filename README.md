# Ravi Developer Agent

Cloud-first, multi-user developer agent intended for ChatGPT and other MCP clients.

## Foundation

- Cloudflare Workers
- MCP Streamable HTTP at `/mcp`
- Stateless `createMcpHandler` architecture
- No committed provider credentials
- Provider adapters planned for GitHub, Supabase, Cloudflare and an isolated cloud browser

## Local development

```bash
npm install
npm run typecheck
npm run dev
```

Health: `GET /health`

MCP: `POST /mcp`

## Security direction

Public distribution requires per-user authentication, provider OAuth, encrypted credential/session storage, tenant isolation, approval gates for sensitive writes, and audit logs. These are deliberately separate from the initial transport scaffold.


## Deployment

Production is built from `main` by the dedicated Cloudflare Worker `ravi-developer-agent`. No other project resources are used.
