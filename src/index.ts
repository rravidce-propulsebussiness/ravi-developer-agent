import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { DurableObject } from "cloudflare:workers";

type Env = {
  AUTH_SERVER_URL?: string;
  BROWSER?: Fetcher;
  BROWSER_SESSIONS: DurableObjectNamespace<TenantBrowserSession>;
};

export class TenantBrowserSession extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "PUT" && url.pathname === "/session") {
      const body = await request.json() as { sessionId?: string };
      if (!body.sessionId) return new Response("invalid_session", { status: 400 });
      await this.ctx.storage.put("sessionId", body.sessionId);
      return Response.json({ ok: true });
    }
    if (request.method === "GET" && url.pathname === "/session") {
      const sessionId = await this.ctx.storage.get<string>("sessionId");
      return sessionId ? Response.json({ sessionId }) : new Response("session_not_found", { status: 404 });
    }
    if (request.method === "DELETE" && url.pathname === "/session") {
      await this.ctx.storage.delete("sessionId");
      return Response.json({ ok: true });
    }
    return new Response("not_found", { status: 404 });
  }
}

type TenantContext = {
  tenantId: string;
  subject: string;
};

function result(data: unknown) {
  const text = JSON.stringify(data);
  return { structuredContent: data as Record<string, unknown>, content: [{ type: "text" as const, text }] };
}

function tenantFromRequest(request: Request): TenantContext | null {
  // Temporary boundary only. A dedicated identity provider will replace this
  // before provider credentials or user data are attached.
  const subject = request.headers.get("x-agent-subject");
  const tenantId = request.headers.get("x-agent-tenant");
  if (!subject || !tenantId) return null;
  if (!/^[a-zA-Z0-9:_-]{1,128}$/.test(subject) || !/^[a-zA-Z0-9_-]{1,64}$/.test(tenantId)) return null;
  return { subject, tenantId };
}

async function tenantSessionId(env: Env, tenant: TenantContext): Promise<string> {
  const id = env.BROWSER_SESSIONS.idFromName(tenant.tenantId);
  const response = await env.BROWSER_SESSIONS.get(id).fetch("https://browser-session/session");
  if (!response.ok) throw new Error("No active browser session for this tenant.");
  const body = await response.json() as { sessionId?: string };
  if (!body.sessionId) throw new Error("Tenant browser session is invalid.");
  return body.sessionId;
}

function createServer(tenant: TenantContext) {
  const server = new McpServer({ name: "ravi-developer-agent", version: "0.2.0" });

  server.registerTool(
    "agent_status",
    {
      title: "Agent Status",
      description: "Return Ravi Developer Agent service capabilities and tenant-safe status.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => result({
      ok: true,
      service: "Ravi Developer Agent",
      version: "0.2.0",
      transport: "MCP Streamable HTTP",
      tenant: tenant.tenantId,
      authentication: "boundary-enabled; identity-provider-pending",
      providers: [],
    }),
  );

  server.registerTool(
    "project_plan",
    {
      title: "Project Plan",
      description: "Create a safe execution plan for a cloud development task before provider actions are enabled.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        task: z.string().min(1).describe("Development task to plan"),
        repository: z.string().optional().describe("owner/repository when known"),
      },
    },
    async ({ task, repository }) => result({
      tenant: tenant.tenantId,
      task,
      repository: repository ?? null,
      execution: [
        "inspect project",
        "select provider/API tools",
        "request approval for sensitive writes",
        "apply changes",
        "deploy",
        "verify in isolated browser",
      ],
      status: "planning-only",
    }),
  );

  server.registerTool(
    "browser_capabilities",
    {
      title: "Browser Capabilities",
      description: "Describe the isolated cloud-browser capabilities available to this tenant. This tool does not navigate or modify websites.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => result({
      tenant: tenant.tenantId,
      provider: "Cloudflare Browser Run",
      capabilities: [
        "persistent browser sessions",
        "multiple tabs",
        "page navigation",
        "screenshots and snapshots",
        "DOM/accessibility inspection",
        "console and network inspection via CDP",
        "live view and human takeover",
      ],
      isolation: "per-tenant browser context/session required",
      navigationEnabled: false,
      reason: "Browser binding and approval-gated navigation tools are not deployed yet.",
    }),
  );

  server.registerTool(
    "browser_open",
    {
      title: "Open Website",
      description: "Open a public HTTP/HTTPS URL in the tenant cloud browser. Private/local network targets are rejected.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { url: z.string().url() },
    },
    async ({ url }) => {
      const target = new URL(url);
      if (!["http:", "https:"].includes(target.protocol)) throw new Error("Only HTTP/HTTPS URLs are allowed.");
      const host = target.hostname.toLowerCase();
      if (host === "localhost" || host === "::1" || host.endsWith(".local") || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host)) throw new Error("Private/local network targets are not allowed.");
      if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
      const response = await env.BROWSER.fetch("https://browser-rendering/snapshot", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: target.toString() }),
      });
      if (!response.ok) throw new Error(`Browser navigation failed (${response.status}).`);
      const body = await response.text();
      return result({ tenant: tenant.tenantId, url: target.toString(), snapshot: body.slice(0, 50000) });
    },
  );
  server.registerTool(
    "browser_session_start",
    {
      title: "Start Browser Session",
      description: "Start an isolated persistent cloud browser session and return its current targets for live browser viewing.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => {
      if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
      const response = await env.BROWSER.fetch("https://browser-rendering/devtools/browser?keep_alive=1200000&targets=true&liveViewUrlExpiresInMs=300000", { method: "POST" });
      if (!response.ok) throw new Error(`Browser session start failed (${response.status}).`);
      const session = await response.json() as { sessionId?: string; id?: string };
      const sessionId = session.sessionId ?? session.id;
      if (!sessionId) throw new Error("Browser provider did not return a session identifier.");
      const ownerId = env.BROWSER_SESSIONS.idFromName(tenant.tenantId);
      const owner = env.BROWSER_SESSIONS.get(ownerId);
      const stored = await owner.fetch("https://browser-session/session", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId }),
      });
      if (!stored.ok) throw new Error("Browser session ownership could not be stored.");
      return result({ tenant: tenant.tenantId, browserReady: true });
    },
  );
  server.registerTool("browser_tabs", {
    title: "List Browser Tabs",
    description: "List the current pages and live-view metadata in an existing tenant browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: {},
  }, async () => {
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const response = await env.BROWSER.fetch(`https://browser-rendering/devtools/browser/${encodeURIComponent(sessionId)}/json/list?liveViewUrlExpiresInMs=300000`);
    if (!response.ok) throw new Error(`Browser tab listing failed (${response.status}).`);
    return result({ tenant: tenant.tenantId, tabs: await response.json() });
  });
  server.registerTool("browser_tab_open", {
    title: "Open Browser Tab",
    description: "Open a public web URL in a new tab of an existing tenant browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { url: z.string().url() },
  }, async ({ url }) => {
    const target = new URL(url);
    if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("Unsupported URL scheme.");
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(sessionId) + "/json/new?url=" + encodeURIComponent(target.toString()) + "&liveViewUrlExpiresInMs=300000";
    const response = await env.BROWSER.fetch(endpoint, { method: "PUT" });
    if (!response.ok) throw new Error("Browser tab open failed.");
    return result({ tenant: tenant.tenantId, tab: await response.json() });
  });
  server.registerTool("browser_page_preview", {
    title: "Browser Page Preview",
    description: "Capture a PNG preview of a public web page for display in ChatGPT.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { url: z.string().url() },
  }, async ({ url }) => {
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const response = await env.BROWSER.fetch("https://browser-rendering/screenshot", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
    if (!response.ok) throw new Error("Browser preview failed.");
    const bytes = new Uint8Array(await response.arrayBuffer());
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return { content: [{ type: "image", data: btoa(binary), mimeType: "image/png" }] };
  });
  server.registerTool("browser_live_view", {
    title: "Browser Live View",
    description: "Create a short-lived read-only live view for an existing browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: {},
  }, async () => {
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(sessionId) + "/live_view";
    const response = await env.BROWSER.fetch(endpoint, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresInMs: 300000, mode: "tab", guardrails: { mode: "readonly" } }),
    });
    if (!response.ok) throw new Error("Live view creation failed.");
    return result({ tenant: tenant.tenantId, liveView: await response.json() });
  });
  return server;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/.well-known/oauth-protected-resource") {
      const resource = url.origin;
      const authorizationServer = env.AUTH_SERVER_URL;
      if (!authorizationServer) {
        return Response.json(
          { error: "oauth_not_configured" },
          { status: 503, headers: { "cache-control": "no-store" } },
        );
      }
      return Response.json({
        resource,
        authorization_servers: [authorizationServer],
        scopes_supported: ["agent:read", "agent:write"],
        resource_documentation: resource + "/",
      }, { headers: { "cache-control": "public, max-age=300" } });
    }

    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "ravi-developer-agent", version: "0.2.0" });
    }

    if (url.pathname === "/") {
      return Response.json({
        name: "Ravi Developer Agent",
        version: "0.2.0",
        mcp: "/mcp",
        health: "/health",
        authentication: "required for MCP",
      });
    }

    if (url.pathname === "/mcp") {
      const tenant = tenantFromRequest(request);
      if (!tenant) {
        return Response.json(
          { error: "unauthorized", message: "Authenticated tenant context is required." },
          {
            status: 401,
            headers: {
              "cache-control": "no-store",
              "WWW-Authenticate": 'Bearer resource_metadata="' + url.origin + '/.well-known/oauth-protected-resource", scope="agent:read"',
            },
          },
        );
      }
      const mcp = createMcpHandler(() => createServer(tenant), { route: "/mcp" });
      return mcp(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
