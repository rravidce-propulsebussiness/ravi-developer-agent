import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { DurableObject } from "cloudflare:workers";
import { registerAppResource, registerAppTool, RESOURCE_MIME_TYPE } from "@modelcontextprotocol/ext-apps/server";

type Env = {
  AUTH_SERVER_URL?: string;
  BROWSER?: Fetcher;
  BROWSER_SESSIONS: DurableObjectNamespace<TenantBrowserSession>;
};

export class TenantBrowserSession extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "PUT" && url.pathname === "/session") {
      const body = await request.json() as { sessionId?: string; allowedDomains?: string[] };
      if (!body.sessionId || !body.allowedDomains?.length) return new Response("invalid_session", { status: 400 });
      await this.ctx.storage.put("sessionId", body.sessionId);
      await this.ctx.storage.put("allowedDomains", body.allowedDomains);
      return Response.json({ ok: true });
    }
    if (request.method === "GET" && url.pathname === "/session") {
      const sessionId = await this.ctx.storage.get<string>("sessionId");
      const allowedDomains = await this.ctx.storage.get<string[]>("allowedDomains");
      return sessionId ? Response.json({ sessionId, allowedDomains: allowedDomains ?? [] }) : new Response("session_not_found", { status: 404 });
    }
    if (request.method === "DELETE" && url.pathname === "/session") {
      await this.ctx.storage.delete(["sessionId", "allowedDomains"]);
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

type TenantBrowserPolicy = { sessionId: string; allowedDomains: string[] };

async function tenantBrowserPolicy(env: Env, tenant: TenantContext): Promise<TenantBrowserPolicy> {
  const id = env.BROWSER_SESSIONS.idFromName(tenant.tenantId);
  const response = await env.BROWSER_SESSIONS.get(id).fetch("https://browser-session/session");
  if (!response.ok) throw new Error("No active browser session for this tenant.");
  const body = await response.json() as { sessionId?: string; allowedDomains?: string[] };
  if (!body.sessionId || !body.allowedDomains?.length) throw new Error("Tenant browser session is invalid.");
  return { sessionId: body.sessionId, allowedDomains: body.allowedDomains };
}

async function tenantSessionId(env: Env, tenant: TenantContext): Promise<string> {
  return (await tenantBrowserPolicy(env, tenant)).sessionId;
}

function validDomainPattern(value: string): boolean {
  if (value !== value.toLowerCase() || value.includes("://") || /[/?#:@\\]/.test(value)) return false;
  if (value === "localhost" || value.endsWith(".localhost")) return false;
  if ((value.match(/\*/g) ?? []).length > 1) return false;
  return /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
}

function hostnameAllowed(hostname: string, patterns: string[]): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return patterns.some((pattern) => pattern.startsWith("*.") ? host.endsWith(pattern.slice(1)) && host !== pattern.slice(2) : host === pattern);
}

function createServer(tenant: TenantContext, env: Env) {
  const server = new McpServer({ name: "ravi-developer-agent", version: "0.2.0" });
  // OpenAI/MCP Apps supports securitySchemes on tool descriptors, but the
  // ext-apps 2.0.3 TypeScript surface has not caught up with that field yet.
  // Keep runtime metadata standards-compliant while containing the cast here.
  const registerTool = (name: string, config: unknown, handler: unknown) =>
    (registerAppTool as any)(server, name, config, handler);

  registerTool(
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

  registerTool(
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
    async ({ task, repository }: { task: string; repository?: string }) => result({
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

  registerTool(
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

  registerTool(
    "browser_open",
    {
      title: "Open Website",
      description: "Open a public HTTP/HTTPS URL in the tenant cloud browser. Private/local network targets are rejected.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { url: z.string().url() },
    },
    async ({ url }: { url: string }) => {
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
  registerTool(
    "browser_session_start",
    {
      title: "Start Browser Session",
      description: "Start an isolated persistent cloud browser session restricted to approved hostnames.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        allowedDomains: z.array(z.string().min(1).refine(validDomainPattern, "Use a lowercase public hostname or *.subdomain pattern")).min(1).max(50).describe("Approved public hostname patterns for this browser session"),
      },
    },
    async ({ allowedDomains }: { allowedDomains: string[] }) => {
      if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
      const response = await env.BROWSER.fetch("https://browser-rendering/devtools/browser?keep_alive=1200000&targets=true&liveViewUrlExpiresInMs=300000", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ guardrails: { allowedDomains } }),
      });
      if (!response.ok) throw new Error(`Browser session start failed (${response.status}).`);
      const session = await response.json() as { sessionId?: string; id?: string };
      const sessionId = session.sessionId ?? session.id;
      if (!sessionId) throw new Error("Browser provider did not return a session identifier.");
      const ownerId = env.BROWSER_SESSIONS.idFromName(tenant.tenantId);
      const owner = env.BROWSER_SESSIONS.get(ownerId);
      const stored = await owner.fetch("https://browser-session/session", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId, allowedDomains }),
      });
      if (!stored.ok) throw new Error("Browser session ownership could not be stored.");
      return result({ tenant: tenant.tenantId, browserReady: true });
    },
  );
  registerTool("browser_tabs", {
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
  registerTool("browser_tab_open", {
    title: "Open Browser Tab",
    description: "Open a public web URL in a new tab of an existing tenant browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { url: z.string().url() },
  }, async ({ url }: { url: string }) => {
    const target = new URL(url);
    if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("Unsupported URL scheme.");
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const policy = await tenantBrowserPolicy(env, tenant);
    if (!hostnameAllowed(target.hostname, policy.allowedDomains)) throw new Error("Destination hostname is outside this tenant browser session policy.");
    const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(policy.sessionId) + "/json/new?url=" + encodeURIComponent(target.toString()) + "&liveViewUrlExpiresInMs=300000";
    const response = await env.BROWSER.fetch(endpoint, { method: "PUT" });
    if (!response.ok) throw new Error("Browser tab open failed.");
    return result({ tenant: tenant.tenantId, tab: await response.json() });
  });
  registerTool("browser_page_preview", {
    title: "Browser Page Preview",
    description: "Capture a PNG preview of a public web page for display in ChatGPT.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { url: z.string().url() },
  }, async ({ url }: { url: string }) => {
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const response = await env.BROWSER.fetch("https://browser-rendering/screenshot", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
    if (!response.ok) throw new Error("Browser preview failed.");
    const bytes = new Uint8Array(await response.arrayBuffer());
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return { content: [{ type: "image", data: btoa(binary), mimeType: "image/png" }] };
  });
  registerAppResource(server, "browser-view", "ui://ravi-developer-agent/browser-v1.html", {}, async () => ({
    contents: [{
      uri: "ui://ravi-developer-agent/browser-v1.html",
      mimeType: RESOURCE_MIME_TYPE,
      text: `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body,#frame{width:100%;height:100%;margin:0}body{font-family:system-ui;background:#111;color:#fff}#status{padding:12px}#frame{border:0;display:none}</style></head><body><div id="status">Preparing secure browser view…</div><iframe id="frame" title="Ravi Developer Agent browser"></iframe><script>const status=document.getElementById("status"),frame=document.getElementById("frame");function apply(v){const u=v?.structuredContent?.liveView?.devtoolsFrontendUrl||v?.structuredContent?.liveView?.url||v?.liveView?.devtoolsFrontendUrl||v?.liveView?.url;if(u){frame.src=u;frame.style.display="block";status.style.display="none"}}window.addEventListener("message",e=>{const m=e.data;if(m?.method==="ui/notifications/tool-result")apply(m.params) });if(window.openai?.toolOutput)apply(window.openai.toolOutput);</script></body></html>`,
      _meta: { ui: { prefersBorder: false, csp: { frameDomains: ["https://live.browser.run"] } }, "openai/ui": { availableDisplayModes: ["inline", "fullscreen"] } },
    }],
  }));

  registerTool("browser_live_view", {
    title: "Browser Live View",
    description: "Create a short-lived read-only live view for an existing browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: {},
    _meta: { ui: { resourceUri: "ui://ravi-developer-agent/browser-v1.html" } },
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
      const mcp = createMcpHandler(() => createServer(tenant, env), { route: "/mcp" });
      return mcp(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
