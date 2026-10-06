import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { DurableObject } from "cloudflare:workers";
import { OAuthResourceServer, insufficientScope, type AuthorizationServerBinding } from "@cloudflare/workers-oauth-provider";
import { registerAppResource, registerAppTool, RESOURCE_MIME_TYPE } from "@modelcontextprotocol/ext-apps/server";
import puppeteer from "@cloudflare/puppeteer";

type AuthProps = {
  userId: string;
  tenantId: string;
  subject: string;
  loginProvider: "github";
  login: string;
};

type Env = {
  BROWSER?: Fetcher;
  BROWSER_SESSIONS: DurableObjectNamespace<TenantBrowserSession>;
  AUTH_SERVER: AuthorizationServerBinding<AuthProps>;
  CONNECTIONS_KV: KVNamespace;
  CONNECTION_ENCRYPTION_KEY?: CryptoKey;
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
  login: string;
  scopes: string[];
};

const RESOURCE_METADATA_URL = "https://ravi-developer-agent.rvrmvth.workers.dev/.well-known/oauth-protected-resource/mcp";

function toolAuthRequired(scopes: string[]) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: "Additional authorization is required for this action." }],
    _meta: {
      "mcp/www_authenticate": `Bearer resource_metadata="${RESOURCE_METADATA_URL}", scope="${scopes.join(" ")}"`,
    },
  };
}

function safeTab(value: unknown) {
  const tab = (value ?? {}) as Record<string, unknown>;
  return {
    id: typeof tab.id === "string" ? tab.id : "",
    type: typeof tab.type === "string" ? tab.type : "",
    title: typeof tab.title === "string" ? tab.title : "",
    url: typeof tab.url === "string" ? tab.url : "",
  };
}

type ProviderName = "github" | "cloudflare" | "supabase";

function providerConnectionKey(tenant: TenantContext, provider: ProviderName): string {
  return `v1:tenant:${tenant.tenantId}:provider:${provider}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToArrayBuffer(value: string): ArrayBuffer {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

async function storeProviderConnection(
  env: Env,
  tenant: TenantContext,
  provider: ProviderName,
  value: Record<string, unknown>,
): Promise<void> {
  if (!env.CONNECTION_ENCRYPTION_KEY) throw new Error("Provider connection encryption is not configured.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    env.CONNECTION_ENCRYPTION_KEY,
    plaintext,
  );
  await env.CONNECTIONS_KV.put(
    providerConnectionKey(tenant, provider),
    JSON.stringify({
      version: 1,
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    }),
  );
}

async function readProviderConnection(
  env: Env,
  tenant: TenantContext,
  provider: ProviderName,
): Promise<Record<string, unknown> | null> {
  if (!env.CONNECTION_ENCRYPTION_KEY) return null;
  const stored = await env.CONNECTIONS_KV.get(providerConnectionKey(tenant, provider));
  if (!stored) return null;
  const payload = JSON.parse(stored) as { version?: number; iv?: string; ciphertext?: string };
  if (payload.version !== 1 || !payload.iv || !payload.ciphertext) throw new Error("Provider connection record is invalid.");
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToArrayBuffer(payload.iv) },
    env.CONNECTION_ENCRYPTION_KEY,
    base64ToArrayBuffer(payload.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(decrypted)) as Record<string, unknown>;
}


function result(data: unknown) {
  const text = JSON.stringify(data);
  return { structuredContent: data as Record<string, unknown>, content: [{ type: "text" as const, text }] };
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


async function openTenantTab(env: Env, tenant: TenantContext, url: string) {
  const target = new URL(url);
  if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("Unsupported URL scheme.");
  if (target.username || target.password) throw new Error("Credentials in navigation URLs are not allowed.");
  if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
  const policy = await tenantBrowserPolicy(env, tenant);
  if (!hostnameAllowed(target.hostname, policy.allowedDomains)) {
    throw new Error("Destination hostname is outside this tenant browser session policy.");
  }
  const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(policy.sessionId) +
    "/json/new?url=" + encodeURIComponent(target.toString());
  const response = await env.BROWSER.fetch(endpoint, { method: "PUT" });
  if (!response.ok) throw new Error(`Browser tab open failed (${response.status}).`);
  return safeTab(await response.json());
}

async function connectTenantPage(env: Env, tenant: TenantContext, targetId?: string) {
  if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
  const sessionId = await tenantSessionId(env, tenant);
  const browser = await puppeteer.connect(env.BROWSER as any, sessionId);
  const pages = await browser.pages();
  let page = pages.find((candidate: any) => targetId && String((candidate.target() as any)._targetId ?? "") === targetId);
  if (!page && !targetId) page = pages.find((candidate: any) => candidate.url() !== "about:blank") ?? pages[0];
  if (!page) {
    browser.disconnect();
    throw new Error("Requested browser page is not available.");
  }
  return { browser, page, targetId: String((page.target() as any)._targetId ?? "") };
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
      authentication: "oauth-2.1",
      providers: [],
    }),
  );

  registerTool(
    "agent_profile",
    {
      title: "Connected Account",
      description: "Return the authenticated Ravi Developer Agent account identity for connection management.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      _meta: { "openai/profile": true },
    },
    async () => result({
      id: tenant.subject,
      name: tenant.login,
      provider: "github",
      tenant: tenant.tenantId,
    }),
  );

  registerTool(
    "provider_connections",
    {
      title: "Provider Connections",
      description: "Show which external developer providers are connected for the authenticated tenant without exposing credentials.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {},
    },
    async () => {
      const providers: ProviderName[] = ["github", "cloudflare", "supabase"];
      const connections = await Promise.all(providers.map(async (provider) => ({
        provider,
        connected: (await env.CONNECTIONS_KV.get(providerConnectionKey(tenant, provider))) !== null,
      })));
      return result({
        tenant: tenant.tenantId,
        encryptedStorageReady: Boolean(env.CONNECTION_ENCRYPTION_KEY),
        connections,
      });
    },
  );

  registerTool(
    "provider_disconnect",
    {
      title: "Disconnect Provider",
      description: "Delete the authenticated tenant's stored connection for one developer provider.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true },
      inputSchema: { provider: z.enum(["github", "cloudflare", "supabase"]) },
    },
    async ({ provider }: { provider: ProviderName }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      await env.CONNECTIONS_KV.delete(providerConnectionKey(tenant, provider));
      return result({ tenant: tenant.tenantId, provider, connected: false });
    },
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
        "persistent tenant browser sessions",
        "Cloudflare-enforced hostname guardrails",
        "multiple tabs and safe page navigation",
        "tab activation and cleanup",
        "short-lived read-only Live View in ChatGPT",
      ],
      isolation: "per-tenant browser context/session",
      navigationEnabled: true,
    }),
  );

  registerTool(
    "browser_open",
    {
      title: "Open Website",
      description: "Open a permitted HTTP/HTTPS URL in a new tab of the tenant's guarded browser session.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { url: z.string().url() },
    },
    async ({ url }: { url: string }) => {
      const tab = await openTenantTab(env, tenant, url);
      return result({ tenant: tenant.tenantId, tab });
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
    const response = await env.BROWSER.fetch(`https://browser-rendering/devtools/browser/${encodeURIComponent(sessionId)}/json/list`);
    if (!response.ok) throw new Error(`Browser tab listing failed (${response.status}).`);
    const rawTabs = await response.json() as unknown[];
    return result({ tenant: tenant.tenantId, tabs: rawTabs.map(safeTab) });
  });
  registerTool("browser_tab_open", {
    title: "Open Browser Tab",
    description: "Open a permitted web URL in a new tab of the tenant's guarded browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { url: z.string().url() },
  }, async ({ url }: { url: string }) => {
    const tab = await openTenantTab(env, tenant, url);
    return result({ tenant: tenant.tenantId, tab });
  });

  registerTool("browser_tab_activate", {
    title: "Activate Browser Tab",
    description: "Make a tab active in the tenant browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: false, destructiveHint: false },
    inputSchema: { targetId: z.string().regex(/^[A-Za-z0-9]+$/) },
  }, async ({ targetId }: { targetId: string }) => {
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(sessionId) +
      "/json/activate/" + encodeURIComponent(targetId);
    const response = await env.BROWSER.fetch(endpoint);
    if (!response.ok) throw new Error(`Browser tab activation failed (${response.status}).`);
    return result({ tenant: tenant.tenantId, targetId, active: true });
  });

  registerTool("browser_tab_close", {
    title: "Close Browser Tab",
    description: "Close a tab in the tenant browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: { targetId: z.string().regex(/^[A-Za-z0-9]+$/) },
  }, async ({ targetId }: { targetId: string }) => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(sessionId) +
      "/json/close/" + encodeURIComponent(targetId);
    const response = await env.BROWSER.fetch(endpoint);
    if (!response.ok) throw new Error(`Browser tab close failed (${response.status}).`);
    return result({ tenant: tenant.tenantId, targetId, closed: true });
  });

  registerTool("browser_session_close", {
    title: "Close Browser Session",
    description: "Close the tenant's current cloud browser session and clear its ownership record.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: {},
  }, async () => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const response = await env.BROWSER.fetch(
      "https://browser-rendering/devtools/browser/" + encodeURIComponent(sessionId),
      { method: "DELETE" },
    );
    if (!response.ok && response.status !== 404) throw new Error(`Browser session close failed (${response.status}).`);
    const ownerId = env.BROWSER_SESSIONS.idFromName(tenant.tenantId);
    await env.BROWSER_SESSIONS.get(ownerId).fetch("https://browser-session/session", { method: "DELETE" });
    return result({ tenant: tenant.tenantId, closed: true });
  });

  registerTool("browser_screenshot", {
    title: "Browser Screenshot",
    description: "Capture the current guarded tenant-browser page as a PNG image.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional() },
  }, async ({ targetId }: { targetId?: string }) => {
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      const screenshot = await page.screenshot({ type: "png" });
      const bytes = screenshot instanceof Uint8Array ? screenshot : new Uint8Array(screenshot as ArrayBuffer);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return {
        structuredContent: { tenant: tenant.tenantId, targetId: resolvedTargetId, url: page.url() },
        content: [{ type: "image" as const, data: btoa(binary), mimeType: "image/png" }],
      };
    } finally {
      browser.disconnect();
    }
  });

  registerTool("browser_page_text", {
    title: "Read Browser Page",
    description: "Read visible text and basic page metadata from the current guarded tenant-browser page.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional() },
  }, async ({ targetId }: { targetId?: string }) => {
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      const visibleText = String(await page.evaluate(() => (globalThis as any).document?.body?.innerText ?? ""));
      return result({
        tenant: tenant.tenantId,
        targetId: resolvedTargetId,
        url: page.url(),
        title: await page.title(),
        text: visibleText.slice(0, 50000),
      });
    } finally {
      browser.disconnect();
    }
  });

  registerAppResource(server, "browser-view", "ui://ravi-developer-agent/browser-v1.html", {}, async () => ({
    contents: [{
      uri: "ui://ravi-developer-agent/browser-v1.html",
      mimeType: RESOURCE_MIME_TYPE,
      text: `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body,#frame{width:100%;height:100%;margin:0}body{font-family:system-ui;background:#111;color:#fff}#status{padding:12px}#frame{border:0;display:none}</style></head><body><div id="status">Preparing secure browser view…</div><iframe id="frame" title="Ravi Developer Agent browser"></iframe><script>const status=document.getElementById("status"),frame=document.getElementById("frame");function apply(v){const host=window.openai?.toolResponseMetadata;const meta=v?._meta||host?.mcp_tool_result?._meta||host?.call_tool_result?._meta||host?._meta;const lv=meta?.liveView;const u=lv?.devtoolsFrontendUrl||lv?.url;if(u){frame.src=u;frame.style.display="block";status.style.display="none"}}window.addEventListener("message",e=>{const m=e.data;if(m?.method==="ui/notifications/tool-result")apply(m.params) });apply(window.openai?.toolResponseMetadata);</script></body></html>`,
      _meta: { ui: { prefersBorder: false, csp: { frameDomains: ["https://live.browser.run"] } }, "openai/ui": { availableDisplayModes: ["inline", "fullscreen"] } },
    }],
  }));

  registerTool("browser_live_control", {
    title: "Interactive Browser Control",
    description: "Create a short-lived interactive browser view for secure human takeover, including manual sign-in.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: {},
    _meta: { ui: { resourceUri: "ui://ravi-developer-agent/browser-v1.html" } },
  }, async () => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const endpoint = "https://browser-rendering/devtools/browser/" + encodeURIComponent(sessionId) + "/live_view";
    const response = await env.BROWSER.fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresInMs: 300000, mode: "tab" }),
    });
    if (!response.ok) throw new Error("Interactive browser view creation failed.");
    const liveView = await response.json();
    return {
      structuredContent: { tenant: tenant.tenantId, browserReady: true, interactive: true },
      content: [{ type: "text" as const, text: "Interactive browser control is ready for secure human takeover." }],
      _meta: { liveView },
    };
  });

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
    const liveView = await response.json();
    return {
      structuredContent: { tenant: tenant.tenantId, browserReady: true },
      content: [{ type: "text" as const, text: "Secure read-only browser view is ready." }],
      _meta: { liveView },
    };
  });
  return server;
}

const MCP_RESOURCE = "https://ravi-developer-agent.rvrmvth.workers.dev/mcp";
const AUTH_ISSUER = "https://ravi-developer-agent-auth.rvrmvth.workers.dev";

const oauthMcp = new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: MCP_RESOURCE,
    authorization_servers: [AUTH_ISSUER],
    resource_name: "Ravi Developer Agent",
  },
  requiredScopes: ["agent:read"],
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler: {
    async fetch(request, env, ctx) {
      if (!ctx.auth.scope.includes("agent:read")) {
        return insufficientScope(ctx.auth, ["agent:read"]);
      }
      const url = new URL(request.url);
      if (url.pathname !== "/mcp") return new Response("Not found", { status: 404 });
      const tenant: TenantContext = {
        tenantId: ctx.props.tenantId,
        subject: ctx.props.subject,
        login: ctx.props.login,
        scopes: ctx.auth.scope,
      };
      const mcp = createMcpHandler(() => createServer(tenant, env), { route: "/mcp" });
      return mcp(request, env, ctx);
    },
  },
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "ravi-developer-agent",
        version: "0.3.0",
        authentication: "oauth-2.1",
      });
    }

    if (url.pathname === "/") {
      return Response.json({
        name: "Ravi Developer Agent",
        version: "0.3.0",
        mcp: "/mcp",
        health: "/health",
        authentication: "OAuth 2.1 required for MCP",
      });
    }

    if (url.pathname === "/mcp" || url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return oauthMcp.fetch(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
