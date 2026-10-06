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
  githubToken: string;
};

type AuthServerService = AuthorizationServerBinding<AuthProps> & {
  getProviderClient(provider: "cloudflare" | "supabase"): Promise<{ clientId: string; clientSecret: string } | null>;
};

type Env = {
  BROWSER?: Fetcher;
  BROWSER_SESSIONS: DurableObjectNamespace<TenantBrowserSession>;
  PROVIDER_CONNECTIONS: DurableObjectNamespace<TenantConnections>;
  OAUTH_CONNECT_STATE: DurableObjectNamespace<OAuthConnectState>;
  TENANT_GUARD: DurableObjectNamespace<TenantGuard>;
  AUTH_SERVER: AuthServerService;
  CLOUDFLARE_OAUTH_CLIENT_ID?: string;
  CLOUDFLARE_OAUTH_CLIENT_SECRET?: string;
  SUPABASE_OAUTH_CLIENT_ID?: string;
  SUPABASE_OAUTH_CLIENT_SECRET?: string;
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

type ProviderName = "cloudflare" | "supabase";
type StoredProviderConnection = { value: ProviderConnection; updatedAt: number };

export class TenantConnections extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const provider = url.pathname.split("/").filter(Boolean)[1] as ProviderName | undefined;
    if (!provider || !["cloudflare", "supabase"].includes(provider)) {
      return new Response("invalid_provider", { status: 400 });
    }
    const key = "provider:" + provider;
    if (request.method === "PUT") {
      const body = await request.json() as StoredProviderConnection;
      if (!body.value?.accessToken || !body.updatedAt) return new Response("invalid_connection", { status: 400 });
      await this.ctx.storage.put(key, body);
      return Response.json({ ok: true });
    }
    if (request.method === "GET") {
      const value = await this.ctx.storage.get<StoredProviderConnection>(key);
      return value ? Response.json(value) : new Response("connection_not_found", { status: 404 });
    }
    if (request.method === "DELETE") {
      await this.ctx.storage.delete(key);
      return Response.json({ ok: true });
    }
    return new Response("method_not_allowed", { status: 405 });
  }
}

type OAuthConnectStateRecord = {
  tenantId: string;
  provider: ProviderName;
  verifier: string;
  createdAt: number;
};

export class OAuthConnectState extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "PUT" && url.pathname === "/state") {
      const body = await request.json() as OAuthConnectStateRecord;
      if (!body.tenantId || !body.provider || !body.verifier || !body.createdAt) return new Response("invalid_state", { status: 400 });
      await this.ctx.storage.put("state", body);
      return Response.json({ ok: true });
    }
    if (request.method === "POST" && url.pathname === "/consume") {
      const body = await this.ctx.storage.get<OAuthConnectStateRecord>("state");
      if (!body) return new Response("state_not_found", { status: 404 });
      await this.ctx.storage.delete("state");
      if (Date.now() - body.createdAt > 10 * 60 * 1000) return new Response("state_expired", { status: 410 });
      return Response.json(body);
    }
    return new Response("not_found", { status: 404 });
  }
}

export class TenantGuard extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/consume") {
      const now = Date.now();
      const minute = Math.floor(now / 60_000);
      const key = "rate:" + minute;
      const count = (await this.ctx.storage.get<number>(key)) ?? 0;
      const limit = 120;
      if (count >= limit) {
        return Response.json({ ok: false, retryAfterSeconds: 60 - Math.floor((now % 60_000) / 1000) }, { status: 429 });
      }
      await this.ctx.storage.put(key, count + 1);
      const previous = "rate:" + (minute - 2);
      await this.ctx.storage.delete(previous);
      return Response.json({ ok: true, remaining: Math.max(0, limit - count - 1) });
    }

    if (request.method === "POST" && url.pathname === "/audit") {
      const body = await request.json() as { action?: string; subject?: string };
      if (!body.action || !/^[a-z0-9_:-]{1,128}$/i.test(body.action)) return new Response("invalid_action", { status: 400 });
      const timestamp = Date.now();
      const id = crypto.randomUUID();
      await this.ctx.storage.put("audit:" + String(timestamp).padStart(13, "0") + ":" + id, {
        timestamp,
        action: body.action,
        subject: body.subject ?? "",
      });
      const cutoff = timestamp - 30 * 24 * 60 * 60 * 1000;
      const old = await this.ctx.storage.list<{ timestamp?: number }>({ prefix: "audit:", limit: 100 });
      const stale = [...old.entries()].filter(([, value]) => (value?.timestamp ?? timestamp) < cutoff).map(([key]) => key);
      if (stale.length) await this.ctx.storage.delete(stale);
      return Response.json({ ok: true });
    }

    if (request.method === "GET" && url.pathname === "/audit") {
      const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") ?? 50) || 50));
      const list = await this.ctx.storage.list<{ timestamp: number; action: string; subject: string }>({ prefix: "audit:", reverse: true, limit });
      return Response.json({ events: [...list.values()] });
    }

    return new Response("not_found", { status: 404 });
  }
}

async function tenantGuard(env: Env, tenantId: string) {
  return env.TENANT_GUARD.get(env.TENANT_GUARD.idFromName(tenantId));
}

async function enforceTenantRateLimit(env: Env, tenantId: string): Promise<Response | null> {
  const response = await (await tenantGuard(env, tenantId)).fetch("https://tenant-guard/consume", { method: "POST" });
  if (response.status !== 429) return null;
  const body = await response.json() as { retryAfterSeconds?: number };
  return new Response("Too many requests", {
    status: 429,
    headers: {
      "retry-after": String(body.retryAfterSeconds ?? 60),
      "cache-control": "no-store",
    },
  });
}

async function auditTenantAction(env: Env, tenant: TenantContext, action: string): Promise<void> {
  try {
    await (await tenantGuard(env, tenant.tenantId)).fetch("https://tenant-guard/audit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action, subject: tenant.subject }),
    });
  } catch {
    // Audit failure must never expose secrets or break the requested action.
  }
}

type TenantContext = {
  tenantId: string;
  subject: string;
  login: string;
  scopes: string[];
  githubToken: string;
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

function result(data: unknown) {
  const text = JSON.stringify(data);
  return { structuredContent: data as Record<string, unknown>, content: [{ type: "text" as const, text }] };
}

function githubHeaders(tenant: TenantContext): HeadersInit {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${tenant.githubToken}`,
    "user-agent": "ravi-developer-agent",
    "x-github-api-version": "2022-11-28",
  };
}

async function githubFetch(tenant: TenantContext, path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(githubHeaders(tenant));
  for (const [key, value] of new Headers(init.headers)) headers.set(key, value);
  return fetch("https://api.github.com" + path, { ...init, headers });
}

async function githubJson<T>(tenant: TenantContext, path: string, init: RequestInit = {}): Promise<T> {
  const response = await githubFetch(tenant, path, init);
  if (!response.ok) throw new Error(`GitHub request failed (${response.status}).`);
  return response.json() as Promise<T>;
}

function encodeRepoPath(path: string): string {
  const parts = path.split("/").filter(Boolean);
  if (!parts.length || parts.some((part) => part === "." || part === "..")) throw new Error("Invalid repository path.");
  return parts.map(encodeURIComponent).join("/");
}

function encodeUtf8Base64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeUtf8Base64(value: string): string {
  const normalized = value.replace(/\s/g, "");
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}


type ProviderConnection = {
  accessToken: string;
  refreshToken?: string;
  tokenType?: string;
  scope?: string;
  expiresAt?: number;
};

const MAIN_ORIGIN = "https://ravi-developer-agent.rvrmvth.workers.dev";
const CLOUDFLARE_CALLBACK = MAIN_ORIGIN + "/oauth/cloudflare/callback";
const SUPABASE_CALLBACK = MAIN_ORIGIN + "/oauth/supabase/callback";

function randomBase64Url(bytesLength = 32): string {
  const bytes = new Uint8Array(bytesLength);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function providerStore(env: Env, tenantId: string) {
  return env.PROVIDER_CONNECTIONS.get(env.PROVIDER_CONNECTIONS.idFromName(tenantId));
}

async function saveProviderConnection(env: Env, tenantId: string, provider: ProviderName, connection: ProviderConnection): Promise<void> {
  const response = await providerStore(env, tenantId).fetch("https://provider-connections/provider/" + provider, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ value: connection, updatedAt: Date.now() } satisfies StoredProviderConnection),
  });
  if (!response.ok) throw new Error("Provider connection could not be stored.");
}

async function providerConnectionExists(env: Env, tenantId: string, provider: ProviderName): Promise<boolean> {
  const response = await providerStore(env, tenantId).fetch("https://provider-connections/provider/" + provider);
  return response.ok;
}

async function loadProviderConnection(env: Env, tenantId: string, provider: ProviderName): Promise<ProviderConnection> {
  const response = await providerStore(env, tenantId).fetch("https://provider-connections/provider/" + provider);
  if (!response.ok) throw new Error(provider + " is not connected.");
  const stored = await response.json() as StoredProviderConnection;
  if (!stored.value?.accessToken) throw new Error(provider + " connection is invalid.");
  return stored.value;
}

async function deleteProviderConnection(env: Env, tenantId: string, provider: ProviderName): Promise<void> {
  await providerStore(env, tenantId).fetch("https://provider-connections/provider/" + provider, { method: "DELETE" });
}

async function providerClient(env: Env, provider: ProviderName): Promise<{ clientId: string; clientSecret: string; callback: string }> {
  if (provider === "cloudflare" && env.CLOUDFLARE_OAUTH_CLIENT_ID && env.CLOUDFLARE_OAUTH_CLIENT_SECRET) {
    return { clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID, clientSecret: env.CLOUDFLARE_OAUTH_CLIENT_SECRET, callback: CLOUDFLARE_CALLBACK };
  }
  if (provider === "supabase" && env.SUPABASE_OAUTH_CLIENT_ID && env.SUPABASE_OAUTH_CLIENT_SECRET) {
    return { clientId: env.SUPABASE_OAUTH_CLIENT_ID, clientSecret: env.SUPABASE_OAUTH_CLIENT_SECRET, callback: SUPABASE_CALLBACK };
  }
  const stored = await env.AUTH_SERVER.getProviderClient(provider);
  if (!stored) throw new Error((provider === "cloudflare" ? "Cloudflare" : "Supabase") + " OAuth application is not configured.");
  return {
    ...stored,
    callback: provider === "cloudflare" ? CLOUDFLARE_CALLBACK : SUPABASE_CALLBACK,
  };
}

async function providerConfigured(env: Env, provider: ProviderName): Promise<boolean> {
  try {
    await providerClient(env, provider);
    return true;
  } catch {
    return false;
  }
}

async function beginProviderOAuth(env: Env, tenant: TenantContext, provider: ProviderName): Promise<string> {
  const client = await providerClient(env, provider);
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(48);
  const stateId = env.OAUTH_CONNECT_STATE.idFromName(state);
  const stored = await env.OAUTH_CONNECT_STATE.get(stateId).fetch("https://oauth-connect/state", {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tenantId: tenant.tenantId, provider, verifier, createdAt: Date.now() } satisfies OAuthConnectStateRecord),
  });
  if (!stored.ok) throw new Error("Provider authorization state could not be stored.");

  const challenge = await pkceChallenge(verifier);
  if (provider === "cloudflare") {
    const url = new URL("https://dash.cloudflare.com/oauth2/auth");
    url.searchParams.set("client_id", client.clientId);
    url.searchParams.set("redirect_uri", client.callback);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("scope", "offline_access account-settings.read workers-scripts.read workers-scripts.write workers-kv-storage.read workers-kv-storage.write d1.read d1.write workers-r2.read workers-r2.write workers-ci.read workers-ci.write browser-rendering.read browser-rendering.write");
    return url.toString();
  }

  const url = new URL("https://api.supabase.com/v1/oauth/authorize");
  url.searchParams.set("client_id", client.clientId);
  url.searchParams.set("redirect_uri", client.callback);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

async function consumeProviderState(env: Env, state: string, provider: ProviderName): Promise<OAuthConnectStateRecord> {
  if (!/^[A-Za-z0-9_-]{20,200}$/.test(state)) throw new Error("Invalid OAuth state.");
  const id = env.OAUTH_CONNECT_STATE.idFromName(state);
  const response = await env.OAUTH_CONNECT_STATE.get(id).fetch("https://oauth-connect/consume", { method: "POST" });
  if (!response.ok) throw new Error("Provider authorization state is invalid or expired.");
  const record = await response.json() as OAuthConnectStateRecord;
  if (record.provider !== provider) throw new Error("Provider authorization state does not match.");
  return record;
}

function basicAuth(clientId: string, clientSecret: string): string {
  return "Basic " + btoa(clientId + ":" + clientSecret);
}

async function exchangeProviderCode(env: Env, provider: ProviderName, code: string, verifier: string): Promise<ProviderConnection> {
  const client = await providerClient(env, provider);
  const tokenUrl = provider === "cloudflare"
    ? "https://dash.cloudflare.com/oauth2/token"
    : "https://api.supabase.com/v1/oauth/token";
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      authorization: basicAuth(client.clientId, client.clientSecret),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: client.callback,
      code_verifier: verifier,
    }),
  });
  if (!response.ok) throw new Error("Provider token exchange failed (" + response.status + ").");
  const token = await response.json() as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
    scope?: string;
  };
  if (!token.access_token) throw new Error("Provider did not return an access token.");
  return {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    tokenType: token.token_type,
    scope: token.scope,
    expiresAt: token.expires_in ? Date.now() + token.expires_in * 1000 : undefined,
  };
}

async function refreshProviderConnection(env: Env, tenantId: string, provider: ProviderName, connection: ProviderConnection): Promise<ProviderConnection> {
  if (!connection.refreshToken || !connection.expiresAt || connection.expiresAt > Date.now() + 60_000) return connection;
  const client = await providerClient(env, provider);
  const tokenUrl = provider === "cloudflare"
    ? "https://dash.cloudflare.com/oauth2/token"
    : "https://api.supabase.com/v1/oauth/token";
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      authorization: basicAuth(client.clientId, client.clientSecret),
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: connection.refreshToken,
    }),
  });
  if (!response.ok) throw new Error(provider + " authorization has expired; reconnect the provider.");
  const token = await response.json() as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
    scope?: string;
  };
  if (!token.access_token) throw new Error(provider + " token refresh failed.");
  const refreshed: ProviderConnection = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token ?? connection.refreshToken,
    tokenType: token.token_type ?? connection.tokenType,
    scope: token.scope ?? connection.scope,
    expiresAt: token.expires_in ? Date.now() + token.expires_in * 1000 : connection.expiresAt,
  };
  await saveProviderConnection(env, tenantId, provider, refreshed);
  return refreshed;
}

async function activeProviderConnection(env: Env, tenantId: string, provider: ProviderName): Promise<ProviderConnection> {
  return refreshProviderConnection(env, tenantId, provider, await loadProviderConnection(env, tenantId, provider));
}

function providerConnectedPage(provider: ProviderName, ok: boolean, message: string): Response {
  const title = ok ? provider + " connected" : provider + " connection failed";
  const safeMessage = message.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>body{font-family:system-ui;background:#101216;color:#f4f6fb;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:520px;padding:28px;border:1px solid #2b3140;border-radius:18px;background:#181b22}h1{margin-top:0}</style>
<div class="card"><h1>${ok ? "Connected" : "Connection failed"}</h1><p>${safeMessage}</p><p>You can close this tab and return to ChatGPT.</p></div>`;
  return new Response(html, {
    status: ok ? 200 : 400,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
    },
  });
}

async function providerOAuthCallback(request: Request, env: Env, provider: ProviderName): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") ?? "";
  try {
    const record = await consumeProviderState(env, state, provider);
    const error = url.searchParams.get("error");
    if (error) return providerConnectedPage(provider, false, "Authorization was not completed.");
    const code = url.searchParams.get("code");
    if (!code) return providerConnectedPage(provider, false, "Authorization code is missing.");
    const connection = await exchangeProviderCode(env, provider, code, record.verifier);
    await saveProviderConnection(env, record.tenantId, provider, connection);
    return providerConnectedPage(provider, true, provider === "cloudflare" ? "Cloudflare is connected to Ravi Developer Agent." : "Supabase is connected to Ravi Developer Agent.");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Provider connection failed.";
    return providerConnectedPage(provider, false, message);
  }
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
  const server = new McpServer({ name: "ravi-developer-agent", version: "0.6.0" });
  // OpenAI/MCP Apps supports securitySchemes on tool descriptors, but the
  // ext-apps 2.0.3 TypeScript surface has not caught up with that field yet.
  // Keep runtime metadata standards-compliant while containing the cast here.
  const registerTool = (name: string, config: any, handler: any) => {
    const wrapped = async (...args: any[]) => {
      const output = await handler(...args);
      const requiresConfirmation = Boolean((output as any)?.structuredContent?.requiresConfirmation);
      if (config?.annotations?.readOnlyHint === false && !requiresConfirmation) {
        await auditTenantAction(env, tenant, name);
      }
      return output;
    };
    return (registerAppTool as any)(server, name, config, wrapped);
  };

  registerTool(
    "audit_recent",
    {
      title: "Recent Audit Activity",
      description: "Show recent state-changing Ravi Developer Agent actions for the authenticated tenant. Secret values and tool payloads are never recorded.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { limit: z.number().int().min(1).max(100).default(25) },
    },
    async ({ limit }: { limit: number }) => {
      const response = await (await tenantGuard(env, tenant.tenantId)).fetch("https://tenant-guard/audit?limit=" + encodeURIComponent(String(limit)));
      if (!response.ok) throw new Error("Audit history is unavailable.");
      const body = await response.json() as { events?: Array<{ timestamp: number; action: string; subject: string }> };
      return result({
        tenant: tenant.tenantId,
        retentionDays: 30,
        events: (body.events ?? []).map((event) => ({
          timestamp: new Date(event.timestamp).toISOString(),
          action: event.action,
        })),
      });
    },
  );

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
      version: "0.6.0",
      transport: "MCP Streamable HTTP",
      tenant: tenant.tenantId,
      authentication: "oauth-2.1",
      providers: {
        github: { configured: true, connected: true },
        cloudflare: {
          configured: await providerConfigured(env, "cloudflare"),
          connected: await providerConnectionExists(env, tenant.tenantId, "cloudflare"),
        },
        supabase: {
          configured: await providerConfigured(env, "supabase"),
          connected: await providerConnectionExists(env, tenant.tenantId, "supabase"),
        },
      },
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
    "project_plan",
    {
      title: "Project Plan",
      description: "Create a safe multi-provider execution plan for a cloud development task.",
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
      status: "ready-for-approved-actions",
    }),
  );

  registerTool(
    "github_connection_status",
    {
      title: "GitHub Connection",
      description: "Check whether GitHub is connected for the authenticated Ravi Developer Agent user.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => result({
      provider: "github",
      connected: true,
      login: tenant.login,
      tenant: tenant.tenantId,
    }),
  );

  registerTool(
    "github_list_repositories",
    {
      title: "List GitHub Repositories",
      description: "List repositories visible to the authenticated GitHub account.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        visibility: z.enum(["all", "public", "private"]).default("all"),
      },
    },
    async ({ visibility }: { visibility: "all" | "public" | "private" }) => {
      const query = new URLSearchParams({
        per_page: "100",
        sort: "updated",
        affiliation: "owner,collaborator,organization_member",
        visibility,
      });
      const repos = await githubJson<Array<{
        full_name: string;
        private: boolean;
        default_branch: string;
        permissions?: { admin?: boolean; push?: boolean; pull?: boolean };
        updated_at?: string;
      }>>(tenant, "/user/repos?" + query.toString());
      return result({
        provider: "github",
        repositories: repos.map((repo) => ({
          fullName: repo.full_name,
          private: repo.private,
          defaultBranch: repo.default_branch,
          permissions: repo.permissions ?? null,
          updatedAt: repo.updated_at ?? null,
        })),
      });
    },
  );

  registerTool(
    "github_get_file",
    {
      title: "Read GitHub File",
      description: "Read a UTF-8 text file from a repository visible to the connected GitHub account.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        owner: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        repo: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        path: z.string().min(1).max(1024),
        ref: z.string().min(1).max(255).optional(),
      },
    },
    async ({ owner, repo, path, ref }: { owner: string; repo: string; path: string; ref?: string }) => {
      const query = ref ? "?ref=" + encodeURIComponent(ref) : "";
      const file = await githubJson<{
        type?: string;
        name?: string;
        path?: string;
        sha?: string;
        size?: number;
        encoding?: string;
        content?: string;
        html_url?: string;
      }>(tenant, "/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/contents/" + encodeRepoPath(path) + query);
      if (file.type !== "file" || file.encoding !== "base64" || typeof file.content !== "string") {
        throw new Error("GitHub path is not a readable UTF-8 file.");
      }
      if ((file.size ?? 0) > 750000) throw new Error("File is too large for an inline tool result.");
      return result({
        repository: owner + "/" + repo,
        path: file.path ?? path,
        sha: file.sha ?? null,
        size: file.size ?? null,
        content: decodeUtf8Base64(file.content),
        htmlUrl: file.html_url ?? null,
      });
    },
  );

  registerTool(
    "github_create_branch",
    {
      title: "Create GitHub Branch",
      description: "Create a branch from an existing branch after explicit confirmation.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false },
      inputSchema: {
        owner: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        repo: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        branch: z.string().min(1).max(255),
        fromBranch: z.string().min(1).max(255).default("main"),
        confirm: z.boolean().default(false),
      },
    },
    async ({ owner, repo, branch, fromBranch, confirm }: { owner: string; repo: string; branch: string; fromBranch: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({ requiresConfirmation: true, action: "create_branch", repository: owner + "/" + repo, branch, fromBranch });
      const base = await githubJson<{ object?: { sha?: string } }>(
        tenant,
        "/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/git/ref/heads/" + encodeURIComponent(fromBranch),
      );
      const sha = base.object?.sha;
      if (!sha) throw new Error("Base branch commit could not be resolved.");
      const created = await githubJson<{ ref?: string; object?: { sha?: string } }>(
        tenant,
        "/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/git/refs",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ref: "refs/heads/" + branch, sha }),
        },
      );
      return result({ repository: owner + "/" + repo, branch: created.ref ?? "refs/heads/" + branch, sha: created.object?.sha ?? sha });
    },
  );

  registerTool(
    "github_put_file",
    {
      title: "Create or Update GitHub File",
      description: "Create or replace a UTF-8 repository file on a branch after explicit confirmation.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true },
      inputSchema: {
        owner: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        repo: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        path: z.string().min(1).max(1024),
        branch: z.string().min(1).max(255),
        message: z.string().min(1).max(500),
        content: z.string().max(500000),
        confirm: z.boolean().default(false),
      },
    },
    async ({ owner, repo, path, branch, message, content, confirm }: { owner: string; repo: string; path: string; branch: string; message: string; content: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({ requiresConfirmation: true, action: "put_file", repository: owner + "/" + repo, path, branch, bytes: new TextEncoder().encode(content).length });

      const apiPath = "/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/contents/" + encodeRepoPath(path);
      const existingResponse = await githubFetch(tenant, apiPath + "?ref=" + encodeURIComponent(branch));
      let sha: string | undefined;
      if (existingResponse.ok) {
        const existing = await existingResponse.json() as { sha?: string; type?: string };
        if (existing.type && existing.type !== "file") throw new Error("Target path is not a file.");
        sha = existing.sha;
      } else if (existingResponse.status !== 404) {
        throw new Error(`GitHub lookup failed (${existingResponse.status}).`);
      }

      const body: Record<string, unknown> = {
        message,
        content: encodeUtf8Base64(content),
        branch,
      };
      if (sha) body.sha = sha;

      const saved = await githubJson<{
        content?: { path?: string; sha?: string; html_url?: string };
        commit?: { sha?: string; html_url?: string };
      }>(tenant, apiPath, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });

      return result({
        repository: owner + "/" + repo,
        path: saved.content?.path ?? path,
        fileSha: saved.content?.sha ?? null,
        commitSha: saved.commit?.sha ?? null,
        commitUrl: saved.commit?.html_url ?? null,
      });
    },
  );

  registerTool(
    "github_create_pull_request",
    {
      title: "Create GitHub Pull Request",
      description: "Open a pull request after explicit confirmation.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false },
      inputSchema: {
        owner: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        repo: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        title: z.string().min(1).max(256),
        body: z.string().max(20000).default(""),
        head: z.string().min(1).max(255),
        base: z.string().min(1).max(255).default("main"),
        confirm: z.boolean().default(false),
      },
    },
    async ({ owner, repo, title, body, head, base, confirm }: { owner: string; repo: string; title: string; body: string; head: string; base: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({ requiresConfirmation: true, action: "create_pull_request", repository: owner + "/" + repo, title, head, base });
      const pull = await githubJson<{ number?: number; html_url?: string; state?: string }>(
        tenant,
        "/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/pulls",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ title, body, head, base }),
        },
      );
      return result({ repository: owner + "/" + repo, number: pull.number ?? null, url: pull.html_url ?? null, state: pull.state ?? null });
    },
  );


  registerTool(
    "cloudflare_connection_status",
    {
      title: "Cloudflare Connection",
      description: "Check whether Cloudflare OAuth is configured and connected for this tenant.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => result({
      provider: "cloudflare",
      configured: await providerConfigured(env, "cloudflare"),
      connected: await providerConnectionExists(env, tenant.tenantId, "cloudflare"),
      tenant: tenant.tenantId,
    }),
  );

  registerTool(
    "cloudflare_connect",
    {
      title: "Connect Cloudflare",
      description: "Start a secure Cloudflare OAuth connection using PKCE. The user must review and approve Cloudflare's consent screen.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false },
      inputSchema: { confirm: z.boolean().default(false) },
    },
    async ({ confirm }: { confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({ requiresConfirmation: true, action: "connect_cloudflare" });
      if (!await providerConfigured(env, "cloudflare")) {
        return result({
          provider: "cloudflare",
          configured: false,
          message: "Cloudflare OAuth client credentials and provider encryption must be configured by the app owner first.",
        });
      }
      return result({
        provider: "cloudflare",
        configured: true,
        connectUrl: await beginProviderOAuth(env, tenant, "cloudflare"),
        expiresInSeconds: 600,
      });
    },
  );

  registerTool(
    "cloudflare_list_accounts",
    {
      title: "List Cloudflare Accounts",
      description: "List Cloudflare accounts authorized for the connected tenant.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch("https://api.cloudflare.com/client/v4/accounts?per_page=50", {
        headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" },
      });
      if (!response.ok) throw new Error("Cloudflare account listing failed (" + response.status + ").");
      const body = await response.json() as {
        success?: boolean;
        result?: Array<{ id?: string; name?: string; type?: string }>;
      };
      if (body.success === false) throw new Error("Cloudflare account listing failed.");
      return result({
        provider: "cloudflare",
        accounts: (body.result ?? []).map((account) => ({
          id: account.id ?? null,
          name: account.name ?? null,
          type: account.type ?? null,
        })),
      });
    },
  );

  registerTool(
    "cloudflare_list_workers",
    {
      title: "List Cloudflare Workers",
      description: "List Worker scripts in an authorized Cloudflare account.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { accountId: z.string().regex(/^[A-Fa-f0-9]{32}$/) },
    },
    async ({ accountId }: { accountId: string }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch("https://api.cloudflare.com/client/v4/accounts/" + encodeURIComponent(accountId) + "/workers/scripts", {
        headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" },
      });
      if (!response.ok) throw new Error("Cloudflare Worker listing failed (" + response.status + ").");
      const body = await response.json() as {
        success?: boolean;
        result?: Array<{ id?: string; modified_on?: string; created_on?: string }>;
      };
      if (body.success === false) throw new Error("Cloudflare Worker listing failed.");
      return result({
        provider: "cloudflare",
        accountId,
        workers: (body.result ?? []).map((worker) => ({
          name: worker.id ?? null,
          createdAt: worker.created_on ?? null,
          modifiedAt: worker.modified_on ?? null,
        })),
      });
    },
  );

  registerTool(
    "cloudflare_list_worker_secrets",
    {
      title: "List Worker Secret Names",
      description: "List secret binding names for a Worker. Secret values are never returned.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        accountId: z.string().regex(/^[A-Fa-f0-9]{32}$/),
        scriptName: z.string().regex(/^[a-z0-9_][a-z0-9-_]*$/),
      },
    },
    async ({ accountId, scriptName }: { accountId: string; scriptName: string }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch(
        "https://api.cloudflare.com/client/v4/accounts/" + encodeURIComponent(accountId) +
          "/workers/scripts/" + encodeURIComponent(scriptName) + "/secrets",
        { headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" } },
      );
      if (!response.ok) throw new Error("Cloudflare Worker secret listing failed (" + response.status + ").");
      const body = await response.json() as {
        success?: boolean;
        result?: Array<{ name?: string; type?: string }>;
      };
      if (body.success === false) throw new Error("Cloudflare Worker secret listing failed.");
      return result({
        provider: "cloudflare",
        accountId,
        scriptName,
        secrets: (body.result ?? []).map((item) => ({ name: item.name ?? null, type: item.type ?? null })),
      });
    },
  );

  registerTool(
    "cloudflare_delete_worker_secret",
    {
      title: "Delete Worker Secret",
      description: "Delete a named Worker secret after explicit confirmation. The secret value is never exposed.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true },
      inputSchema: {
        accountId: z.string().regex(/^[A-Fa-f0-9]{32}$/),
        scriptName: z.string().regex(/^[a-z0-9_][a-z0-9-_]*$/),
        secretName: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
        confirm: z.boolean().default(false),
      },
    },
    async ({ accountId, scriptName, secretName, confirm }: { accountId: string; scriptName: string; secretName: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({
        requiresConfirmation: true,
        action: "delete_worker_secret",
        accountId,
        scriptName,
        secretName,
      });
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch(
        "https://api.cloudflare.com/client/v4/accounts/" + encodeURIComponent(accountId) +
          "/workers/scripts/" + encodeURIComponent(scriptName) + "/secrets/" + encodeURIComponent(secretName) + "?url_encoded=true",
        {
          method: "DELETE",
          headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" },
        },
      );
      if (!response.ok) throw new Error("Cloudflare Worker secret deletion failed (" + response.status + ").");
      return result({ provider: "cloudflare", accountId, scriptName, secretName, deleted: true });
    },
  );

  registerTool(
    "cloudflare_trigger_build",
    {
      title: "Trigger Cloudflare Build",
      description: "Trigger an existing Cloudflare Workers build by branch or commit after explicit confirmation.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false },
      inputSchema: {
        accountId: z.string().regex(/^[A-Fa-f0-9]{32}$/),
        triggerUuid: z.string().uuid(),
        branch: z.string().min(1).max(255).optional(),
        commitHash: z.string().regex(/^[A-Fa-f0-9]{7,64}$/).optional(),
        confirm: z.boolean().default(false),
      },
    },
    async ({ accountId, triggerUuid, branch, commitHash, confirm }: { accountId: string; triggerUuid: string; branch?: string; commitHash?: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!branch && !commitHash) throw new Error("Provide either branch or commitHash.");
      if (branch && commitHash) throw new Error("Provide only one of branch or commitHash.");
      if (!confirm) return result({
        requiresConfirmation: true,
        action: "trigger_cloudflare_build",
        accountId,
        triggerUuid,
        branch: branch ?? null,
        commitHash: commitHash ?? null,
      });
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch(
        "https://api.cloudflare.com/client/v4/accounts/" + encodeURIComponent(accountId) +
          "/builds/triggers/" + encodeURIComponent(triggerUuid) + "/builds",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + connection.accessToken,
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify(commitHash ? { commit_hash: commitHash } : { branch }),
        },
      );
      if (!response.ok) throw new Error("Cloudflare build trigger failed (" + response.status + ").");
      const body = await response.json() as {
        success?: boolean;
        result?: { build_uuid?: string; status?: string; preview_url?: string };
      };
      if (body.success === false) throw new Error("Cloudflare build trigger failed.");
      return result({
        provider: "cloudflare",
        buildUuid: body.result?.build_uuid ?? null,
        status: body.result?.status ?? null,
        previewUrl: body.result?.preview_url ?? null,
      });
    },
  );

  registerTool(
    "cloudflare_list_builds",
    {
      title: "List Cloudflare Builds",
      description: "List recent Workers Builds for an authorized Cloudflare account, including trigger and deployment status.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        accountId: z.string().regex(/^[A-Fa-f0-9]{32}$/),
        perPage: z.number().int().min(1).max(50).default(20),
      },
    },
    async ({ accountId, perPage }: { accountId: string; perPage: number }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch(
        "https://api.cloudflare.com/client/v4/accounts/" + encodeURIComponent(accountId) +
          "/builds/builds?per_page=" + encodeURIComponent(String(perPage)),
        { headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" } },
      );
      if (!response.ok) throw new Error("Cloudflare build listing failed (" + response.status + ").");
      const body = await response.json() as {
        success?: boolean;
        result?: Array<{
          build_uuid?: string;
          status?: string;
          build_outcome?: string | null;
          created_on?: string;
          stopped_on?: string | null;
          trigger?: { trigger_uuid?: string; trigger_name?: string; repo_connection?: { repo_name?: string; branch?: string } };
          build_trigger_metadata?: { commit_hash?: string; branch?: string; repo_name?: string };
        }>;
      };
      if (body.success === false) throw new Error("Cloudflare build listing failed.");
      return result({
        provider: "cloudflare",
        accountId,
        builds: (body.result ?? []).map((build) => ({
          buildUuid: build.build_uuid ?? null,
          status: build.status ?? null,
          outcome: build.build_outcome ?? null,
          createdAt: build.created_on ?? null,
          stoppedAt: build.stopped_on ?? null,
          triggerUuid: build.trigger?.trigger_uuid ?? null,
          triggerName: build.trigger?.trigger_name ?? null,
          repository: build.build_trigger_metadata?.repo_name ?? build.trigger?.repo_connection?.repo_name ?? null,
          branch: build.build_trigger_metadata?.branch ?? null,
          commitHash: build.build_trigger_metadata?.commit_hash ?? null,
        })),
      });
    },
  );

  registerTool(
    "cloudflare_get_build",
    {
      title: "Get Cloudflare Build",
      description: "Read the current status and outcome of one Workers Build.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        accountId: z.string().regex(/^[A-Fa-f0-9]{32}$/),
        buildUuid: z.string().uuid(),
      },
    },
    async ({ accountId, buildUuid }: { accountId: string; buildUuid: string }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "cloudflare");
      const response = await fetch(
        "https://api.cloudflare.com/client/v4/accounts/" + encodeURIComponent(accountId) +
          "/builds/builds/" + encodeURIComponent(buildUuid),
        { headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" } },
      );
      if (!response.ok) throw new Error("Cloudflare build lookup failed (" + response.status + ").");
      const body = await response.json() as {
        success?: boolean;
        result?: {
          build_uuid?: string;
          status?: string;
          build_outcome?: string | null;
          created_on?: string;
          running_on?: string | null;
          stopped_on?: string | null;
          preview_url?: string | null;
        };
      };
      if (body.success === false) throw new Error("Cloudflare build lookup failed.");
      return result({
        provider: "cloudflare",
        buildUuid: body.result?.build_uuid ?? buildUuid,
        status: body.result?.status ?? null,
        outcome: body.result?.build_outcome ?? null,
        createdAt: body.result?.created_on ?? null,
        runningAt: body.result?.running_on ?? null,
        stoppedAt: body.result?.stopped_on ?? null,
        previewUrl: body.result?.preview_url ?? null,
      });
    },
  );

  registerTool(
    "supabase_connection_status",
    {
      title: "Supabase Connection",
      description: "Check whether Supabase OAuth is configured and connected for this tenant.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => result({
      provider: "supabase",
      configured: await providerConfigured(env, "supabase"),
      connected: await providerConnectionExists(env, tenant.tenantId, "supabase"),
      tenant: tenant.tenantId,
    }),
  );

  registerTool(
    "supabase_connect",
    {
      title: "Connect Supabase",
      description: "Start a secure Supabase Management API OAuth connection using PKCE. The user must review and approve Supabase's consent screen.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false },
      inputSchema: { confirm: z.boolean().default(false) },
    },
    async ({ confirm }: { confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({ requiresConfirmation: true, action: "connect_supabase" });
      if (!await providerConfigured(env, "supabase")) {
        return result({
          provider: "supabase",
          configured: false,
          message: "Supabase OAuth client credentials and provider encryption must be configured by the app owner first.",
        });
      }
      return result({
        provider: "supabase",
        configured: true,
        connectUrl: await beginProviderOAuth(env, tenant, "supabase"),
        expiresInSeconds: 600,
      });
    },
  );

  registerTool(
    "supabase_list_projects",
    {
      title: "List Supabase Projects",
      description: "List Supabase projects available to the connected tenant through the Management API.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async () => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "supabase");
      const response = await fetch("https://api.supabase.com/v1/projects", {
        headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" },
      });
      if (!response.ok) throw new Error("Supabase project listing failed (" + response.status + ").");
      const projects = await response.json() as Array<{
        id?: string;
        ref?: string;
        name?: string;
        region?: string;
        status?: string;
        organization_id?: string;
      }>;
      return result({
        provider: "supabase",
        projects: projects.map((project) => ({
          id: project.id ?? project.ref ?? null,
          name: project.name ?? null,
          region: project.region ?? null,
          status: project.status ?? null,
          organizationId: project.organization_id ?? null,
        })),
      });
    },
  );

  registerTool(
    "supabase_get_project",
    {
      title: "Get Supabase Project",
      description: "Read current project metadata and lifecycle status from the connected Supabase account.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { projectRef: z.string().regex(/^[a-z0-9]{20}$/) },
    },
    async ({ projectRef }: { projectRef: string }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "supabase");
      const response = await fetch(
        "https://api.supabase.com/v1/projects/" + encodeURIComponent(projectRef),
        { headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" } },
      );
      if (!response.ok) throw new Error("Supabase project lookup failed (" + response.status + ").");
      const project = await response.json() as {
        id?: string;
        ref?: string;
        name?: string;
        region?: string;
        status?: string;
        organization_id?: string;
        database?: unknown;
        created_at?: string;
      };
      return result({
        provider: "supabase",
        project: {
          id: project.id ?? project.ref ?? projectRef,
          name: project.name ?? null,
          region: project.region ?? null,
          status: project.status ?? null,
          organizationId: project.organization_id ?? null,
          createdAt: project.created_at ?? null,
        },
      });
    },
  );

  registerTool(
    "supabase_execute_sql_readonly",
    {
      title: "Run Supabase Read-only SQL",
      description: "Execute a read-only SQL query against a connected Supabase project through the Management API.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: {
        projectRef: z.string().regex(/^[a-z0-9]{20}$/),
        query: z.string().min(1).max(100000),
        parameters: z.array(z.unknown()).max(100).optional(),
      },
    },
    async ({ projectRef, query, parameters }: { projectRef: string; query: string; parameters?: unknown[] }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "supabase");
      const response = await fetch(
        "https://api.supabase.com/v1/projects/" + encodeURIComponent(projectRef) + "/database/query",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + connection.accessToken,
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify({ query, parameters: parameters ?? [], read_only: true }),
        },
      );
      if (!response.ok) throw new Error("Supabase read-only SQL failed (" + response.status + ").");
      return result({ provider: "supabase", projectRef, rows: await response.json() });
    },
  );

  registerTool(
    "supabase_apply_migration",
    {
      title: "Apply Supabase Migration",
      description: "Apply a named SQL migration to a connected Supabase project after explicit confirmation. Do not include credentials or secrets in SQL.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true },
      inputSchema: {
        projectRef: z.string().regex(/^[a-z0-9]{20}$/),
        name: z.string().regex(/^[A-Za-z0-9_.-]{1,128}$/),
        query: z.string().min(1).max(200000),
        confirm: z.boolean().default(false),
      },
    },
    async ({ projectRef, name, query, confirm }: { projectRef: string; name: string; query: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({
        requiresConfirmation: true,
        action: "supabase_apply_migration",
        projectRef,
        name,
        queryLength: query.length,
      });
      const connection = await activeProviderConnection(env, tenant.tenantId, "supabase");
      const response = await fetch(
        "https://api.supabase.com/v1/projects/" + encodeURIComponent(projectRef) + "/database/migrations",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + connection.accessToken,
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify({ name, query }),
        },
      );
      if (!response.ok) throw new Error("Supabase migration failed (" + response.status + ").");
      return result({ provider: "supabase", projectRef, name, applied: true });
    },
  );

  registerTool(
    "supabase_list_migrations",
    {
      title: "List Supabase Migrations",
      description: "List applied migration versions for a connected Supabase project.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false },
      inputSchema: { projectRef: z.string().regex(/^[a-z0-9]{20}$/) },
    },
    async ({ projectRef }: { projectRef: string }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "supabase");
      const response = await fetch(
        "https://api.supabase.com/v1/projects/" + encodeURIComponent(projectRef) + "/database/migrations",
        { headers: { authorization: "Bearer " + connection.accessToken, accept: "application/json" } },
      );
      if (!response.ok) throw new Error("Supabase migration listing failed (" + response.status + ").");
      return result({ provider: "supabase", projectRef, migrations: await response.json() });
    },
  );

  registerTool(
    "provider_disconnect",
    {
      title: "Disconnect Provider",
      description: "Delete this tenant's locally stored encrypted Cloudflare or Supabase provider connection after explicit confirmation.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true },
      inputSchema: {
        provider: z.enum(["cloudflare", "supabase"]),
        confirm: z.boolean().default(false),
      },
    },
    async ({ provider, confirm }: { provider: ProviderName; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm) return result({ requiresConfirmation: true, action: "disconnect_provider", provider });
      await deleteProviderConnection(env, tenant.tenantId, provider);
      return result({ provider, connected: false, deleted: true });
    },
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

  registerTool("browser_click", {
    title: "Click Browser Element",
    description: "Click an element in the authenticated tenant browser after explicit confirmation.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: {
      selector: z.string().min(1).max(1000),
      targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional(),
      confirm: z.boolean().default(false),
    },
  }, async ({ selector, targetId, confirm }: { selector: string; targetId?: string; confirm: boolean }) => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!confirm) return result({ requiresConfirmation: true, action: "browser_click", selector, targetId: targetId ?? null });
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      await page.click(selector);
      await new Promise((resolve) => setTimeout(resolve, 300));
      return result({
        tenant: tenant.tenantId,
        targetId: resolvedTargetId,
        clicked: true,
        url: page.url(),
        title: await page.title(),
      });
    } finally {
      browser.disconnect();
    }
  });

  registerTool("browser_type", {
    title: "Type Into Browser",
    description: "Type non-secret text into a browser field after explicit confirmation. Password, one-time-code, and payment-card fields are blocked; use Interactive Browser Control for those.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: {
      selector: z.string().min(1).max(1000),
      text: z.string().max(10000),
      clearFirst: z.boolean().default(false),
      targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional(),
      confirm: z.boolean().default(false),
    },
  }, async ({ selector, text, clearFirst, targetId, confirm }: { selector: string; text: string; clearFirst: boolean; targetId?: string; confirm: boolean }) => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!confirm) return result({ requiresConfirmation: true, action: "browser_type", selector, targetId: targetId ?? null, characters: text.length });
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      const field = await page.$eval(selector, (el: any) => ({
        tag: String(el.tagName ?? "").toLowerCase(),
        type: String(el.type ?? "").toLowerCase(),
        autocomplete: String(el.autocomplete ?? "").toLowerCase(),
        name: String(el.name ?? "").toLowerCase(),
      }));
      const sensitive = field.type === "password" ||
        /(password|passwd|secret|token|otp|one-time|cc-|card|cvv|cvc)/.test(field.autocomplete + " " + field.name);
      if (sensitive) throw new Error("Sensitive credential/payment fields must be completed through Interactive Browser Control.");
      if (clearFirst) {
        await page.$eval(selector, (el: any) => {
          if ("value" in el) {
            el.focus();
            el.value = "";
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
          }
        });
      }
      await page.type(selector, text);
      return result({
        tenant: tenant.tenantId,
        targetId: resolvedTargetId,
        typed: true,
        characters: text.length,
        url: page.url(),
      });
    } finally {
      browser.disconnect();
    }
  });

  registerTool("browser_select", {
    title: "Select Browser Option",
    description: "Select one or more values in a browser dropdown after explicit confirmation.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: {
      selector: z.string().min(1).max(1000),
      values: z.array(z.string().max(1000)).min(1).max(20),
      targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional(),
      confirm: z.boolean().default(false),
    },
  }, async ({ selector, values, targetId, confirm }: { selector: string; values: string[]; targetId?: string; confirm: boolean }) => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!confirm) return result({ requiresConfirmation: true, action: "browser_select", selector, values, targetId: targetId ?? null });
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      const selected = await page.select(selector, ...values);
      return result({
        tenant: tenant.tenantId,
        targetId: resolvedTargetId,
        selected,
        url: page.url(),
      });
    } finally {
      browser.disconnect();
    }
  });

  registerTool("browser_press", {
    title: "Press Browser Key",
    description: "Press a restricted navigation/form key in the tenant browser after explicit confirmation.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: {
      key: z.enum(["Enter", "Escape", "Tab", "Backspace", "Delete", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"]),
      targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional(),
      confirm: z.boolean().default(false),
    },
  }, async ({ key, targetId, confirm }: { key: "Enter" | "Escape" | "Tab" | "Backspace" | "Delete" | "ArrowUp" | "ArrowDown" | "ArrowLeft" | "ArrowRight"; targetId?: string; confirm: boolean }) => {
    if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
    if (!confirm) return result({ requiresConfirmation: true, action: "browser_press", key, targetId: targetId ?? null });
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      await page.keyboard.press(key);
      await new Promise((resolve) => setTimeout(resolve, 200));
      return result({
        tenant: tenant.tenantId,
        targetId: resolvedTargetId,
        pressed: key,
        url: page.url(),
        title: await page.title(),
      });
    } finally {
      browser.disconnect();
    }
  });

  registerTool("browser_wait", {
    title: "Wait For Browser",
    description: "Wait briefly for a selector or page activity in the current tenant browser.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: {
      selector: z.string().min(1).max(1000).optional(),
      timeoutMs: z.number().int().min(100).max(10000).default(3000),
      targetId: z.string().regex(/^[A-Za-z0-9]+$/).optional(),
    },
  }, async ({ selector, timeoutMs, targetId }: { selector?: string; timeoutMs: number; targetId?: string }) => {
    const { browser, page, targetId: resolvedTargetId } = await connectTenantPage(env, tenant, targetId);
    try {
      if (selector) await page.waitForSelector(selector, { timeout: timeoutMs });
      else await new Promise((resolve) => setTimeout(resolve, timeoutMs));
      return result({
        tenant: tenant.tenantId,
        targetId: resolvedTargetId,
        ready: true,
        url: page.url(),
        title: await page.title(),
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
        githubToken: ctx.props.githubToken,
      };
      const limited = await enforceTenantRateLimit(env, tenant.tenantId);
      if (limited) return limited;
      const mcp = createMcpHandler(() => createServer(tenant, env), { route: "/mcp" });
      return mcp(request, env, ctx);
    },
  },
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      const [cloudflareConfigured, supabaseConfigured] = await Promise.all([
        providerConfigured(env, "cloudflare"),
        providerConfigured(env, "supabase"),
      ]);
      return Response.json({
        ok: true,
        service: "ravi-developer-agent",
        version: "0.5.0",
        authentication: "oauth-2.1",
        providerOAuth: {
          storage: "tenant-durable-object-aes-256-at-rest",
          cloudflareConfigured,
          supabaseConfigured,
        },
      }, { headers: { "cache-control": "no-store" } });
    }

    if (url.pathname === "/") {
      return Response.json({
        name: "Ravi Developer Agent",
        version: "0.5.0",
        mcp: "/mcp",
        health: "/health",
        authentication: "OAuth 2.1 required for MCP",
      });
    }

    if (url.pathname === "/oauth/cloudflare/callback") {
      return providerOAuthCallback(request, env, "cloudflare");
    }

    if (url.pathname === "/oauth/supabase/callback") {
      return providerOAuthCallback(request, env, "supabase");
    }

    if (url.pathname === "/mcp" || url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return oauthMcp.fetch(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
