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

type Env = {
  BROWSER?: Fetcher;
  BROWSER_SESSIONS: DurableObjectNamespace<TenantBrowserSession>;
  PROVIDER_CONNECTIONS: DurableObjectNamespace<TenantConnections>;
  OAUTH_CONNECT_STATE: DurableObjectNamespace<OAuthConnectState>;
  AUTH_SERVER: AuthorizationServerBinding<AuthProps>;
  CONNECTION_ENCRYPTION_KEY?: string;
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
type EncryptedConnection = { iv: string; ciphertext: string; updatedAt: number };

export class TenantConnections extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const provider = url.pathname.split("/").filter(Boolean)[1] as ProviderName | undefined;
    if (!provider || !["cloudflare", "supabase"].includes(provider)) {
      return new Response("invalid_provider", { status: 400 });
    }
    const key = "provider:" + provider;
    if (request.method === "PUT") {
      const body = await request.json() as EncryptedConnection;
      if (!body.iv || !body.ciphertext || !body.updatedAt) return new Response("invalid_connection", { status: 400 });
      await this.ctx.storage.put(key, body);
      return Response.json({ ok: true });
    }
    if (request.method === "GET") {
      const value = await this.ctx.storage.get<EncryptedConnection>(key);
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

function connectionKeyBytes(env: Env): Uint8Array {
  const value = env.CONNECTION_ENCRYPTION_KEY?.trim();
  if (!value) throw new Error("Provider connection encryption is not configured.");
  let bytes: Uint8Array;
  if (/^[0-9a-f]{64}$/i.test(value)) {
    bytes = Uint8Array.from(value.match(/.{2}/g)!.map((pair) => parseInt(pair, 16)));
  } else {
    try {
      const binary = atob(value);
      bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    } catch {
      throw new Error("Provider connection encryption key is invalid.");
    }
  }
  if (bytes.length !== 32) throw new Error("Provider connection encryption key must be 32 bytes.");
  return bytes;
}

async function connectionCryptoKey(env: Env): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", connectionKeyBytes(env), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function encryptConnection(env: Env, tenantId: string, provider: ProviderName, value: ProviderConnection): Promise<EncryptedConnection> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(tenantId + ":" + provider);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    await connectionCryptoKey(env),
    plaintext,
  );
  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    updatedAt: Date.now(),
  };
}

async function decryptConnection(env: Env, tenantId: string, provider: ProviderName, value: EncryptedConnection): Promise<ProviderConnection> {
  const aad = new TextEncoder().encode(tenantId + ":" + provider);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(value.iv), additionalData: aad },
    await connectionCryptoKey(env),
    base64ToBytes(value.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as ProviderConnection;
}

function providerStore(env: Env, tenantId: string) {
  return env.PROVIDER_CONNECTIONS.get(env.PROVIDER_CONNECTIONS.idFromName(tenantId));
}

async function saveProviderConnection(env: Env, tenantId: string, provider: ProviderName, connection: ProviderConnection): Promise<void> {
  const encrypted = await encryptConnection(env, tenantId, provider, connection);
  const response = await providerStore(env, tenantId).fetch("https://provider-connections/provider/" + provider, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(encrypted),
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
  return decryptConnection(env, tenantId, provider, await response.json() as EncryptedConnection);
}

async function deleteProviderConnection(env: Env, tenantId: string, provider: ProviderName): Promise<void> {
  await providerStore(env, tenantId).fetch("https://provider-connections/provider/" + provider, { method: "DELETE" });
}

function providerClient(env: Env, provider: ProviderName): { clientId: string; clientSecret: string; callback: string } {
  if (provider === "cloudflare") {
    if (!env.CLOUDFLARE_OAUTH_CLIENT_ID || !env.CLOUDFLARE_OAUTH_CLIENT_SECRET) throw new Error("Cloudflare OAuth application is not configured.");
    return { clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID, clientSecret: env.CLOUDFLARE_OAUTH_CLIENT_SECRET, callback: CLOUDFLARE_CALLBACK };
  }
  if (!env.SUPABASE_OAUTH_CLIENT_ID || !env.SUPABASE_OAUTH_CLIENT_SECRET) throw new Error("Supabase OAuth application is not configured.");
  return { clientId: env.SUPABASE_OAUTH_CLIENT_ID, clientSecret: env.SUPABASE_OAUTH_CLIENT_SECRET, callback: SUPABASE_CALLBACK };
}

function providerConfigured(env: Env, provider: ProviderName): boolean {
  try {
    connectionKeyBytes(env);
    providerClient(env, provider);
    return true;
  } catch {
    return false;
  }
}

async function beginProviderOAuth(env: Env, tenant: TenantContext, provider: ProviderName): Promise<string> {
  const client = providerClient(env, provider);
  connectionKeyBytes(env);
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
    url.searchParams.set("scope", "offline_access workers-platform.read workers-platform.write");
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
  const client = providerClient(env, provider);
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
  const client = providerClient(env, provider);
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
      providers: ["github"],
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
