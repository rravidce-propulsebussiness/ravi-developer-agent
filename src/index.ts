import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { DurableObject } from "cloudflare:workers";
import { OAuthResourceServer, insufficientScope, type AuthorizationServerBinding } from "@cloudflare/workers-oauth-provider";
import { registerAppResource, registerAppTool, RESOURCE_MIME_TYPE } from "@modelcontextprotocol/ext-apps/server";
import puppeteer from "@cloudflare/puppeteer";
import { hostnameAllowed, validDomainPattern } from "./security";

type AuthProps = {
  userId: string;
  tenantId: string;
  subject: string;
  loginProvider: "github";
  login: string;
  githubToken: string;
};

type AuthServerService = AuthorizationServerBinding<AuthProps> & {
  getGithubToken(userId: string, fallback?: string): Promise<string | null>;
  getProviderClient(provider: "cloudflare" | "supabase"): Promise<{ clientId: string; clientSecret: string } | null>;
  deleteUserData(userId: string): Promise<{ revokedGrants: number; githubTokenDeleted: boolean }>;
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
  OPENAI_APPS_CHALLENGE?: string;
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
    if (request.method === "DELETE" && url.pathname === "/all") {
      await this.ctx.storage.deleteAll();
      return Response.json({ ok: true });
    }
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

    if (request.method === "DELETE" && url.pathname === "/all") {
      await this.ctx.storage.deleteAll();
      return Response.json({ ok: true });
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

function isSensitiveRepositoryPath(path: string): boolean {
  const normalized = path.toLowerCase().replace(/\\/g, "/");
  const base = normalized.split("/").pop() ?? "";
  if (base === ".env.example" || base === ".env.sample" || base.endsWith(".example")) return false;
  if (base === ".env" || base.startsWith(".env.") || base === ".npmrc" || base === ".pypirc") return true;
  if (/^(id_rsa|id_ed25519|credentials|secrets?)(\.|$)/.test(base)) return true;
  if (normalized.includes("/.ssh/") || normalized.includes("/.aws/") || normalized.includes("/.gnupg/")) return true;
  return false;
}

function containsLikelyCredential(value: string): boolean {
  const checks = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bsk-[A-Za-z0-9_-]{20,}\b/,
    /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password)\s*[:=]\s*["'][^"'\n]{8,}["']/i,
  ];
  return checks.some((pattern) => pattern.test(value));
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
    url.searchParams.set("scope", "offline_access account-settings.read workers-scripts.read workers-scripts.write workers-ci.read workers-ci.write");
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
  const server = new McpServer({ name: "ravi-developer-agent", version: "1.0.0" });
  // OpenAI/MCP Apps supports securitySchemes on tool descriptors, but the
  // ext-apps 2.0.3 TypeScript surface has not caught up with that field yet.
  // Keep runtime metadata standards-compliant while containing the cast here.
  const openWorldTools = new Set([
    "github_create_branch",
    "github_put_file",
    "github_create_pull_request",
    "cloudflare_trigger_build",
    "browser_open",
    "browser_session_start",
    "browser_tabs",
    "browser_tab_open",
    "browser_tab_activate",
    "browser_tab_close",
    "browser_session_close",
    "browser_screenshot",
    "browser_page_text",
    "browser_click",
    "browser_type",
    "browser_select",
    "browser_press",
    "browser_wait",
    "browser_live_view",
  ]);
  const registerTool = (name: string, config: any, handler: any) => {
    const normalizedConfig = {
      ...config,
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }),
      },
    };
    const wrapped = async (...args: any[]) => {
      const output = await handler(...args);
      const requiresConfirmation = Boolean((output as any)?.structuredContent?.requiresConfirmation);
      if (normalizedConfig.annotations.readOnlyHint === false && !requiresConfirmation && !normalizedConfig?._meta?.raviSkipAudit) {
        await auditTenantAction(env, tenant, name);
      }
      return output;
    };
    return (registerAppTool as any)(server, name, normalizedConfig, wrapped);
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
      version: "1.0.0",
      transport: "MCP Streamable HTTP",
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
    }),
  );

  registerTool(
    "delete_my_data",
    {
      title: "Delete My Ravi Developer Agent Data",
      description: "Permanently delete this authenticated user's Ravi Developer Agent provider connections, browser-session state, audit/rate data, stored GitHub user-token state, and Ravi Developer Agent OAuth grants. This does not delete resources or content held independently by GitHub, Cloudflare, Supabase, or visited websites.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
      inputSchema: {
        confirm: z.boolean().default(false),
        confirmationText: z.string().max(64).default(""),
      },
      _meta: { raviSkipAudit: true },
    },
    async ({ confirm, confirmationText }: { confirm: boolean; confirmationText: string }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (!confirm || confirmationText !== "DELETE MY DATA") {
        return result({
          requiresConfirmation: true,
          destructive: true,
          action: "delete_my_data",
          requiredConfirmationText: "DELETE MY DATA",
          deletes: [
            "Ravi Developer Agent's stored Cloudflare and Supabase connections",
            "tenant browser-session ownership and the active cloud browser session",
            "tenant audit and rate-limit records",
            "stored GitHub App user-token state",
            "Ravi Developer Agent OAuth grants",
          ],
          doesNotDelete: [
            "GitHub repositories or account data",
            "Cloudflare resources",
            "Supabase projects or databases",
            "data held by websites visited in the browser",
          ],
        });
      }

      let browserClosed = false;
      const browserOwner = env.BROWSER_SESSIONS.get(env.BROWSER_SESSIONS.idFromName(tenant.tenantId));
      try {
        const sessionResponse = await browserOwner.fetch("https://browser-session/session");
        if (sessionResponse.ok && env.BROWSER) {
          const session = await sessionResponse.json() as { sessionId?: string };
          if (session.sessionId) {
            const close = await env.BROWSER.fetch(
              "https://browser-rendering/devtools/browser/" + encodeURIComponent(session.sessionId),
              { method: "DELETE" },
            );
            browserClosed = close.ok || close.status === 404;
          }
        }
      } catch {
        browserClosed = false;
      }
      await browserOwner.fetch("https://browser-session/session", { method: "DELETE" });

      const connections = env.PROVIDER_CONNECTIONS.get(env.PROVIDER_CONNECTIONS.idFromName(tenant.tenantId));
      await connections.fetch("https://provider-connections/all", { method: "DELETE" });

      const guard = env.TENANT_GUARD.get(env.TENANT_GUARD.idFromName(tenant.tenantId));
      await guard.fetch("https://tenant-guard/all", { method: "DELETE" });

      const authDeletion = await env.AUTH_SERVER.deleteUserData(tenant.subject);
      return result({
        deleted: true,
        browserClosed,
        providerConnectionsDeleted: true,
        tenantAuditAndRateDataDeleted: true,
        githubTokenDeleted: authDeletion.githubTokenDeleted,
        oauthGrantsRevoked: authDeletion.revokedGrants,
      });
    },
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
    }),
  );

  registerTool(
    "github_list_repositories",
    {
      title: "List GitHub Repositories",
      description: "List repositories visible to the authenticated GitHub account.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: {
        owner: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        repo: z.string().regex(/^[A-Za-z0-9_.-]+$/),
        path: z.string().min(1).max(1024),
        ref: z.string().min(1).max(255).optional(),
      },
    },
    async ({ owner, repo, path, ref }: { owner: string; repo: string; path: string; ref?: string }) => {
      if (isSensitiveRepositoryPath(path)) throw new Error("Reading credential/config secret files is not supported.");
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
      const decoded = decodeUtf8Base64(file.content);
      if (containsLikelyCredential(decoded)) throw new Error("The requested file appears to contain authentication secrets and cannot be returned through this plugin.");
      return result({
        repository: owner + "/" + repo,
        path: file.path ?? path,
        sha: file.sha ?? null,
        size: file.size ?? null,
        content: decoded,
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
      if (isSensitiveRepositoryPath(path)) throw new Error("Writing credential/config secret files is not supported.");
      if (path.toLowerCase().replace(/\\/g, "/").startsWith(".github/workflows/")) throw new Error("Editing GitHub Actions workflow files is not enabled for this plugin.");
      if (containsLikelyCredential(content)) throw new Error("The proposed file content appears to contain authentication secrets. Store secrets directly with the provider and reference them by environment variable instead.");
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
    }),
  );

  registerTool(
    "cloudflare_connect",
    {
      title: "Connect Cloudflare",
      description: "Start a secure Cloudflare OAuth connection using PKCE. The user must review and approve Cloudflare's consent screen.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
    }),
  );

  registerTool(
    "supabase_connect",
    {
      title: "Connect Supabase",
      description: "Start a secure Supabase Management API OAuth connection using PKCE. The user must review and approve Supabase's consent screen.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
    "supabase_schema_inspect",
    {
      title: "Inspect Supabase Schema",
      description: "Read table and column metadata for one schema in a connected Supabase project. This tool does not return application table rows.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: {
        projectRef: z.string().regex(/^[a-z0-9]{20}$/),
        schema: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,62}$/).default("public"),
      },
    },
    async ({ projectRef, schema }: { projectRef: string; schema: string }) => {
      const connection = await activeProviderConnection(env, tenant.tenantId, "supabase");
      const query =
        "select table_schema, table_name, column_name, data_type, is_nullable, ordinal_position " +
        "from information_schema.columns where table_schema = '" + schema + "' " +
        "order by table_name, ordinal_position";
      const response = await fetch(
        "https://api.supabase.com/v1/projects/" + encodeURIComponent(projectRef) + "/database/query",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + connection.accessToken,
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify({ query, read_only: true }),
        },
      );
      if (!response.ok) throw new Error("Supabase schema inspection failed (" + response.status + ").");
      return result({ provider: "supabase", projectRef, schema, columns: await response.json() });
    },
  );

  registerTool(
    "supabase_apply_migration",
    {
      title: "Apply Supabase Migration",
      description: "Apply a named SQL migration to a connected Supabase project after explicit confirmation. Do not include credentials or secrets in SQL.",
      securitySchemes: [{ type: "oauth2", scopes: ["agent:read", "agent:write"] }],
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
      inputSchema: {
        projectRef: z.string().regex(/^[a-z0-9]{20}$/),
        name: z.string().regex(/^[A-Za-z0-9_.-]{1,128}$/),
        query: z.string().min(1).max(200000),
        confirm: z.boolean().default(false),
      },
    },
    async ({ projectRef, name, query, confirm }: { projectRef: string; name: string; query: string; confirm: boolean }) => {
      if (!tenant.scopes.includes("agent:write")) return toolAuthRequired(["agent:read", "agent:write"]);
      if (containsLikelyCredential(query)) throw new Error("Migration SQL appears to contain authentication secrets. Store secrets with the provider instead of embedding them in SQL.");
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
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
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
      return result({ tab });
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
      return result({ browserReady: true });
    },
  );
  registerTool("browser_tabs", {
    title: "List Browser Tabs",
    description: "List the current pages in the tenant browser session without exposing debugger or Live View credentials.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: {},
  }, async () => {
    if (!env.BROWSER) throw new Error("Cloud browser binding is unavailable.");
    const sessionId = await tenantSessionId(env, tenant);
    const response = await env.BROWSER.fetch(`https://browser-rendering/devtools/browser/${encodeURIComponent(sessionId)}/json/list`);
    if (!response.ok) throw new Error(`Browser tab listing failed (${response.status}).`);
    const rawTabs = await response.json() as unknown[];
    return result({ tabs: rawTabs.map(safeTab) });
  });
  registerTool("browser_tab_open", {
    title: "Open Browser Tab",
    description: "Open a permitted web URL in a new tab of the tenant's guarded browser session.",
    securitySchemes: [{ type: "oauth2", scopes: ["agent:read"] }],
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { url: z.string().url() },
  }, async ({ url }: { url: string }) => {
    const tab = await openTenantTab(env, tenant, url);
    return result({ tab });
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
    return result({ targetId, active: true });
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
    return result({ targetId, closed: true });
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
    return result({ closed: true });
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
        structuredContent: { targetId: resolvedTargetId, url: page.url() },
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
      if (sensitive) throw new Error("Sensitive credential, one-time-code, API-key, token, and payment fields are not supported by this plugin. Use an OAuth/provider connection or the service directly.");
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
      _meta: { ui: { prefersBorder: false, domain: "https://ravi-developer-agent.rvrmvth.workers.dev", csp: { frameDomains: ["https://live.browser.run"] } }, "openai/ui": { availableDisplayModes: ["inline", "fullscreen"] } },
    }],
  }));

  registerTool("browser_live_view", {
    title: "Browser Live View",
    description: "Create a short-lived read-only live view for an existing browser session. Do not use browser sessions for passwords, API keys, MFA/OTP codes, payment data, or other credentials.",
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
      structuredContent: { browserReady: true },
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
      const githubToken = await env.AUTH_SERVER.getGithubToken(ctx.props.userId, ctx.props.githubToken);
      const tenant: TenantContext = {
        tenantId: ctx.props.tenantId,
        subject: ctx.props.subject,
        login: ctx.props.login,
        scopes: ctx.auth.scope,
        githubToken: githubToken ?? ctx.props.githubToken,
      };
      const limited = await enforceTenantRateLimit(env, tenant.tenantId);
      if (limited) return limited;
      const mcp = createMcpHandler(() => createServer(tenant, env), { route: "/mcp" });
      return mcp(request, env, ctx);
    },
  },
});

function publicPage(title: string, body: string): Response {
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{font-family:system-ui;line-height:1.55;background:#0f1115;color:#f5f7fb;max-width:860px;margin:48px auto;padding:0 22px}main{background:#171a21;border:1px solid #2a3040;border-radius:18px;padding:30px}a{color:#9ec7ff}h1,h2{line-height:1.2}.muted{color:#aeb7c8}</style></head><body><main><h1>${title}</h1>${body}<p class="muted">Ravi Developer Agent</p></main></body></html>`;
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=300",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
    },
  });
}

const PRIVACY_HTML = `
<p>Ravi Developer Agent helps users work with software projects through user-authorized GitHub, Cloudflare, Supabase, and cloud-browser connections.</p>
<h2>Data we process</h2><p>We process the account identity, repository or project information, tool inputs, and provider authorization tokens required to perform requested actions. Provider tokens remain server-side and are not intentionally returned in MCP tool output. Browser sessions are isolated per tenant.</p>
<h2>Storage and retention</h2><p>Provider connection data is kept in tenant-specific Cloudflare storage. Action audit records contain action names and timestamps, not secret values or tool payloads, and are retained for up to 30 days. Short-lived OAuth and secure-entry state expires automatically.</p>
<h2>Sharing</h2><p>Data is sent only to services the user connects or websites the user asks the browser to access, as needed to perform requested actions. We do not sell user data.</p>
<h2>Controls</h2><p>Users can disconnect supported providers, close browser sessions, revoke provider authorization at the provider, or use the authenticated <strong>Delete My Ravi Developer Agent Data</strong> action to erase Ravi Developer Agent's tenant-stored provider connections, browser-session state, audit/rate records, GitHub user-token state, and OAuth grants. Ravi Developer Agent does not ask users to enter passwords, API keys, MFA/OTP codes, payment-card data, or other authentication secrets into its tools or browser controls.</p>
<h2>Contact</h2><p>For privacy questions, use the project support page. Authenticated users can perform self-service deletion with the Delete My Ravi Developer Agent Data action.</p>`;

const TERMS_HTML = `
<p>By using Ravi Developer Agent, you authorize it to perform only the actions you request through accounts you are permitted to use.</p>
<h2>Account responsibility</h2><p>You are responsible for maintaining appropriate permissions on connected GitHub, Cloudflare, Supabase, and website accounts and for reviewing consequential actions before confirmation.</p>
<h2>Safe use</h2><p>Do not use the service to access systems without authorization, expose credentials, evade provider safeguards, or perform unlawful activity. Authentication should use provider OAuth or provider-controlled sign-in flows. Ravi Developer Agent tools must not collect passwords, API keys, OTP/MFA codes, payment-card data, or other authentication secrets.</p>
<h2>Availability</h2><p>The service is provided on a best-effort basis and depends on third-party APIs and browser services. Provider limits, outages, or policy changes can affect availability.</p>
<h2>Changes</h2><p>These terms may be updated as the service and supported providers change. Continued use after an update constitutes acceptance of the revised terms.</p>`;

const SUPPORT_HTML = `
<p>For setup help, bug reports, or security concerns, use the Ravi Developer Agent GitHub repository.</p>
<p><a href="https://github.com/rravidce-propulsebussiness/ravi-developer-agent/issues">Open GitHub Issues</a></p>
<p>When reporting a problem, never include passwords, OAuth tokens, API keys, database passwords, or Worker secret values.</p>`;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/privacy") return publicPage("Privacy Policy", PRIVACY_HTML);
    if (url.pathname === "/terms") return publicPage("Terms of Service", TERMS_HTML);
    if (url.pathname === "/support") return publicPage("Support", SUPPORT_HTML);
    if (url.pathname === "/.well-known/openai-apps-challenge") {
      const challenge = env.OPENAI_APPS_CHALLENGE?.trim();
      return challenge
        ? new Response(challenge, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } })
        : new Response("Not found", { status: 404 });
    }

    if (url.pathname === "/health") {
      const [cloudflareConfigured, supabaseConfigured] = await Promise.all([
        providerConfigured(env, "cloudflare"),
        providerConfigured(env, "supabase"),
      ]);
      return Response.json({
        ok: true,
        service: "ravi-developer-agent",
        version: "1.0.0",
        authentication: "oauth-2.1",
        providerOAuth: {
          storage: "tenant-durable-object-aes-256-at-rest",
          cloudflareConfigured,
          supabaseConfigured,
        },
      }, { headers: { "cache-control": "no-store" } });
    }

    if (url.pathname === "/" || url.pathname === "/about") {
      return publicPage("Ravi Developer Agent", `
<p>Ravi Developer Agent is a tenant-isolated developer plugin for GitHub, Cloudflare, Supabase, and guarded cloud-browser verification.</p>
<h2>What it does</h2>
<p>Inspect repositories, prepare and apply approved code changes, inspect Cloudflare deployments, inspect Supabase schema metadata and apply confirmed migrations, and verify public web applications in an isolated browser.</p>
<h2>Security boundaries</h2>
<p>Account access uses OAuth. State-changing tools require write authorization where applicable and consequential actions use confirmation gates. The public plugin does not ask users to enter passwords, API keys, MFA/OTP codes, payment-card data, or other authentication secrets.</p>
<h2>Links</h2>
<p><a href="/privacy">Privacy Policy</a> · <a href="/terms">Terms of Service</a> · <a href="/support">Support</a></p>
<p><a href="https://github.com/rravidce-propulsebussiness/ravi-developer-agent">Source repository</a></p>
`);
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
