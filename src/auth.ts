import {
  AuthorizationError,
  OAuthAuthorizationServer,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";
import { WorkerEntrypoint } from "cloudflare:workers";

const AUTH_ISSUER = "https://ravi-developer-agent-auth.rvrmvth.workers.dev";
const MCP_RESOURCE = "https://ravi-developer-agent.rvrmvth.workers.dev/mcp";
const GITHUB_CALLBACK = AUTH_ISSUER + "/callback";
const GITHUB_MANIFEST_CALLBACK = AUTH_ISSUER + "/setup/github-app/callback";
const PROVIDER_SETUP_CALLBACK = AUTH_ISSUER + "/setup/providers/callback";
const GITHUB_APP_OWNER = "rravidce-propulsebussiness";
const APP_HOME = "https://ravi-developer-agent.rvrmvth.workers.dev";

type AuthEnv = {
  OAUTH_KV: KVNamespace;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
};

type AuthProps = {
  userId: string;
  tenantId: string;
  subject: string;
  loginProvider: "github";
  login: string;
  githubToken: string;
  email: string;
  emailVerified: true;
};

const authorizationServer = new OAuthAuthorizationServer<AuthEnv>({
  issuer: AUTH_ISSUER,
  resources: [MCP_RESOURCE],
  scopesSupported: ["openid", "email", "agent:read", "agent:write", "offline_access"],
  clientIdMetadataDocumentEnabled: true,
  clientRegistrationEndpoint: "/oauth/register",
});

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

function consentPage(details: {
  clientName: string;
  clientDomain?: string | null;
  redirectHost: string;
  redirectIsLoopback: boolean;
  scope: string[];
}, handle: string): string {
  const scopes = details.scope
    .map((scope) => `<label><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> ${escapeHtml(scope)}</label>`)
    .join("<br>");
  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Ravi Developer Agent</title>
<style>body{font-family:system-ui;max-width:680px;margin:48px auto;padding:0 20px;background:#0f1115;color:#f5f7fb}main{background:#171a21;border:1px solid #2a3040;border-radius:18px;padding:28px}h1{margin-top:0}label{display:block;padding:7px 0}.muted{color:#aeb7c8}.warn{background:#30261d;padding:12px;border-radius:10px}button{padding:10px 16px;border-radius:10px;border:0;margin-right:8px;font-weight:650}.allow{background:#fff;color:#111}.deny{background:#2a3040;color:#fff}</style>
</head><body><main>
<h1>Connect ${escapeHtml(details.clientName)}</h1>
<p class="muted">${details.clientDomain ? `Published by <strong>${escapeHtml(details.clientDomain)}</strong>.` : "This client name is self-asserted."} Access will return to <strong>${escapeHtml(details.redirectHost)}</strong>.</p>
${details.redirectIsLoopback ? '<p class="warn"><strong>Local callback:</strong> continue only if you started this sign-in on your device.</p>' : ""}
<form method="post">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<p>${scopes}</p>
<button class="allow" name="decision" value="approve">Continue with GitHub</button>
<button class="deny" name="decision" value="deny">Deny</button>
</form></main></body></html>`;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function s256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

function randomVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

type GithubClient = { clientId: string; clientSecret: string };

async function githubClient(env: AuthEnv): Promise<GithubClient | null> {
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) {
    return { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
  }
  const [clientId, clientSecret] = await Promise.all([
    env.OAUTH_KV.get("github:client_id"),
    env.OAUTH_KV.get("github:client_secret"),
  ]);
  return clientId && clientSecret ? { clientId, clientSecret } : null;
}

async function githubConfigured(env: AuthEnv): Promise<boolean> {
  return Boolean(await githubClient(env));
}

type GithubUserTokenRecord = {
  accessToken: string;
  expiresAt?: number;
  refreshToken?: string;
  refreshExpiresAt?: number;
  updatedAt: number;
};

function githubUserTokenKey(userId: string): string {
  return "github:user-token:" + userId;
}

async function saveGithubUserToken(env: AuthEnv, userId: string, token: {
  access_token: string;
  expires_in?: number;
  refresh_token?: string;
  refresh_token_expires_in?: number;
}): Promise<GithubUserTokenRecord> {
  const now = Date.now();
  const record: GithubUserTokenRecord = {
    accessToken: token.access_token,
    expiresAt: token.expires_in ? now + token.expires_in * 1000 : undefined,
    refreshToken: token.refresh_token,
    refreshExpiresAt: token.refresh_token_expires_in ? now + token.refresh_token_expires_in * 1000 : undefined,
    updatedAt: now,
  };
  await env.OAUTH_KV.put(githubUserTokenKey(userId), JSON.stringify(record));
  return record;
}

async function activeGithubUserToken(env: AuthEnv, userId: string, fallback?: string): Promise<string | null> {
  const raw = await env.OAUTH_KV.get(githubUserTokenKey(userId));
  if (!raw) return fallback ?? null;
  let record: GithubUserTokenRecord;
  try {
    record = JSON.parse(raw) as GithubUserTokenRecord;
  } catch {
    return fallback ?? null;
  }
  if (!record.accessToken) return fallback ?? null;
  if (!record.expiresAt || record.expiresAt > Date.now() + 5 * 60 * 1000) return record.accessToken;
  if (!record.refreshToken || (record.refreshExpiresAt && record.refreshExpiresAt <= Date.now() + 60_000)) {
    return fallback ?? record.accessToken;
  }

  const client = await githubClient(env);
  if (!client) return fallback ?? record.accessToken;
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: client.clientId,
      client_secret: client.clientSecret,
      grant_type: "refresh_token",
      refresh_token: record.refreshToken,
    }),
  });
  if (!response.ok) return fallback ?? record.accessToken;
  const refreshed = await response.json() as {
    access_token?: string;
    expires_in?: number;
    refresh_token?: string;
    refresh_token_expires_in?: number;
  };
  if (!refreshed.access_token) return fallback ?? record.accessToken;
  const saved = await saveGithubUserToken(env, userId, {
    access_token: refreshed.access_token,
    expires_in: refreshed.expires_in,
    refresh_token: refreshed.refresh_token ?? record.refreshToken,
    refresh_token_expires_in: refreshed.refresh_token_expires_in,
  });
  return saved.accessToken;
}

async function githubManifestPage(env: AuthEnv): Promise<Response> {
  if (await githubConfigured(env)) {
    return new Response(`<!doctype html><meta charset="utf-8"><title>GitHub App ready</title><style>body{font-family:system-ui;background:#0f1115;color:#f5f7fb;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:620px;padding:28px;border:1px solid #2a3040;border-radius:18px;background:#171a21}</style><div class="card"><h1>GitHub App already configured</h1><p>Ravi Developer Agent can now use GitHub as its sign-in and repository provider.</p></div>`, {
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    });
  }

  const state = randomVerifier();
  await env.OAUTH_KV.put("github:manifest_state:" + state, "1", { expirationTtl: 3600 });
  const manifest = {
    name: "Ravi Developer Agent",
    url: APP_HOME,
    redirect_url: GITHUB_MANIFEST_CALLBACK,
    callback_urls: [GITHUB_CALLBACK, PROVIDER_SETUP_CALLBACK],
    description: "Tenant-isolated developer agent for GitHub, cloud deployment, and browser testing.",
    public: true,
    request_oauth_on_install: true,
    default_events: [],
    default_permissions: {
      metadata: "read",
      contents: "write",
      pull_requests: "write",
      workflows: "write",
      email_addresses: "read",
    },
  };
  const safeManifest = escapeHtml(JSON.stringify(manifest));
  const safeState = encodeURIComponent(state);
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Create Ravi Developer Agent GitHub App</title><style>body{font-family:system-ui;background:#0f1115;color:#f5f7fb;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:640px;padding:28px;border:1px solid #2a3040;border-radius:18px;background:#171a21}button{padding:11px 18px;border:0;border-radius:10px;font-weight:700}</style><div class="card"><h1>Create the GitHub App</h1><p>GitHub will show the requested repository permissions before creation. The app is public so other users can install it later.</p><form action="https://github.com/settings/apps/new?state=${safeState}" method="post"><input type="hidden" name="manifest" value="${safeManifest}"><button type="submit">Continue to GitHub</button></form></div>`, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
    },
  });
}

function parseCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") ?? "";
  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

async function providerSetupSession(request: Request, env: AuthEnv): Promise<boolean> {
  const session = parseCookie(request, "rda_setup");
  if (!session || !/^[A-Za-z0-9_-]{20,200}$/.test(session)) return false;
  return Boolean(await env.OAUTH_KV.get("setup:session:" + session));
}

async function beginProviderSetup(env: AuthEnv): Promise<Response> {
  const client = await githubClient(env);
  if (!client) return new Response("Create the Ravi Developer Agent GitHub App first.", { status: 503 });
  const state = randomVerifier();
  const verifier = randomVerifier();
  await env.OAUTH_KV.put("setup:oauth:" + state, verifier, { expirationTtl: 600 });
  const target = new URL("https://github.com/login/oauth/authorize");
  target.searchParams.set("client_id", client.clientId);
  target.searchParams.set("redirect_uri", PROVIDER_SETUP_CALLBACK);
  target.searchParams.set("state", state);
  target.searchParams.set("code_challenge", await s256(verifier));
  target.searchParams.set("code_challenge_method", "S256");
  return Response.redirect(target.toString(), 302);
}

async function providerSetupCallback(request: Request, env: AuthEnv): Promise<Response> {
  const client = await githubClient(env);
  if (!client) return new Response("GitHub App is not configured.", { status: 503 });
  const url = new URL(request.url);
  const state = url.searchParams.get("state") ?? "";
  const code = url.searchParams.get("code") ?? "";
  if (!state || !code) return new Response("Missing setup authorization parameters.", { status: 400 });
  const key = "setup:oauth:" + state;
  const verifier = await env.OAUTH_KV.get(key);
  await env.OAUTH_KV.delete(key);
  if (!verifier) return new Response("Setup authorization state is invalid or expired.", { status: 400 });

  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({
      client_id: client.clientId,
      client_secret: client.clientSecret,
      code,
      redirect_uri: PROVIDER_SETUP_CALLBACK,
      code_verifier: verifier,
    }),
  });
  if (!tokenResponse.ok) return new Response("GitHub setup sign-in failed.", { status: 502 });
  const token = await tokenResponse.json() as { access_token?: string };
  if (!token.access_token) return new Response("GitHub setup sign-in was not authorized.", { status: 401 });

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      accept: "application/vnd.github+json",
      authorization: "Bearer " + token.access_token,
      "user-agent": "ravi-developer-agent",
      "x-github-api-version": "2026-03-10",
    },
  });
  if (!userResponse.ok) return new Response("GitHub owner verification failed.", { status: 502 });
  const user = await userResponse.json() as { login?: string };
  if (user.login?.toLowerCase() !== GITHUB_APP_OWNER.toLowerCase()) {
    return new Response("Only the Ravi Developer Agent publisher can configure provider OAuth clients.", { status: 403 });
  }

  const session = randomVerifier();
  await env.OAUTH_KV.put("setup:session:" + session, "publisher", { expirationTtl: 900 });
  return new Response(null, {
    status: 302,
    headers: {
      location: AUTH_ISSUER + "/setup/providers/form",
      "set-cookie": "rda_setup=" + encodeURIComponent(session) + "; Path=/setup/providers; HttpOnly; Secure; SameSite=Strict; Max-Age=900",
      "cache-control": "no-store",
    },
  });
}

function providerSetupHtml(configured: { cloudflare: boolean; supabase: boolean }): string {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Provider OAuth setup</title>
<style>body{font-family:system-ui;background:#0f1115;color:#f5f7fb;display:grid;place-items:center;min-height:100vh;margin:0}.card{width:min(760px,calc(100% - 40px));padding:28px;border:1px solid #2a3040;border-radius:18px;background:#171a21}label{display:block;margin:14px 0 6px}.pair{display:grid;grid-template-columns:1fr;gap:8px}input{box-sizing:border-box;width:100%;padding:10px;border:1px solid #3a4255;border-radius:9px;background:#0f1115;color:#fff}button{margin-top:20px;padding:11px 18px;border:0;border-radius:10px;font-weight:700}.ok{color:#89e59a}.muted{color:#aeb7c8}code{word-break:break-all}</style>
<div class="card"><h1>Provider OAuth setup</h1><p class="muted">Credentials are submitted directly to the authorization Worker and are never returned to ChatGPT.</p>
<p>Cloudflare: <strong class="${configured.cloudflare ? "ok" : ""}">${configured.cloudflare ? "configured" : "not configured"}</strong><br>Supabase: <strong class="${configured.supabase ? "ok" : ""}">${configured.supabase ? "configured" : "not configured"}</strong></p>
<form method="post">
<h2>Cloudflare</h2><p class="muted">Redirect URI: <code>https://ravi-developer-agent.rvrmvth.workers.dev/oauth/cloudflare/callback</code></p>
<label>Client ID</label><input name="cloudflare_client_id" autocomplete="off">
<label>Client secret</label><input name="cloudflare_client_secret" type="password" autocomplete="new-password">
<h2>Supabase</h2><p class="muted">Redirect URI: <code>https://ravi-developer-agent.rvrmvth.workers.dev/oauth/supabase/callback</code></p>
<label>Client ID</label><input name="supabase_client_id" autocomplete="off">
<label>Client secret</label><input name="supabase_client_secret" type="password" autocomplete="new-password">
<button type="submit">Save provider credentials</button></form></div>`;
}

async function providerSetupForm(request: Request, env: AuthEnv): Promise<Response> {
  if (!await providerSetupSession(request, env)) return Response.redirect(AUTH_ISSUER + "/setup/providers", 302);

  if (request.method === "POST") {
    const form = await request.formData();
    for (const provider of ["cloudflare", "supabase"] as const) {
      const clientId = String(form.get(provider + "_client_id") ?? "").trim();
      const clientSecret = String(form.get(provider + "_client_secret") ?? "").trim();
      if ((clientId && !clientSecret) || (!clientId && clientSecret)) {
        return new Response("Both client ID and client secret are required for " + provider + ".", { status: 400 });
      }
      if (clientId && clientSecret) {
        await Promise.all([
          env.OAUTH_KV.put("provider:" + provider + ":client_id", clientId),
          env.OAUTH_KV.put("provider:" + provider + ":client_secret", clientSecret),
        ]);
      }
    }
  }

  const configured = {
    cloudflare: Boolean(await env.OAUTH_KV.get("provider:cloudflare:client_id") && await env.OAUTH_KV.get("provider:cloudflare:client_secret")),
    supabase: Boolean(await env.OAUTH_KV.get("provider:supabase:client_id") && await env.OAUTH_KV.get("provider:supabase:client_secret")),
  };
  return new Response(providerSetupHtml(configured), {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
    },
  });
}

async function githubManifestCallback(request: Request, env: AuthEnv): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") ?? "";
  const code = url.searchParams.get("code") ?? "";
  if (!state || !code) return new Response("Missing GitHub App manifest callback parameters.", { status: 400 });
  const stateKey = "github:manifest_state:" + state;
  const expected = await env.OAUTH_KV.get(stateKey);
  await env.OAUTH_KV.delete(stateKey);
  if (!expected) return new Response("GitHub App setup state is invalid or expired.", { status: 400 });

  const conversion = await fetch("https://api.github.com/app-manifests/" + encodeURIComponent(code) + "/conversions", {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      "user-agent": "ravi-developer-agent",
      "x-github-api-version": "2026-03-10",
    },
  });
  if (!conversion.ok) return new Response("GitHub App manifest conversion failed.", { status: 502 });

  const app = await conversion.json() as {
    client_id?: string;
    client_secret?: string;
    slug?: string;
    owner?: { login?: string };
  };
  if (!app.client_id || !app.client_secret || app.owner?.login?.toLowerCase() !== GITHUB_APP_OWNER.toLowerCase()) {
    return new Response("GitHub App owner validation failed.", { status: 403 });
  }

  await Promise.all([
    env.OAUTH_KV.put("github:client_id", app.client_id),
    env.OAUTH_KV.put("github:client_secret", app.client_secret),
    env.OAUTH_KV.put("github:app_slug", app.slug ?? ""),
  ]);

  const installUrl = app.slug ? "https://github.com/apps/" + encodeURIComponent(app.slug) + "/installations/new" : "https://github.com/settings/installations";
  const safeInstallUrl = escapeHtml(installUrl);
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GitHub App created</title><style>body{font-family:system-ui;background:#0f1115;color:#f5f7fb;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:620px;padding:28px;border:1px solid #2a3040;border-radius:18px;background:#171a21}a{display:inline-block;padding:11px 18px;border-radius:10px;background:#fff;color:#111;text-decoration:none;font-weight:700}</style><div class="card"><h1>GitHub App created</h1><p>The client credentials were stored inside the isolated authorization Worker. Install the app on the repositories Ravi Developer Agent should manage.</p><a href="${safeInstallUrl}">Install GitHub App</a></div>`, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; navigate-to https://github.com; base-uri 'none'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
    },
  });
}

async function startGithubSignIn(_request: Request, env: AuthEnv, approvedRequest: AuthRequest, headers: Headers): Promise<Response> {
  const client = await githubClient(env);
  if (!client) {
    return new Response("GitHub sign-in is not configured.", { status: 503, headers: { "cache-control": "no-store" } });
  }
  const oauth = authorizationServer.getOAuthApi(env);
  const verifier = randomVerifier();
  const upstream = await oauth.beginUpstream(approvedRequest, { data: { verifier }, headers });
  const target = new URL("https://github.com/login/oauth/authorize");
  target.searchParams.set("client_id", client.clientId);
  target.searchParams.set("redirect_uri", GITHUB_CALLBACK);
  target.searchParams.set("state", upstream.state);
  target.searchParams.set("code_challenge", await s256(verifier));
  target.searchParams.set("code_challenge_method", "S256");
  upstream.headers.set("Location", target.toString());
  return new Response(null, { status: 302, headers: upstream.headers });
}

async function authorize(request: Request, env: AuthEnv): Promise<Response> {
  const oauth = authorizationServer.getOAuthApi(env);
  try {
    if (request.method === "GET") {
      const parsed = await oauth.parseAuthRequest(request);
      const details = await oauth.describeConsent(parsed);
      const consent = await oauth.beginConsent(parsed);
      consent.headers.set("content-type", "text/html; charset=utf-8");
      return new Response(consentPage(details, consent.handle), { headers: consent.headers });
    }

    if (request.method === "POST") {
      const form = await request.formData();
      const handle = String(form.get("handle") ?? "");
      if (form.get("decision") !== "approve") {
        const denied = await oauth.denyConsent(request, handle);
        return new Response(null, { status: 302, headers: denied.headers });
      }
      const scope = form.getAll("scope").map(String);
      const approved = await oauth.approveConsent(request, handle, { scope });
      return startGithubSignIn(request, env, approved.request, approved.headers);
    }

    return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  } catch (error) {
    if (error instanceof AuthorizationError && error.redirectTo) {
      return Response.redirect(error.redirectTo, 302);
    }
    if (error instanceof AuthorizationError) {
      return new Response(error.description, { status: 400, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    }
    throw error;
  }
}

async function githubCallback(request: Request, env: AuthEnv): Promise<Response> {
  const client = await githubClient(env);
  if (!client) {
    return new Response("GitHub sign-in is not configured.", { status: 503, headers: { "cache-control": "no-store" } });
  }

  const oauth = authorizationServer.getOAuthApi(env);
  const resumed = await oauth.finishUpstream<{ verifier: string }>(request);
  const url = new URL(request.url);
  if (url.searchParams.get("error")) {
    const redirect = new URL(resumed.request.redirectUri);
    redirect.searchParams.set("error", "access_denied");
    redirect.searchParams.set("error_description", "GitHub sign-in was not approved.");
    redirect.searchParams.set("state", resumed.request.state);
    redirect.searchParams.set("iss", AUTH_ISSUER);
    resumed.headers.set("Location", redirect.toString());
    return new Response(null, { status: 302, headers: resumed.headers });
  }

  const code = url.searchParams.get("code");
  if (!code) return new Response("Missing GitHub authorization code.", { status: 400 });

  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "accept": "application/json", "content-type": "application/json" },
    body: JSON.stringify({
      client_id: client.clientId,
      client_secret: client.clientSecret,
      code,
      redirect_uri: GITHUB_CALLBACK,
      code_verifier: resumed.data.verifier,
    }),
  });
  if (!tokenResponse.ok) return new Response("GitHub token exchange failed.", { status: 502 });
  const token = await tokenResponse.json() as { access_token?: string; expires_in?: number; refresh_token?: string; refresh_token_expires_in?: number; error?: string };
  if (!token.access_token) return new Response("GitHub sign-in failed.", { status: 401 });

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      "accept": "application/vnd.github+json",
      "authorization": `Bearer ${token.access_token}`,
      "user-agent": "ravi-developer-agent",
      "x-github-api-version": "2026-03-10",
    },
  });
  if (!userResponse.ok) return new Response("GitHub identity lookup failed.", { status: 502 });
  const user = await userResponse.json() as { id?: number; login?: string };
  if (!user.id) return new Response("GitHub identity is invalid.", { status: 502 });

  const emailsResponse = await fetch("https://api.github.com/user/emails?per_page=100", {
    headers: {
      "accept": "application/vnd.github+json",
      "authorization": `Bearer ${token.access_token}`,
      "user-agent": "ravi-developer-agent",
      "x-github-api-version": "2026-03-10",
    },
  });
  if (!emailsResponse.ok) return new Response("GitHub verified email lookup failed.", { status: 502 });
  const emails = await emailsResponse.json() as Array<{ email?: string; primary?: boolean; verified?: boolean }>;
  const verifiedEmail = emails.find((item) => item.primary && item.verified && item.email)?.email
    ?? emails.find((item) => item.verified && item.email)?.email;
  if (!verifiedEmail) return new Response("A verified GitHub email is required to connect Ravi Developer Agent.", { status: 403 });

  const userId = `github-${user.id}`;
  await saveGithubUserToken(env, userId, {
    access_token: token.access_token,
    expires_in: token.expires_in,
    refresh_token: token.refresh_token,
    refresh_token_expires_in: token.refresh_token_expires_in,
  });
  const props: AuthProps = {
    userId,
    tenantId: `gh-${user.id}`,
    subject: userId,
    loginProvider: "github",
    login: user.login ?? userId,
    githubToken: token.access_token,
    email: verifiedEmail,
    emailVerified: true,
  };
  const completed = await oauth.completeAuthorization({
    request: resumed.request,
    userId,
    metadata: { provider: "github", login: user.login ?? "", email_verified: true },
    scope: resumed.request.scope,
    props,
  });
  resumed.headers.set("Location", completed.redirectTo);
  return new Response(null, { status: 302, headers: resumed.headers });
}

function openIdConfiguration(): Response {
  return Response.json({
    issuer: AUTH_ISSUER,
    authorization_endpoint: AUTH_ISSUER + "/authorize",
    token_endpoint: AUTH_ISSUER + "/oauth/token",
    userinfo_endpoint: AUTH_ISSUER + "/userinfo",
    registration_endpoint: AUTH_ISSUER + "/oauth/register",
    scopes_supported: ["openid", "email", "agent:read", "agent:write", "offline_access"],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
    subject_types_supported: ["public"],
    claims_supported: ["sub", "email", "email_verified"],
  }, { headers: { "cache-control": "public, max-age=300" } });
}

async function userInfo(request: Request, env: AuthEnv): Promise<Response> {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "www-authenticate": 'Bearer error="invalid_token", error_description="A bearer access token is required"',
        "cache-control": "no-store",
      },
    });
  }
  const validated = await authorizationServer.validateToken(MCP_RESOURCE, match[1], env);
  if (!validated) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "www-authenticate": 'Bearer error="invalid_token", error_description="The access token is invalid or expired"',
        "cache-control": "no-store",
      },
    });
  }
  if (!validated.scope.includes("openid") || !validated.scope.includes("email")) {
    return new Response("Insufficient scope", {
      status: 403,
      headers: {
        "www-authenticate": 'Bearer error="insufficient_scope", scope="openid email"',
        "cache-control": "no-store",
      },
    });
  }
  if (!validated.props.email || validated.props.emailVerified !== true) {
    return new Response("Verified email unavailable", { status: 403, headers: { "cache-control": "no-store" } });
  }
  return Response.json({
    sub: validated.userId,
    email: validated.props.email,
    email_verified: true,
  }, { headers: { "cache-control": "no-store" } });
}

export class AuthServer extends WorkerEntrypoint<AuthEnv> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/.well-known/openid-configuration") return openIdConfiguration();
    if (url.pathname === "/userinfo") return userInfo(request, this.env);
    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "ravi-developer-agent-auth",
        oauth: "enabled",
        upstreamLogin: await githubConfigured(this.env) ? "github-app" : "github-app-not-configured",
      }, { headers: { "cache-control": "no-store" } });
    }
    if (url.pathname === "/setup/github-app") return githubManifestPage(this.env);
    if (url.pathname === "/setup/github-app/callback") return githubManifestCallback(request, this.env);
    if (url.pathname === "/setup/providers") return beginProviderSetup(this.env);
    if (url.pathname === "/setup/providers/callback") return providerSetupCallback(request, this.env);
    if (url.pathname === "/setup/providers/form") return providerSetupForm(request, this.env);
    if (url.pathname === "/authorize") return authorize(request, this.env);
    if (url.pathname === "/callback") return githubCallback(request, this.env);
    return authorizationServer.fetch(request, this.env, this.ctx);
  }

  validateToken(resource: string, token: string) {
    return authorizationServer.validateToken(resource, token, this.env);
  }

  async getGithubToken(userId: string, fallback?: string) {
    return activeGithubUserToken(this.env, userId, fallback);
  }

  async getProviderClient(provider: "cloudflare" | "supabase") {
    const [clientId, clientSecret] = await Promise.all([
      this.env.OAUTH_KV.get("provider:" + provider + ":client_id"),
      this.env.OAUTH_KV.get("provider:" + provider + ":client_secret"),
    ]);
    return clientId && clientSecret ? { clientId, clientSecret } : null;
  }
}

export default AuthServer;
