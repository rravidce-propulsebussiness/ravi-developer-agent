import {
  AuthorizationError,
  OAuthAuthorizationServer,
} from "@cloudflare/workers-oauth-provider";
import { WorkerEntrypoint } from "cloudflare:workers";

const AUTH_ISSUER = "https://ravi-developer-agent-auth.rvrmvth.workers.dev";
const MCP_RESOURCE = "https://ravi-developer-agent.rvrmvth.workers.dev/mcp";
const GITHUB_CALLBACK = AUTH_ISSUER + "/callback";

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
};

const authorizationServer = new OAuthAuthorizationServer<AuthEnv>({
  issuer: AUTH_ISSUER,
  resources: [MCP_RESOURCE],
  scopesSupported: ["agent:read", "agent:write", "offline_access"],
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

async function startGithubSignIn(request: Request, env: AuthEnv, approvedRequest: Parameters<Awaited<ReturnType<ReturnType<typeof authorizationServer.getOAuthApi>["beginUpstream"]>>>[0] extends never ? never : any, headers: Headers): Promise<Response> {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return new Response("GitHub sign-in is not configured.", { status: 503, headers: { "cache-control": "no-store" } });
  }
  const oauth = authorizationServer.getOAuthApi(env);
  const verifier = randomVerifier();
  const upstream = await oauth.beginUpstream(approvedRequest, { data: { verifier }, headers });
  const target = new URL("https://github.com/login/oauth/authorize");
  target.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  target.searchParams.set("redirect_uri", GITHUB_CALLBACK);
  target.searchParams.set("state", upstream.state);
  target.searchParams.set("code_challenge", await s256(verifier));
  target.searchParams.set("code_challenge_method", "S256");
  target.searchParams.set("scope", "read:user");
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
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
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
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: GITHUB_CALLBACK,
      code_verifier: resumed.data.verifier,
    }),
  });
  if (!tokenResponse.ok) return new Response("GitHub token exchange failed.", { status: 502 });
  const token = await tokenResponse.json() as { access_token?: string; error?: string };
  if (!token.access_token) return new Response("GitHub sign-in failed.", { status: 401 });

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      "accept": "application/vnd.github+json",
      "authorization": `Bearer ${token.access_token}`,
      "user-agent": "ravi-developer-agent",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (!userResponse.ok) return new Response("GitHub identity lookup failed.", { status: 502 });
  const user = await userResponse.json() as { id?: number; login?: string };
  if (!user.id) return new Response("GitHub identity is invalid.", { status: 502 });

  const userId = `github-${user.id}`;
  const props: AuthProps = {
    userId,
    tenantId: `gh-${user.id}`,
    subject: userId,
    loginProvider: "github",
  };
  const completed = await oauth.completeAuthorization({
    request: resumed.request,
    userId,
    metadata: { provider: "github", login: user.login ?? "" },
    scope: resumed.request.scope,
    props,
  });
  resumed.headers.set("Location", completed.redirectTo);
  return new Response(null, { status: 302, headers: resumed.headers });
}

export class AuthServer extends WorkerEntrypoint<AuthEnv> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "ravi-developer-agent-auth",
        oauth: "enabled",
        upstreamLogin: this.env.GITHUB_CLIENT_ID && this.env.GITHUB_CLIENT_SECRET ? "github" : "github-not-configured",
      });
    }
    if (url.pathname === "/authorize") return authorize(request, this.env);
    if (url.pathname === "/callback") return githubCallback(request, this.env);
    return authorizationServer.fetch(request, this.env, this.ctx);
  }

  validateToken(resource: string, token: string) {
    return authorizationServer.validateToken(resource, token, this.env);
  }
}

export default AuthServer;
