import { WorkerEntrypoint } from "cloudflare:workers";

export class AuthServer extends WorkerEntrypoint {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "ravi-developer-agent-auth",
        status: "scaffolded",
        oauth: "disabled-until-dedicated-storage-and-upstream-login-are-configured",
      });
    }
    return Response.json(
      { error: "authorization_server_not_configured" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  async validateToken(_resource: string, _token: string) {
    return { valid: false };
  }
}

export default {
  async fetch(request: Request, env: unknown, ctx: ExecutionContext) {
    const entry = new AuthServer(ctx, env);
    return entry.fetch(request);
  },
};
