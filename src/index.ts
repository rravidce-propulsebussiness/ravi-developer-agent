import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

type Env = {
  AUTH_SERVER_URL?: string;
  BROWSER?: Fetcher;
};

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
