import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

type Env = Record<string, never>;

function result(data: unknown) {
  const text = JSON.stringify(data);
  return { structuredContent: data as Record<string, unknown>, content: [{ type: "text" as const, text }] };
}

function createServer() {
  const server = new McpServer({ name: "ravi-developer-agent", version: "0.1.0" });

  server.registerTool(
    "agent_status",
    { description: "Return Ravi Developer Agent service capabilities and status." },
    async () => result({
      ok: true,
      service: "Ravi Developer Agent",
      version: "0.1.0",
      transport: "MCP Streamable HTTP",
      multiUserReady: false,
      authentication: "planned-next",
      providers: ["github", "supabase", "cloudflare", "browser"],
    }),
  );

  server.registerTool(
    "project_plan",
    {
      description: "Create a safe execution plan for a cloud development task before provider actions are enabled.",
      inputSchema: {
        task: z.string().min(1).describe("Development task to plan"),
        repository: z.string().optional().describe("owner/repository when known"),
      },
    },
    async ({ task, repository }) => result({
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

  return server;
}

const mcp = createMcpHandler(() => createServer(), { route: "/mcp" });

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "ravi-developer-agent", version: "0.1.0" });
    }
    if (url.pathname === "/") {
      return Response.json({
        name: "Ravi Developer Agent",
        version: "0.1.0",
        mcp: "/mcp",
        health: "/health",
      });
    }
    return mcp(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
