import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const plugin = JSON.parse(readFileSync(new URL("../plugin/plugin.json", import.meta.url), "utf8"));
const mcp = JSON.parse(readFileSync(new URL("../plugin/mcp.json", import.meta.url), "utf8"));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

describe("ChatGPT plugin submission package", () => {
  it("keeps release versions aligned", () => {
    expect(plugin.version).toBe("1.0.1");
    expect(pkg.version).toBe("1.0.1");
  });

  it("uses the production Streamable HTTP MCP endpoint", () => {
    const server = mcp.mcpServers?.["ravi-developer-agent"];
    expect(server?.type).toBe("streamable-http");
    expect(server?.url).toBe("https://ravi-developer-agent.rvrmvth.workers.dev/mcp");
  });

  it("has exactly the initial-review test-case counts OpenAI requires", () => {
    const cases = plugin.extensions?.["com.openai"]?.review?.test_cases;
    expect(cases?.positive).toHaveLength(5);
    expect(cases?.negative).toHaveLength(3);
    for (const item of cases.positive) {
      expect(item.prompt).toBeTruthy();
      expect(item.tools_triggered).toBeTruthy();
      expect(item.expected_behavior).toBeTruthy();
    }
  });

  it("declares public HTTPS policy and support URLs", () => {
    const ui = plugin.extensions?.["com.openai"]?.interface;
    for (const key of ["websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"]) {
      expect(ui?.[key]).toMatch(/^https:\/\//);
    }
  });

  it("does not package reviewer credentials or authentication secrets", () => {
    const serialized = JSON.stringify(plugin).toLowerCase();
    expect(serialized).not.toContain("test_credentials");
    expect(serialized).not.toContain("reviewer_instructions");
    // Safety copy may legitimately mention words such as "password" or "API key".
    // Reject packaged credential fields and well-known token formats instead.
    expect(serialized).not.toMatch(/"(?:client_secret|access_token|api[_-]?key|password)"\s*:\s*"[^"]+"/);
    expect(serialized).not.toMatch(/\b(?:gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|sk-[a-z0-9_-]{20,})\b/i);
  });
});
