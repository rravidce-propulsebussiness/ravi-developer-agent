import { describe, expect, it } from "vitest";
import { hostnameAllowed, validDomainPattern } from "../src/security";

describe("validDomainPattern", () => {
  it("accepts public hostnames and controlled wildcard patterns", () => {
    expect(validDomainPattern("example.com")).toBe(true);
    expect(validDomainPattern("api.example.co.in")).toBe(true);
    expect(validDomainPattern("*.example.com")).toBe(true);
  });

  it("rejects localhost, URLs, IP literals, uppercase, and malformed wildcards", () => {
    for (const value of [
      "localhost",
      "app.localhost",
      "https://example.com",
      "127.0.0.1",
      "169.254.169.254",
      "::1",
      "Example.com",
      "*.*.example.com",
      "example.com/path",
      "user@example.com",
    ]) {
      expect(validDomainPattern(value), value).toBe(false);
    }
  });
});

describe("hostnameAllowed", () => {
  it("matches exact hosts case-insensitively and ignores a trailing dot", () => {
    expect(hostnameAllowed("EXAMPLE.COM.", ["example.com"])).toBe(true);
    expect(hostnameAllowed("api.example.com", ["example.com"])).toBe(false);
  });

  it("allows subdomains for wildcard patterns but not the apex", () => {
    expect(hostnameAllowed("api.example.com", ["*.example.com"])).toBe(true);
    expect(hostnameAllowed("deep.api.example.com", ["*.example.com"])).toBe(true);
    expect(hostnameAllowed("example.com", ["*.example.com"])).toBe(false);
    expect(hostnameAllowed("evil-example.com", ["*.example.com"])).toBe(false);
  });
});
