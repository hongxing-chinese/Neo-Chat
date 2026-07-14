import { describe, expect, it } from "vitest";
import {
  buildContentSecurityPolicy,
  CONTENT_SECURITY_POLICY_HEADER,
  getSecurityHeaders,
} from "../lib/security/headers";

function getCspValue(mode: "local" | "hosted"): string {
  return buildContentSecurityPolicy("testNonce", mode);
}

function getDirective(csp: string, directive: string): string {
  return (
    csp
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${directive} `)) || ""
  );
}

describe("security headers", () => {
  it("keeps request-specific CSP out of static response headers", () => {
    expect(
      getSecurityHeaders().find(
        (header) => header.key === CONTENT_SECURITY_POLICY_HEADER,
      ),
    ).toBeUndefined();
  });

  it("requires a base64-compatible nonce", () => {
    expect(() => buildContentSecurityPolicy("", "hosted")).toThrow();
    expect(() =>
      buildContentSecurityPolicy('bad"; script-src *', "hosted"),
    ).toThrow();
  });

  it("does not upgrade self-hosted HTTP requests to HTTPS", () => {
    expect(getCspValue("local")).not.toContain("upgrade-insecure-requests");
    expect(getCspValue("hosted")).not.toContain("upgrade-insecure-requests");
  });

  it("allows development evaluation while requiring nonce-backed scripts", () => {
    const csp = getCspValue("local");

    expect(getDirective(csp, "script-src")).toContain("'nonce-testNonce'");
    expect(getDirective(csp, "script-src")).toContain("'strict-dynamic'");
    expect(getDirective(csp, "script-src")).not.toContain("'unsafe-inline'");
    expect(getDirective(csp, "script-src")).toContain("'unsafe-eval'");
    expect(getDirective(csp, "img-src")).toContain("http:");
    expect(getDirective(csp, "connect-src")).toContain("http:");
  });

  it("removes broad http and unsafe-eval sources in hosted CSP", () => {
    const csp = getCspValue("hosted");

    expect(getDirective(csp, "script-src")).not.toContain("'unsafe-eval'");
    expect(getDirective(csp, "script-src")).not.toContain("'unsafe-inline'");
    expect(getDirective(csp, "script-src")).toContain("'nonce-testNonce'");
    expect(getDirective(csp, "script-src")).toContain("'strict-dynamic'");
    expect(getDirective(csp, "img-src")).not.toContain("http:");
    expect(getDirective(csp, "connect-src")).not.toContain("http:");
  });
});
