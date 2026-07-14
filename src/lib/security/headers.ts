import type { DeploymentMode } from "./deployment";
import { getDeploymentMode } from "./deployment";

export const CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";
export const CSP_NONCE_HEADER = "x-nonce";

export interface SecurityHeader {
  key: string;
  value: string;
}

function assertValidNonce(nonce: string): void {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(nonce)) {
    throw new Error("CSP nonce must be a non-empty base64-compatible value");
  }
}

export function buildContentSecurityPolicy(
  nonce: string,
  mode: DeploymentMode = getDeploymentMode(),
): string {
  assertValidNonce(nonce);
  const isHosted = mode === "hosted";
  const scriptSources = [
    "'self'",
    `'nonce-${nonce}'`,
    "'strict-dynamic'",
    ...(!isHosted ? ["'unsafe-eval'"] : []),
  ];

  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `script-src ${scriptSources.join(" ")}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: https:${isHosted ? "" : " http:"}`,
    "media-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src 'self' https: blob:${isHosted ? "" : " http:"}`,
    "frame-src 'self' blob: data:",
    "worker-src 'self' blob:",
  ].join("; ");
}

export function getSecurityHeaders(): SecurityHeader[] {
  return [
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "X-Frame-Options", value: "DENY" },
    {
      key: "Permissions-Policy",
      value:
        "camera=(), microphone=(self), geolocation=(), payment=(), usb=(), serial=()",
    },
  ];
}
