import { NextRequest, NextResponse } from "next/server";
import {
  ACCESS_ATTEMPTS_COOKIE,
  ACCESS_ERROR_CODES,
  ACCESS_SESSION_COOKIE,
  getAccessAttemptState,
  isAccessLocked,
  isAccessPasswordEnabled,
  isValidAccessSessionCookie,
} from "./lib/security/accessControl";
import { applyRequestGuards } from "./lib/security/requestGuards";
import { REQUEST_PROOF_SESSION_PATH } from "./lib/security/requestProof";
import {
  buildContentSecurityPolicy,
  CONTENT_SECURITY_POLICY_HEADER,
  CSP_NONCE_HEADER,
} from "./lib/security/headers";

const ACCESS_VERIFY_PATH = "/api/access/verify";

function jsonError(
  status: number,
  payload: Record<string, unknown>,
): NextResponse {
  const response = NextResponse.json(
    { ...payload, statusCode: status },
    { status },
  );
  response.headers.set("Cache-Control", "no-store");
  return response;
}

function createNonce(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

function applyContentSecurityPolicy(
  response: NextResponse,
  contentSecurityPolicy: string,
): NextResponse {
  response.headers.set(CONTENT_SECURITY_POLICY_HEADER, contentSecurityPolicy);
  return response;
}

function nextWithContentSecurityPolicy(
  request: NextRequest,
  nonce: string,
  contentSecurityPolicy: string,
): NextResponse {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(CSP_NONCE_HEADER, nonce);
  requestHeaders.set(CONTENT_SECURITY_POLICY_HEADER, contentSecurityPolicy);

  return applyContentSecurityPolicy(
    NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    }),
    contentSecurityPolicy,
  );
}

export async function middleware(request: NextRequest) {
  const nonce = createNonce();
  const contentSecurityPolicy = buildContentSecurityPolicy(nonce);
  const nextResponse = () =>
    nextWithContentSecurityPolicy(request, nonce, contentSecurityPolicy);

  if (!request.nextUrl.pathname.startsWith("/api/")) {
    return nextResponse();
  }

  const guardResponse = await applyRequestGuards(request);
  if (guardResponse) {
    return applyContentSecurityPolicy(guardResponse, contentSecurityPolicy);
  }

  if (!isAccessPasswordEnabled()) {
    return nextResponse();
  }

  if (
    request.nextUrl.pathname === ACCESS_VERIFY_PATH ||
    request.nextUrl.pathname === REQUEST_PROOF_SESSION_PATH
  ) {
    return nextResponse();
  }

  const sessionCookie = request.cookies.get(ACCESS_SESSION_COOKIE)?.value;
  if (await isValidAccessSessionCookie(sessionCookie)) {
    return nextResponse();
  }

  const attemptState = await getAccessAttemptState(
    request.cookies.get(ACCESS_ATTEMPTS_COOKIE)?.value,
  );
  if (isAccessLocked(attemptState)) {
    return applyContentSecurityPolicy(
      jsonError(423, {
        error: "Access is temporarily locked",
        code: ACCESS_ERROR_CODES.locked,
        lockedUntil: attemptState.lockedUntil,
      }),
      contentSecurityPolicy,
    );
  }

  return applyContentSecurityPolicy(
    jsonError(401, {
      error: "Access password is required",
      code: ACCESS_ERROR_CODES.required,
    }),
    contentSecurityPolicy,
  );
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
