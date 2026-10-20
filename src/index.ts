import { createHash } from "node:crypto";
import type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth";

export interface OneIdOptions {
  clientId: string;
  clientSecret: string;
  /** Information-system code assigned by OneID, not an OIDC scope list. */
  scope: string;
  /** Exact HTTPS Authorization.do endpoint issued by OneID. No assumed host. */
  endpoint: string;
  /** Exact registered callback URL, including /api/auth/callback/oneid. */
  redirectURI: string;
  /** Legacy deployments use query parameters on server-side POST requests. */
  parameterTransport?: "query" | "body";
  /** Legacy OneID deployments do not support PKCE. Confirm with the operator. */
  pkce?: boolean;
  timeoutMs?: number;
  disableSignUp?: boolean;
  disableImplicitSignUp?: boolean;
  /** Supply a fetch-compatible implementation for testing or custom networking. */
  fetch?: typeof globalThis.fetch;
}

/** Errors deliberately omit provider responses, credentials, and personal data. */
export class OneIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OneIdError";
  }
}

type JsonObject = Record<string, unknown>;

function object(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function httpsUrl(value: string, field: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OneIdError(`OneID ${field} must be an absolute HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new OneIdError(`OneID ${field} must use HTTPS without credentials, query, or fragment`);
  }
  return url;
}

/** Creates a Generic OAuth helper for the legacy OneID Authorization.do flow. */
export function oneId(options: OneIdOptions): GenericOAuthConfig<"oneid"> {
  // Copy configuration so later caller mutations cannot change callback binding.
  const clientId = text(options.clientId);
  const clientSecret = text(options.clientSecret);
  const scope = text(options.scope);
  if (!clientId || !clientSecret || !scope || /\s/.test(scope)) {
    throw new OneIdError("OneID requires clientId, clientSecret, and one assigned scope code");
  }
  const endpoint = httpsUrl(options.endpoint, "endpoint").href;
  const redirectURI = httpsUrl(options.redirectURI, "redirectURI").href;
  const parameterTransport = options.parameterTransport ?? "query";
  if (parameterTransport !== "query" && parameterTransport !== "body") {
    throw new OneIdError("OneID parameterTransport must be query or body");
  }
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new OneIdError("OneID timeoutMs must be a positive integer");
  }
  const pkce = options.pkce ?? false;
  const request = options.fetch ?? globalThis.fetch;

  async function post(parameters: Record<string, string>): Promise<JsonObject> {
    const url = new URL(endpoint);
    const params = new URLSearchParams({ client_id: clientId!, client_secret: clientSecret!, ...parameters });
    const init: RequestInit = {
      method: "POST",
      redirect: "error",
      cache: "no-store",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (parameterTransport === "query") {
      url.search = params.toString();
    } else {
      init.body = params;
    }
    let response: Response;
    try {
      response = await request(url, init);
    } catch {
      throw new OneIdError("OneID request failed or timed out");
    }
    if (!response.ok) {
      throw new OneIdError(`OneID request failed (HTTP ${response.status})`);
    }
    let result: unknown;
    try {
      result = await response.json();
    } catch {
      throw new OneIdError("OneID returned invalid JSON");
    }
    if (!object(result) || result.error || result.error_description) {
      throw new OneIdError("OneID returned an unsuccessful response");
    }
    if (result.ret_cd !== undefined && !/^0+$/.test(String(result.ret_cd))) {
      throw new OneIdError("OneID returned an unsuccessful response code");
    }
    return result;
  }

  return {
    providerId: "oneid",
    name: "OneID (Uzbekistan)",
    clientId,
    clientSecret,
    authorizationUrl: endpoint,
    tokenUrl: endpoint,
    scopes: [scope],
    redirectURI,
    responseType: "one_code",
    pkce,
    disableSignUp: options.disableSignUp,
    disableImplicitSignUp: options.disableImplicitSignUp,
    async getToken({ code, redirectURI: callback, codeVerifier }) {
      if (!text(code) || callback !== redirectURI) {
        throw new OneIdError("OneID authorization code or callback is invalid");
      }
      const parameters: Record<string, string> = {
        grant_type: "one_authorization_code",
        code,
        redirect_uri: redirectURI,
      };
      if (pkce && codeVerifier) parameters.code_verifier = codeVerifier;
      const result = await post(parameters);
      const accessToken = text(result.access_token);
      if (!accessToken) throw new OneIdError("OneID did not return an access token");
      const expiresIn = Number(result.expires_in);
      return {
        accessToken,
        tokenType: "Bearer",
        ...(Number.isFinite(expiresIn) && expiresIn > 0
          ? { accessTokenExpiresAt: new Date(Date.now() + expiresIn * 1000) }
          : {}),
      };
    },
    async getUserInfo({ accessToken }) {
      if (!accessToken) throw new OneIdError("OneID access token is missing");
      const profile = await post({
        grant_type: "one_access_token_identify",
        access_token: accessToken,
      });
      const id = text(profile.user_id);
      if (!id) throw new OneIdError("OneID profile has no stable user_id");
      // A reserved-domain placeholder allows sign-up without trusting a mutable,
      // potentially unverified contact email for automatic account linking.
      const digest = createHash("sha256").update(id).digest("hex");
      const name = text(profile.full_name) ??
        [text(profile.first_name), text(profile.sur_name)].filter(Boolean).join(" ");
      return {
        id,
        name: name || "OneID user",
        email: `${digest}@oneid.invalid`,
        emailVerified: false,
      };
    },
  };
}
