/**
 * AUTH_MODE=oauth (fork-only): every person signs in with their own NinjaOne
 * account, and every tool call they make runs on their own NinjaOne token.
 *
 * Towards Claude and Microsoft 365 Copilot this server is its own OAuth 2.1
 * authorization server (metadata, /authorize, /token, /register, /revoke,
 * PKCE S256). /authorize sends the browser on to NinjaOne's authorization code
 * flow; the NinjaOne callback stores that person's NinjaOne refresh token and
 * completes the client's flow with a code of our own.
 *
 *   client ──/authorize──▶ server ──302──▶ <region>.ninjarmm.com/ws/oauth/authorize
 *   NinjaOne ──302──▶ /oauth/ninja/callback?code=…   (server redeems it)
 *   server ──302──▶ client redirect_uri?code=…
 *   client ──/token──▶ access + refresh token
 *   client ──/mcp, Bearer token──▶ tools run on that person's NinjaOne token
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { getBaseUrlForRegion, isValidRegion, parseScopes } from "../utils/types.js";
import type { NinjaOneCredentials } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { OAuthStore, randomToken, sha256, type OAuthClient } from "./store.js";
import { exchangeNinjaCode, ninjaAuthorizeUrl, NinjaSessions, type NinjaAppConfig } from "./ninja.js";

export const OAUTH_SCOPE = "ninjaone";
export const NINJA_CALLBACK_PATH = "/oauth/ninja/callback";

const CODE_TTL_MS = 5 * 60_000;
const BODY_LIMIT = 64 * 1024;

export interface OAuthServerConfig {
  publicUrl: string;
  secretKey: string;
  dbPath: string;
  ninja: NinjaAppConfig;
  accessTokenTtlMs: number;
  refreshTokenTtlMs: number;
  /** A fixed client (Microsoft 365 Copilot cannot register dynamically). */
  staticClient?: { clientId: string; secret: string; redirectUris: string[]; authMethod: OAuthClient["authMethod"] };
}

/** The authenticated person behind a /mcp request. */
export interface OAuthPrincipal {
  userId: string;
  clientId: string;
  scopes: string[];
  expiresAt: number;
}

function envInt(name: string, fallback: number): number {
  const value = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

/** Read and validate AUTH_MODE=oauth settings. Throws with every problem listed. */
export function loadOAuthConfig(env: NodeJS.ProcessEnv = process.env): OAuthServerConfig {
  const problems: string[] = [];
  const publicUrl = (env.MCP_PUBLIC_URL ?? "").trim().replace(/\/+$/, "");
  if (!publicUrl) problems.push("MCP_PUBLIC_URL is required (e.g. https://ninjaone.example.com, without /mcp)");
  else if (!/^https:\/\//.test(publicUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
    problems.push("MCP_PUBLIC_URL must be https (http only for localhost)");
  }
  const secretKey = (env.MCP_SECRET_KEY ?? "").trim();
  if (secretKey.length < 32) problems.push("MCP_SECRET_KEY must be at least 32 characters (openssl rand -hex 32)");
  const clientId = (env.NINJAONE_CLIENT_ID ?? "").trim();
  const clientSecret = (env.NINJAONE_CLIENT_SECRET ?? "").trim();
  if (!clientId || !clientSecret) {
    problems.push("NINJAONE_CLIENT_ID and NINJAONE_CLIENT_SECRET (of the NinjaOne Web application) are required");
  }
  const region = (env.NINJAONE_REGION ?? "us").trim().toLowerCase();
  if (!isValidRegion(region)) problems.push(`NINJAONE_REGION "${region}" is not one of us, eu, oc, ca, us2, fed`);

  let staticClient: OAuthServerConfig["staticClient"];
  const staticId = (env.MCP_OAUTH_CLIENT_ID ?? "").trim();
  if (staticId) {
    const secret = (env.MCP_OAUTH_CLIENT_SECRET ?? "").trim();
    const redirectUris = (env.MCP_OAUTH_CLIENT_REDIRECT_URIS ?? "")
      .split(/[\s,]+/)
      .filter(Boolean);
    const method = (env.MCP_OAUTH_CLIENT_AUTH_METHOD ?? "client_secret_post").trim();
    if (!secret) problems.push("MCP_OAUTH_CLIENT_SECRET is required with MCP_OAUTH_CLIENT_ID");
    if (redirectUris.length === 0) problems.push("MCP_OAUTH_CLIENT_REDIRECT_URIS is required with MCP_OAUTH_CLIENT_ID");
    if (method !== "client_secret_post" && method !== "client_secret_basic") {
      problems.push("MCP_OAUTH_CLIENT_AUTH_METHOD must be client_secret_post or client_secret_basic");
    }
    staticClient = { clientId: staticId, secret, redirectUris, authMethod: method as OAuthClient["authMethod"] };
  }

  if (problems.length > 0) {
    throw new Error(`AUTH_MODE=oauth is misconfigured:\n- ${problems.join("\n- ")}`);
  }

  return {
    publicUrl,
    secretKey,
    dbPath: env.MCP_OAUTH_DB_PATH?.trim() || join(env.MCP_DATA_DIR?.trim() || "/data", "oauth.sqlite3"),
    ninja: {
      baseUrl: getBaseUrlForRegion(region as Parameters<typeof getBaseUrlForRegion>[0]),
      clientId,
      clientSecret,
      scopes: parseScopes(env.NINJAONE_SCOPES) ?? ["monitoring", "management"],
      redirectUri: `${publicUrl}${NINJA_CALLBACK_PATH}`,
    },
    accessTokenTtlMs: envInt("MCP_OAUTH_ACCESS_TOKEN_TTL", 3600) * 1000,
    refreshTokenTtlMs: envInt("MCP_OAUTH_REFRESH_TOKEN_TTL", 30 * 24 * 3600) * 1000,
    staticClient,
  };
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly description: string
  ) {
    super(description);
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    ...headers,
  });
  res.end(JSON.stringify(body));
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function sendPage(res: ServerResponse, status: number, title: string, message: string): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  });
  res.end(
    `<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<title>${escapeHtml(title)}</title><style>body{font-family:system-ui,sans-serif;background:#fafafa;color:#18181b;` +
      `display:grid;place-items:center;min-height:100vh;margin:0}main{background:#fff;border:1px solid #e4e4e7;border-radius:12px;` +
      `padding:32px;max-width:440px;margin:16px}h1{font-size:20px;margin:0 0 12px}p{color:#52525b;line-height:1.5;margin:0}</style>` +
      `</head><body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></main></body></html>`
  );
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > BODY_LIMIT) throw new HttpError(413, "invalid_request", "Request body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  return new URLSearchParams(await readBody(req));
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function isAllowedRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    if (url.hash) return false;
    if (url.protocol === "https:") return true;
    // Loopback redirects for native clients (RFC 8252); no other plain http.
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  } catch {
    return false;
  }
}

export class OAuthServer {
  readonly store: OAuthStore;
  readonly sessions: NinjaSessions;
  private readonly issuer: string;
  private readonly resourceUrl: string;
  private readonly resourceMetadataUrl: string;

  constructor(private readonly config: OAuthServerConfig) {
    this.store = new OAuthStore(config.dbPath, config.secretKey);
    this.sessions = new NinjaSessions(config.ninja, this.store);
    this.issuer = config.publicUrl;
    this.resourceUrl = `${config.publicUrl}/mcp`;
    this.resourceMetadataUrl = `${config.publicUrl}/.well-known/oauth-protected-resource/mcp`;
    if (config.staticClient) {
      this.store.saveClient({
        clientId: config.staticClient.clientId,
        secretHash: sha256(config.staticClient.secret),
        redirectUris: config.staticClient.redirectUris,
        name: "Static client (MCP_OAUTH_CLIENT_ID)",
        authMethod: config.staticClient.authMethod,
      });
    }
    this.store.purgeExpired();
  }

  close(): void {
    this.store.close();
  }

  authorizationServerMetadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      registration_endpoint: `${this.issuer}/register`,
      revocation_endpoint: `${this.issuer}/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      revocation_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      scopes_supported: [OAUTH_SCOPE],
    };
  }

  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.resourceUrl,
      authorization_servers: [this.issuer],
      scopes_supported: [OAUTH_SCOPE],
      bearer_methods_supported: ["header"],
      resource_name: "NinjaOne MCP",
    };
  }

  /**
   * Serve the OAuth routes. Returns false when the path is not one of them,
   * so the caller carries on with /mcp, /health and the 404.
   */
  async handle(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
    const path = url.pathname;
    const method = req.method ?? "GET";
    try {
      if (method === "OPTIONS" && (path.startsWith("/.well-known/") || ["/token", "/register", "/revoke"].includes(path))) {
        res.writeHead(204, {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
          "Access-Control-Max-Age": "86400",
        });
        res.end();
        return true;
      }
      if (path.startsWith("/.well-known/oauth-authorization-server") || path.startsWith("/.well-known/openid-configuration")) {
        sendJson(res, 200, this.authorizationServerMetadata());
        return true;
      }
      if (path.startsWith("/.well-known/oauth-protected-resource")) {
        sendJson(res, 200, this.protectedResourceMetadata());
        return true;
      }
      if (path === "/authorize" && (method === "GET" || method === "POST")) {
        const params = method === "GET" ? url.searchParams : await readForm(req);
        this.authorize(params, res);
        return true;
      }
      if (path === NINJA_CALLBACK_PATH && method === "GET") {
        await this.ninjaCallback(url.searchParams, res);
        return true;
      }
      if (path === "/token" && method === "POST") {
        await this.token(req, res);
        return true;
      }
      if (path === "/register" && method === "POST") {
        await this.register(req, res);
        return true;
      }
      if (path === "/revoke" && method === "POST") {
        await this.revoke(req, res);
        return true;
      }
      return false;
    } catch (error) {
      if (error instanceof HttpError) {
        sendJson(res, error.status, { error: error.error, error_description: error.description });
      } else {
        logger.error("OAuth endpoint failed", { path, error: error instanceof Error ? error.message : String(error) });
        sendJson(res, 500, { error: "server_error", error_description: "Internal error" });
      }
      return true;
    }
  }

  /**
   * Check the Bearer token on a /mcp request. Writes the 401 challenge and
   * returns null when it is missing or not valid.
   */
  authenticate(req: IncomingMessage, res: ServerResponse): OAuthPrincipal | null {
    const header = req.headers.authorization ?? "";
    const match = /^Bearer\s+(.+)$/i.exec(header);
    const token = match?.[1]?.trim();
    const issued = token ? this.store.getToken(token) : null;
    const valid =
      issued !== null &&
      issued.kind === "access" &&
      issued.expiresAt > Date.now() &&
      (issued.resource === null || issued.resource.replace(/\/$/, "") === this.resourceUrl) &&
      this.store.getUser(issued.userId) !== null;
    if (!valid || !issued) {
      const params = [`resource_metadata="${this.resourceMetadataUrl}"`, `scope="${OAUTH_SCOPE}"`];
      if (token) params.push(`error="invalid_token"`);
      sendJson(
        res,
        401,
        { error: "invalid_token", error_description: token ? "The access token is not valid" : "Sign in required" },
        { "WWW-Authenticate": `Bearer ${params.join(", ")}` }
      );
      return null;
    }
    return {
      userId: issued.userId,
      clientId: issued.clientId,
      scopes: issued.scope.split(" ").filter(Boolean),
      expiresAt: Math.floor(issued.expiresAt / 1000),
    };
  }

  // --- /authorize ----------------------------------------------------------

  private authorize(params: URLSearchParams, res: ServerResponse): void {
    const clientId = params.get("client_id") ?? "";
    const client = clientId ? this.store.getClient(clientId) : null;
    if (!client) {
      sendPage(res, 400, "Onbekende toepassing", "Deze toepassing is niet bij deze server geregistreerd. Verbind de connector opnieuw.");
      return;
    }
    const redirectUri = params.get("redirect_uri") ?? (client.redirectUris.length === 1 ? client.redirectUris[0] : "");
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      sendPage(res, 400, "Ongeldige terugkeer-URL", "De redirect_uri van deze aanvraag is niet geregistreerd voor deze toepassing.");
      return;
    }
    // From here on errors go back to the client, as RFC 6749 4.1.2.1 asks.
    const clientState = params.get("state");
    const fail = (error: string, description: string) => {
      const target = new URL(redirectUri);
      target.searchParams.set("error", error);
      target.searchParams.set("error_description", description);
      if (clientState) target.searchParams.set("state", clientState);
      res.writeHead(302, { Location: target.toString(), "Cache-Control": "no-store" });
      res.end();
    };
    if (params.get("response_type") !== "code") {
      fail("unsupported_response_type", "Only response_type=code is supported");
      return;
    }
    const codeChallenge = params.get("code_challenge") ?? "";
    if (!codeChallenge || (params.get("code_challenge_method") ?? "plain") !== "S256") {
      fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
      return;
    }
    const requested = (params.get("scope") ?? OAUTH_SCOPE).split(" ").filter(Boolean);
    if (requested.some((s) => s !== OAUTH_SCOPE)) {
      fail("invalid_scope", `Only the scope "${OAUTH_SCOPE}" is supported`);
      return;
    }
    const state = randomToken();
    this.store.savePending({
      state,
      clientId,
      redirectUri,
      codeChallenge,
      clientState,
      scope: OAUTH_SCOPE,
      resource: params.get("resource"),
      createdAt: Date.now(),
    });
    res.writeHead(302, { Location: ninjaAuthorizeUrl(this.config.ninja, state), "Cache-Control": "no-store" });
    res.end();
  }

  private async ninjaCallback(params: URLSearchParams, res: ServerResponse): Promise<void> {
    const pending = this.store.takePending(params.get("state") ?? "");
    if (!pending || pending.createdAt < Date.now() - 15 * 60_000) {
      sendPage(res, 400, "Aanmelding verlopen", "Deze aanmelding is verlopen of al gebruikt. Start het verbinden opnieuw vanuit Claude of Copilot.");
      return;
    }
    const back = (query: Record<string, string>) => {
      const target = new URL(pending.redirectUri);
      for (const [key, value] of Object.entries(query)) target.searchParams.set(key, value);
      if (pending.clientState) target.searchParams.set("state", pending.clientState);
      res.writeHead(302, { Location: target.toString(), "Cache-Control": "no-store" });
      res.end();
    };

    const ninjaError = params.get("error");
    const code = params.get("code");
    if (ninjaError || !code) {
      back({ error: "access_denied", error_description: `NinjaOne sign-in did not complete (${ninjaError ?? "no code"})` });
      return;
    }

    let tokens;
    try {
      tokens = await exchangeNinjaCode(this.config.ninja, code);
    } catch (error) {
      logger.error("NinjaOne code exchange failed", {
        error: error instanceof Error ? error.message : String(error),
        body: (error as { body?: string }).body?.slice(0, 500),
      });
      sendPage(
        res,
        502,
        "Aanmelden bij NinjaOne mislukt",
        error instanceof Error && error.message.includes("refresh token")
          ? error.message
          : "NinjaOne weigerde de aanmelding. Controleer de Client ID, het secret en de redirect-URL van de NinjaOne-app."
      );
      return;
    }

    const userId = randomToken(16);
    this.store.saveUser(userId, tokens);
    const ourCode = randomToken();
    this.store.saveCode(ourCode, {
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      userId,
      scope: pending.scope,
      resource: pending.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    logger.info("NinjaOne sign-in completed", { clientId: pending.clientId });
    back({ code: ourCode });
  }

  // --- /token --------------------------------------------------------------

  /** Authenticate the client on /token and /revoke. Public clients only send client_id. */
  private authenticateClient(req: IncomingMessage, form: URLSearchParams): OAuthClient {
    let clientId = form.get("client_id") ?? "";
    let secret = form.get("client_secret");
    const basic = /^Basic\s+(.+)$/i.exec(req.headers.authorization ?? "");
    if (basic) {
      const decoded = Buffer.from(basic[1], "base64").toString("utf8");
      const colon = decoded.indexOf(":");
      if (colon > 0) {
        clientId = decodeURIComponent(decoded.slice(0, colon));
        secret = decodeURIComponent(decoded.slice(colon + 1));
      }
    }
    const client = clientId ? this.store.getClient(clientId) : null;
    if (!client) throw new HttpError(401, "invalid_client", "Unknown client");
    if (client.secretHash) {
      if (!secret || !safeEqual(sha256(secret), client.secretHash)) {
        throw new HttpError(401, "invalid_client", "Client authentication failed");
      }
    }
    return client;
  }

  private issueTokens(clientId: string, userId: string, scope: string, resource: string | null): Record<string, unknown> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const now = Date.now();
    this.store.saveToken(accessToken, {
      kind: "access",
      clientId,
      userId,
      scope,
      resource,
      expiresAt: now + this.config.accessTokenTtlMs,
    });
    this.store.saveToken(refreshToken, {
      kind: "refresh",
      clientId,
      userId,
      scope,
      resource,
      expiresAt: now + this.config.refreshTokenTtlMs,
    });
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(this.config.accessTokenTtlMs / 1000),
      refresh_token: refreshToken,
      scope,
    };
  }

  private async token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const form = await readForm(req);
    const client = this.authenticateClient(req, form);
    const grantType = form.get("grant_type");

    if (grantType === "authorization_code") {
      const code = this.store.takeCode(form.get("code") ?? "");
      if (!code || code.expiresAt < Date.now() || code.clientId !== client.clientId) {
        throw new HttpError(400, "invalid_grant", "The authorization code is not valid");
      }
      const redirectUri = form.get("redirect_uri");
      if (redirectUri && redirectUri !== code.redirectUri) {
        throw new HttpError(400, "invalid_grant", "redirect_uri does not match the authorization request");
      }
      const verifier = form.get("code_verifier") ?? "";
      if (!verifier || !safeEqual(pkceS256(verifier), code.codeChallenge)) {
        throw new HttpError(400, "invalid_grant", "PKCE verification failed");
      }
      sendJson(res, 200, this.issueTokens(client.clientId, code.userId, code.scope, code.resource));
      return;
    }

    if (grantType === "refresh_token") {
      const presented = form.get("refresh_token") ?? "";
      const issued = presented ? this.store.getToken(presented) : null;
      if (
        !issued ||
        issued.kind !== "refresh" ||
        issued.expiresAt < Date.now() ||
        issued.clientId !== client.clientId ||
        this.store.getUser(issued.userId) === null
      ) {
        throw new HttpError(400, "invalid_grant", "The refresh token is not valid");
      }
      // Rotate: the presented refresh token is spent.
      this.store.deleteToken(presented);
      sendJson(res, 200, this.issueTokens(client.clientId, issued.userId, issued.scope, issued.resource));
      return;
    }

    throw new HttpError(400, "unsupported_grant_type", "Only authorization_code and refresh_token are supported");
  }

  // --- /register (RFC 7591) ------------------------------------------------

  private async register(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let meta: Record<string, unknown>;
    try {
      meta = JSON.parse(await readBody(req)) as Record<string, unknown>;
    } catch {
      throw new HttpError(400, "invalid_client_metadata", "Body must be JSON");
    }
    const redirectUris = Array.isArray(meta.redirect_uris) ? meta.redirect_uris.filter((u) => typeof u === "string") : [];
    if (redirectUris.length === 0 || !redirectUris.every(isAllowedRedirectUri)) {
      throw new HttpError(400, "invalid_redirect_uri", "redirect_uris must be https URLs (or http on localhost)");
    }
    const method = typeof meta.token_endpoint_auth_method === "string" ? meta.token_endpoint_auth_method : "none";
    if (!["none", "client_secret_post", "client_secret_basic"].includes(method)) {
      throw new HttpError(400, "invalid_client_metadata", `token_endpoint_auth_method ${method} is not supported`);
    }
    const clientId = randomToken(16);
    const secret = method === "none" ? null : randomToken();
    const name = typeof meta.client_name === "string" ? meta.client_name.slice(0, 200) : "MCP client";
    this.store.saveClient({
      clientId,
      secretHash: secret ? sha256(secret) : null,
      redirectUris,
      name,
      authMethod: method as OAuthClient["authMethod"],
    });
    logger.info("OAuth client registered", { clientId, name });
    sendJson(res, 201, {
      client_id: clientId,
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: method,
      scope: OAUTH_SCOPE,
    });
  }

  // --- /revoke (RFC 7009) --------------------------------------------------

  private async revoke(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const form = await readForm(req);
    const client = this.authenticateClient(req, form);
    const token = form.get("token") ?? "";
    const issued = token ? this.store.getToken(token) : null;
    if (issued && issued.clientId === client.clientId) {
      this.store.deleteToken(token);
    }
    res.writeHead(200, { "Cache-Control": "no-store" });
    res.end();
  }
}

/**
 * Credentials for one /mcp request of a signed-in person: the deployment's
 * region, scopes and script policy (NINJAONE_* env, as in env mode), with the
 * person's own NinjaOne token instead of the client credentials grant.
 */
export function oauthCredentialsFor(
  server: OAuthServer,
  build: typeof import("../mcp-server.js").buildCredentials
): (authInfo: { extra?: Record<string, unknown> } | undefined) => NinjaOneCredentials | undefined {
  return (authInfo) => {
    const userId = authInfo?.extra?.userId;
    if (typeof userId !== "string") return undefined;
    const { creds } = build(
      process.env.NINJAONE_CLIENT_ID,
      process.env.NINJAONE_CLIENT_SECRET,
      process.env.NINJAONE_REGION
    );
    if (!creds) return undefined;
    return { ...creds, accessToken: (force) => server.sessions.getAccessToken(userId, force) };
  };
}
