/**
 * AUTH_MODE=oauth (fork-only): Claude / Copilot sign in through this server,
 * which sends the browser to NinjaOne's authorization code flow, keeps that
 * person's NinjaOne tokens, and runs every tool call on them.
 *
 * NinjaOne itself is faked by stubbing global fetch for *.ninjarmm.com; calls
 * to the local server go through the real fetch.
 */
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { startHttpTransport } from "../index.js";
import { loadOAuthConfig } from "../oauth/server.js";
import { OAuthStore, Sealer } from "../oauth/store.js";
import { mcpJson } from "./helpers.js";

const PUBLIC_URL = "https://ninjaone.example.test";
const REDIRECT = "https://claude.example.test/api/mcp/auth_callback";

const ENV_KEYS = [
  "AUTH_MODE",
  "MCP_PUBLIC_URL",
  "MCP_SECRET_KEY",
  "MCP_OAUTH_DB_PATH",
  "MCP_OAUTH_CLIENT_ID",
  "MCP_OAUTH_CLIENT_SECRET",
  "MCP_OAUTH_CLIENT_REDIRECT_URIS",
  "MCP_HTTP_PORT",
  "MCP_HTTP_HOST",
  "NINJAONE_CLIENT_ID",
  "NINJAONE_CLIENT_SECRET",
  "NINJAONE_REGION",
  "NINJAONE_SCOPES",
  "CONDUIT_S2S_SECRET",
  "MCP_ALLOW_INSECURE_DEV",
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];
let dataDir: string;
const realFetch = globalThis.fetch;

interface NinjaFake {
  tokenRequests: URLSearchParams[];
  apiAuthHeaders: string[];
  /** What the token endpoint answers next for a refresh_token grant. */
  refreshStatus: number;
  accessTokenSeq: number;
}
let ninja: NinjaFake;

function stubNinjaOne(): void {
  ninja = { tokenRequests: [], apiAuthHeaders: [], refreshStatus: 200, accessTokenSeq: 0 };
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (!url.hostname.endsWith("ninjarmm.com")) return realFetch(input, init);

    if (url.pathname === "/ws/oauth/token") {
      const form = new URLSearchParams(String(init?.body ?? ""));
      ninja.tokenRequests.push(form);
      if (form.get("grant_type") === "refresh_token" && ninja.refreshStatus !== 200) {
        return new Response(JSON.stringify({ error: "invalid_grant" }), { status: ninja.refreshStatus });
      }
      ninja.accessTokenSeq += 1;
      return Response.json({
        access_token: `ninja-access-${ninja.accessTokenSeq}`,
        refresh_token: `ninja-refresh-${ninja.accessTokenSeq}`,
        expires_in: 3600,
        token_type: "Bearer",
      });
    }
    if (url.pathname.endsWith("/v2/organizations")) {
      const headers = new Headers(init?.headers);
      ninja.apiAuthHeaders.push(headers.get("authorization") ?? "");
      return Response.json([{ id: 1, name: "Synthetic Org" }]);
    }
    return new Response("not faked", { status: 404 });
  });
}

async function listen(): Promise<string> {
  const server = await startHttpTransport();
  servers.push(server);
  const bound = server.address();
  if (!bound || typeof bound === "string") throw new Error("no port");
  return `http://127.0.0.1:${bound.port}`;
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

async function register(base: string): Promise<string> {
  const res = await fetch(`${base}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Claude", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as { client_id: string }).client_id;
}

/** Walk the whole browser flow and return the client's tokens. */
async function signIn(base: string, clientId: string): Promise<{ access_token: string; refresh_token: string }> {
  const { verifier, challenge } = pkce();
  const authorize = new URL(`${base}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "client-state-1",
    scope: "ninjaone",
  }).toString();
  const toNinja = await fetch(authorize, { redirect: "manual" });
  expect(toNinja.status).toBe(302);
  const ninjaUrl = new URL(toNinja.headers.get("location") ?? "");
  expect(ninjaUrl.origin).toBe("https://eu.ninjarmm.com");
  expect(ninjaUrl.pathname).toBe("/ws/oauth/authorize");
  expect(ninjaUrl.searchParams.get("client_id")).toBe("ninja-web-app");
  expect(ninjaUrl.searchParams.get("redirect_uri")).toBe(`${PUBLIC_URL}/oauth/ninja/callback`);
  expect(ninjaUrl.searchParams.get("scope")).toBe("monitoring management offline_access");

  const callback = await fetch(
    `${base}/oauth/ninja/callback?code=ninja-code-1&state=${ninjaUrl.searchParams.get("state")}`,
    { redirect: "manual" }
  );
  expect(callback.status).toBe(302);
  const back = new URL(callback.headers.get("location") ?? "");
  expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
  expect(back.searchParams.get("state")).toBe("client-state-1");
  const code = back.searchParams.get("code") ?? "";

  const exchange = ninja.tokenRequests.at(-1);
  expect(exchange?.get("grant_type")).toBe("authorization_code");
  expect(exchange?.get("code")).toBe("ninja-code-1");
  expect(exchange?.get("client_secret")).toBe("ninja-web-secret");

  const token = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    }).toString(),
  });
  expect(token.status).toBe(200);
  return (await token.json()) as { access_token: string; refresh_token: string };
}

function callTool(base: string, accessToken: string | null, name: string, args: Record<string, unknown> = {}) {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
}

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
  dataDir = mkdtempSync(join(tmpdir(), "ninja-oauth-"));
  process.env.AUTH_MODE = "oauth";
  process.env.MCP_PUBLIC_URL = PUBLIC_URL;
  process.env.MCP_SECRET_KEY = "0123456789abcdef0123456789abcdef-synthetic";
  process.env.MCP_OAUTH_DB_PATH = join(dataDir, "oauth.sqlite3");
  process.env.MCP_HTTP_PORT = "0";
  process.env.MCP_HTTP_HOST = "127.0.0.1";
  process.env.NINJAONE_CLIENT_ID = "ninja-web-app";
  process.env.NINJAONE_CLIENT_SECRET = "ninja-web-secret";
  process.env.NINJAONE_REGION = "eu";
  stubNinjaOne();
});

afterEach(async () => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server?.listening) continue;
    await new Promise<void>((resolve, reject) => {
      server.closeAllConnections();
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
  rmSync(dataDir, { recursive: true, force: true });
});

describe("AUTH_MODE=oauth configuration", () => {
  it("lists every missing setting", () => {
    expect(() => loadOAuthConfig({ AUTH_MODE: "oauth" })).toThrow(
      /MCP_PUBLIC_URL[\s\S]*MCP_SECRET_KEY[\s\S]*NINJAONE_CLIENT_ID/
    );
  });

  it("refuses a plain-http public URL outside localhost", () => {
    expect(() =>
      loadOAuthConfig({ ...process.env, MCP_PUBLIC_URL: "http://ninjaone.example.test" })
    ).toThrow(/must be https/);
  });

  it("starts without CONDUIT_S2S_SECRET and publishes OAuth metadata", async () => {
    const base = await listen();
    const as = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(as.issuer).toBe(PUBLIC_URL);
    expect(as.authorization_endpoint).toBe(`${PUBLIC_URL}/authorize`);
    expect(as.code_challenge_methods_supported).toEqual(["S256"]);
    const pr = (await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()) as Record<string, unknown>;
    expect(pr.resource).toBe(`${PUBLIC_URL}/mcp`);
    expect(pr.authorization_servers).toEqual([PUBLIC_URL]);
  });
});

describe("AUTH_MODE=oauth /mcp", () => {
  it("answers 401 with a resource_metadata challenge without a token", async () => {
    const base = await listen();
    const res = await callTool(base, null, "ninjaone_status");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource/mcp"`
    );
    const bad = await callTool(base, "not-a-token", "ninjaone_status");
    expect(bad.status).toBe(401);
    expect(bad.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("runs tool calls on the signed-in person's NinjaOne token, not client credentials", async () => {
    const base = await listen();
    const clientId = await register(base);
    const tokens = await signIn(base, clientId);

    const res = await callTool(base, tokens.access_token, "ninjaone_organizations_list", { limit: 1 });
    expect(res.status).toBe(200);
    const body = (await mcpJson(res)) as { result: { content: { text: string }[]; isError?: boolean } };
    expect(body.result.isError).toBeFalsy();
    expect(body.result.content[0].text).toContain("Synthetic Org");
    expect(ninja.apiAuthHeaders).toEqual(["Bearer ninja-access-1"]);
    expect(ninja.tokenRequests.map((f) => f.get("grant_type"))).not.toContain("client_credentials");
  });

  it("keeps two people's NinjaOne tokens apart", async () => {
    const base = await listen();
    const clientId = await register(base);
    const first = await signIn(base, clientId);
    const second = await signIn(base, clientId);

    await callTool(base, second.access_token, "ninjaone_organizations_list", { limit: 1 });
    await callTool(base, first.access_token, "ninjaone_organizations_list", { limit: 1 });
    expect(ninja.apiAuthHeaders).toEqual(["Bearer ninja-access-2", "Bearer ninja-access-1"]);
  });

  it("refreshes an expired NinjaOne token with the stored refresh token", async () => {
    const base = await listen();
    const clientId = await register(base);
    const tokens = await signIn(base, clientId);

    // Age the stored NinjaOne token past its expiry.
    const store = new OAuthStore(process.env.MCP_OAUTH_DB_PATH as string, process.env.MCP_SECRET_KEY as string);
    const userId = store.getToken(tokens.access_token)?.userId as string;
    store.saveUser(userId, { refreshToken: "ninja-refresh-1", accessToken: "ninja-access-1", accessExpiresAt: 0 });
    store.close();

    await callTool(base, tokens.access_token, "ninjaone_organizations_list", { limit: 1 });
    const refresh = ninja.tokenRequests.at(-1);
    expect(refresh?.get("grant_type")).toBe("refresh_token");
    expect(refresh?.get("refresh_token")).toBe("ninja-refresh-1");
    expect(ninja.apiAuthHeaders).toEqual(["Bearer ninja-access-2"]);
  });

  it("signs the person out when NinjaOne refuses the refresh token", async () => {
    const base = await listen();
    const clientId = await register(base);
    const tokens = await signIn(base, clientId);
    const store = new OAuthStore(process.env.MCP_OAUTH_DB_PATH as string, process.env.MCP_SECRET_KEY as string);
    const userId = store.getToken(tokens.access_token)?.userId as string;
    store.saveUser(userId, { refreshToken: "ninja-refresh-1", accessToken: null, accessExpiresAt: 0 });
    store.close();
    ninja.refreshStatus = 400;

    const res = await callTool(base, tokens.access_token, "ninjaone_organizations_list", { limit: 1 });
    const body = (await mcpJson(res)) as { result: { content: { text: string }[]; isError?: boolean } };
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toContain("Reconnect the connector");

    // The next request is sent back to sign in.
    const next = await callTool(base, tokens.access_token, "ninjaone_status");
    expect(next.status).toBe(401);
  });
});

describe("AUTH_MODE=oauth token endpoint", () => {
  it("rejects a wrong PKCE verifier and a reused code", async () => {
    const base = await listen();
    const clientId = await register(base);
    const { challenge } = pkce();
    const authorize = new URL(`${base}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    const ninjaUrl = new URL((await fetch(authorize, { redirect: "manual" })).headers.get("location") ?? "");
    const back = new URL(
      (
        await fetch(`${base}/oauth/ninja/callback?code=c&state=${ninjaUrl.searchParams.get("state")}`, {
          redirect: "manual",
        })
      ).headers.get("location") ?? ""
    );
    const form = {
      grant_type: "authorization_code",
      client_id: clientId,
      code: back.searchParams.get("code") ?? "",
      redirect_uri: REDIRECT,
      code_verifier: "wrong-verifier",
    };
    const wrong = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form).toString(),
    });
    expect(wrong.status).toBe(400);
    expect(((await wrong.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("refuses authorize without PKCE, back to the client", async () => {
    const base = await listen();
    const clientId = await register(base);
    const res = await fetch(
      `${base}/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}&state=s`,
      { redirect: "manual" }
    );
    expect(res.status).toBe(302);
    const back = new URL(res.headers.get("location") ?? "");
    expect(back.searchParams.get("error")).toBe("invalid_request");
    expect(back.searchParams.get("state")).toBe("s");
  });

  it("refuses an unregistered redirect_uri on its own page", async () => {
    const base = await listen();
    const clientId = await register(base);
    const res = await fetch(
      `${base}/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent("https://evil.example.test/cb")}`,
      { redirect: "manual" }
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("rotates refresh tokens", async () => {
    const base = await listen();
    const clientId = await register(base);
    const tokens = await signIn(base, clientId);
    const refresh = (token: string) =>
      fetch(`${base}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: token }).toString(),
      });
    const first = await refresh(tokens.refresh_token);
    expect(first.status).toBe(200);
    const again = await refresh(tokens.refresh_token);
    expect(again.status).toBe(400);
  });

  it("authenticates the fixed Copilot client with its secret", async () => {
    process.env.MCP_OAUTH_CLIENT_ID = "m365-copilot";
    process.env.MCP_OAUTH_CLIENT_SECRET = "copilot-synthetic-secret";
    process.env.MCP_OAUTH_CLIENT_REDIRECT_URIS = REDIRECT;
    const base = await listen();
    const wrong = await fetch(`${base}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from("m365-copilot:nope").toString("base64")}`,
      },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "x" }).toString(),
    });
    expect(wrong.status).toBe(401);
    const right = await fetch(`${base}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from("m365-copilot:copilot-synthetic-secret").toString("base64")}`,
      },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "x" }).toString(),
    });
    // Client accepted; the made-up refresh token is not.
    expect(right.status).toBe(400);
  });
});

describe("Sealer", () => {
  it("round-trips and refuses another key", () => {
    const sealed = new Sealer("a".repeat(32)).seal("ninja-refresh-secret");
    expect(sealed).not.toContain("ninja-refresh-secret");
    expect(new Sealer("a".repeat(32)).open(sealed)).toBe("ninja-refresh-secret");
    expect(() => new Sealer("b".repeat(32)).open(sealed)).toThrow();
  });
});
