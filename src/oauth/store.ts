/**
 * Persistent state for AUTH_MODE=oauth (fork-only).
 *
 * One SQLite file on the /data volume holds the OAuth clients that registered
 * with this server, the short-lived authorization state, the tokens this
 * server issued (as SHA-256 digests only) and, per signed-in person, their
 * NinjaOne tokens encrypted with AES-256-GCM under MCP_SECRET_KEY.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export interface OAuthClient {
  clientId: string;
  /** SHA-256 of the secret; null for public (PKCE-only) clients. */
  secretHash: string | null;
  redirectUris: string[];
  name: string;
  authMethod: "none" | "client_secret_post" | "client_secret_basic";
}

export interface PendingAuthorization {
  state: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  clientState: string | null;
  scope: string;
  resource: string | null;
  createdAt: number;
}

export interface AuthorizationCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  userId: string;
  scope: string;
  resource: string | null;
  expiresAt: number;
}

export interface IssuedToken {
  kind: "access" | "refresh";
  clientId: string;
  userId: string;
  scope: string;
  resource: string | null;
  expiresAt: number;
}

export interface NinjaTokens {
  refreshToken: string;
  accessToken: string | null;
  /** Epoch milliseconds. */
  accessExpiresAt: number;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** AES-256-GCM with a key derived from MCP_SECRET_KEY: base64url(iv | tag | ciphertext). */
export class Sealer {
  private readonly key: Buffer;

  constructor(secret: string) {
    this.key = createHash("sha256").update(`ninjaone-mcp:${secret}`).digest();
  }

  seal(plain: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
  }

  open(sealed: string): string {
    const raw = Buffer.from(sealed, "base64url");
    const decipher = createDecipheriv("aes-256-gcm", this.key, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
  }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  name TEXT NOT NULL,
  auth_method TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending (
  state TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  client_state TEXT,
  scope TEXT NOT NULL,
  resource TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  ninja_tokens TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens(user_id);
`;

type Row = Record<string, unknown>;

export class OAuthStore {
  private readonly db: DatabaseSync;
  private readonly sealer: Sealer;

  constructor(path: string, secret: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(SCHEMA);
    this.sealer = new Sealer(secret);
  }

  close(): void {
    this.db.close();
  }

  /** Drop expired codes, tokens and authorization state. */
  purgeExpired(now = Date.now()): void {
    this.db.prepare("DELETE FROM codes WHERE expires_at < ?").run(now);
    this.db.prepare("DELETE FROM tokens WHERE expires_at < ?").run(now);
    this.db.prepare("DELETE FROM pending WHERE created_at < ?").run(now - 15 * 60_000);
    // A person whose last token is gone can never come back to that row.
    this.db
      .prepare("DELETE FROM users WHERE user_id NOT IN (SELECT DISTINCT user_id FROM tokens) AND created_at < ?")
      .run(now - 15 * 60_000);
  }

  // --- clients -------------------------------------------------------------

  saveClient(client: OAuthClient): void {
    this.db
      .prepare(
        `INSERT INTO clients (client_id, secret_hash, redirect_uris, name, auth_method, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET secret_hash = excluded.secret_hash,
           redirect_uris = excluded.redirect_uris, name = excluded.name, auth_method = excluded.auth_method`
      )
      .run(
        client.clientId,
        client.secretHash,
        JSON.stringify(client.redirectUris),
        client.name,
        client.authMethod,
        Date.now()
      );
  }

  getClient(clientId: string): OAuthClient | null {
    const row = this.db.prepare("SELECT * FROM clients WHERE client_id = ?").get(clientId) as Row | undefined;
    if (!row) return null;
    return {
      clientId: String(row.client_id),
      secretHash: row.secret_hash == null ? null : String(row.secret_hash),
      redirectUris: JSON.parse(String(row.redirect_uris)) as string[],
      name: String(row.name),
      authMethod: String(row.auth_method) as OAuthClient["authMethod"],
    };
  }

  // --- authorization state -------------------------------------------------

  savePending(p: PendingAuthorization): void {
    this.db
      .prepare(
        `INSERT INTO pending (state, client_id, redirect_uri, code_challenge, client_state, scope, resource, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(p.state, p.clientId, p.redirectUri, p.codeChallenge, p.clientState, p.scope, p.resource, p.createdAt);
  }

  /** Read and delete: a NinjaOne callback state is single use. */
  takePending(state: string): PendingAuthorization | null {
    const row = this.db.prepare("SELECT * FROM pending WHERE state = ?").get(state) as Row | undefined;
    if (!row) return null;
    this.db.prepare("DELETE FROM pending WHERE state = ?").run(state);
    return {
      state: String(row.state),
      clientId: String(row.client_id),
      redirectUri: String(row.redirect_uri),
      codeChallenge: String(row.code_challenge),
      clientState: row.client_state == null ? null : String(row.client_state),
      scope: String(row.scope),
      resource: row.resource == null ? null : String(row.resource),
      createdAt: Number(row.created_at),
    };
  }

  saveCode(code: string, c: AuthorizationCode): void {
    this.db
      .prepare(
        `INSERT INTO codes (code_hash, client_id, redirect_uri, code_challenge, user_id, scope, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(sha256(code), c.clientId, c.redirectUri, c.codeChallenge, c.userId, c.scope, c.resource, c.expiresAt);
  }

  /** Read and delete: an authorization code is single use. */
  takeCode(code: string): AuthorizationCode | null {
    const hash = sha256(code);
    const row = this.db.prepare("SELECT * FROM codes WHERE code_hash = ?").get(hash) as Row | undefined;
    if (!row) return null;
    this.db.prepare("DELETE FROM codes WHERE code_hash = ?").run(hash);
    return {
      clientId: String(row.client_id),
      redirectUri: String(row.redirect_uri),
      codeChallenge: String(row.code_challenge),
      userId: String(row.user_id),
      scope: String(row.scope),
      resource: row.resource == null ? null : String(row.resource),
      expiresAt: Number(row.expires_at),
    };
  }

  // --- issued tokens -------------------------------------------------------

  saveToken(token: string, t: IssuedToken): void {
    this.db
      .prepare(
        `INSERT INTO tokens (token_hash, kind, client_id, user_id, scope, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(sha256(token), t.kind, t.clientId, t.userId, t.scope, t.resource, t.expiresAt);
  }

  getToken(token: string): IssuedToken | null {
    const row = this.db.prepare("SELECT * FROM tokens WHERE token_hash = ?").get(sha256(token)) as
      | Row
      | undefined;
    if (!row) return null;
    return {
      kind: String(row.kind) as IssuedToken["kind"],
      clientId: String(row.client_id),
      userId: String(row.user_id),
      scope: String(row.scope),
      resource: row.resource == null ? null : String(row.resource),
      expiresAt: Number(row.expires_at),
    };
  }

  deleteToken(token: string): void {
    this.db.prepare("DELETE FROM tokens WHERE token_hash = ?").run(sha256(token));
  }

  // --- people --------------------------------------------------------------

  saveUser(userId: string, tokens: NinjaTokens): void {
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO users (user_id, ninja_tokens, created_at, last_seen) VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET ninja_tokens = excluded.ninja_tokens, last_seen = excluded.last_seen`
      )
      .run(userId, this.sealer.seal(JSON.stringify(tokens)), now, now);
  }

  getUser(userId: string): NinjaTokens | null {
    const row = this.db.prepare("SELECT ninja_tokens FROM users WHERE user_id = ?").get(userId) as
      | Row
      | undefined;
    if (!row) return null;
    try {
      return JSON.parse(this.sealer.open(String(row.ninja_tokens))) as NinjaTokens;
    } catch {
      // Sealed under another MCP_SECRET_KEY: unusable, so the person signs in again.
      return null;
    }
  }

  /** Forget a person and every token issued to them. */
  deleteUser(userId: string): void {
    this.db.prepare("DELETE FROM tokens WHERE user_id = ?").run(userId);
    this.db.prepare("DELETE FROM codes WHERE user_id = ?").run(userId);
    this.db.prepare("DELETE FROM users WHERE user_id = ?").run(userId);
  }
}
