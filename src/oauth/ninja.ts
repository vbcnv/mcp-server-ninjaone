/**
 * NinjaOne side of AUTH_MODE=oauth (fork-only): the authorization code flow
 * against a NinjaOne "Web" application, and keeping each person's NinjaOne
 * access token fresh with their refresh token.
 */
import type { NinjaTokens, OAuthStore } from "./store.js";
import { logger } from "../utils/logger.js";

/** Refresh this long before NinjaOne's expiry, like the SDK does. */
const EXPIRY_BUFFER_MS = 2 * 60_000;

export interface NinjaAppConfig {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  /** NinjaOne API scopes, without offline_access (always added). */
  scopes: string[];
  redirectUri: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

/** NinjaOne refused the refresh token: the person has to sign in again. */
export class NinjaSessionExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NinjaSessionExpiredError";
  }
}

/** NinjaOne answered with an OAuth error. */
export class NinjaTokenError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string
  ) {
    super(message);
    this.name = "NinjaTokenError";
  }
}

export function ninjaAuthorizeUrl(app: NinjaAppConfig, state: string): string {
  const url = new URL(`${app.baseUrl}/ws/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", app.clientId);
  url.searchParams.set("redirect_uri", app.redirectUri);
  url.searchParams.set("scope", [...app.scopes, "offline_access"].join(" "));
  url.searchParams.set("state", state);
  return url.toString();
}

async function postToken(app: NinjaAppConfig, params: Record<string, string>): Promise<TokenResponse> {
  const response = await fetch(`${app.baseUrl}/ws/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      client_id: app.clientId,
      client_secret: app.clientSecret,
      ...params,
    }).toString(),
  });
  const body = await response.text();
  if (!response.ok) {
    throw new NinjaTokenError(`NinjaOne token endpoint answered ${response.status}`, response.status, body);
  }
  const data = JSON.parse(body) as TokenResponse;
  if (!data.access_token) {
    throw new NinjaTokenError("NinjaOne token response has no access_token", response.status, body);
  }
  return data;
}

function toTokens(data: TokenResponse, previousRefresh?: string): NinjaTokens {
  const refreshToken = data.refresh_token ?? previousRefresh;
  if (!refreshToken) {
    throw new NinjaTokenError(
      "NinjaOne issued no refresh token. Enable the Refresh Token grant on the NinjaOne app " +
        "(Administration > Apps > API) so sign-ins survive the one-hour access token.",
      200,
      ""
    );
  }
  return {
    refreshToken,
    accessToken: data.access_token,
    accessExpiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
  };
}

export async function exchangeNinjaCode(app: NinjaAppConfig, code: string): Promise<NinjaTokens> {
  const data = await postToken(app, {
    grant_type: "authorization_code",
    code,
    redirect_uri: app.redirectUri,
  });
  return toTokens(data);
}

/**
 * Hands out a valid NinjaOne access token per person. Refreshes are
 * serialised per person, because NinjaOne may rotate the refresh token and
 * two concurrent refreshes would race on the stored one.
 */
export class NinjaSessions {
  private readonly inFlight = new Map<string, Promise<string>>();

  constructor(
    private readonly app: NinjaAppConfig,
    private readonly store: OAuthStore
  ) {}

  async getAccessToken(userId: string, forceRefresh = false): Promise<string> {
    const tokens = this.store.getUser(userId);
    if (!tokens) {
      throw new NinjaSessionExpiredError("This NinjaOne sign-in is no longer known. Reconnect the connector.");
    }
    if (!forceRefresh && tokens.accessToken && Date.now() < tokens.accessExpiresAt - EXPIRY_BUFFER_MS) {
      return tokens.accessToken;
    }
    const running = this.inFlight.get(userId);
    if (running) return running;

    const refresh = this.refresh(userId, tokens).finally(() => this.inFlight.delete(userId));
    this.inFlight.set(userId, refresh);
    return refresh;
  }

  private async refresh(userId: string, tokens: NinjaTokens): Promise<string> {
    let data: TokenResponse;
    try {
      data = await postToken(this.app, { grant_type: "refresh_token", refresh_token: tokens.refreshToken });
    } catch (error) {
      // 400/401 is NinjaOne refusing the refresh token (revoked, expired, user
      // disabled): forget the person so their next request is sent to sign in.
      // Anything else (outage, 5xx) leaves the sign-in alone.
      if (error instanceof NinjaTokenError && (error.status === 400 || error.status === 401)) {
        logger.warn("NinjaOne refused a refresh token; signing the user out", { status: error.status });
        this.store.deleteUser(userId);
        throw new NinjaSessionExpiredError(
          "NinjaOne no longer accepts this sign-in. Reconnect the connector to sign in again."
        );
      }
      throw error;
    }
    const next = toTokens(data, tokens.refreshToken);
    this.store.saveUser(userId, next);
    return next.accessToken as string;
  }
}
