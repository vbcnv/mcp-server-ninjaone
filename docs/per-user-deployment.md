# Per-user deployment (`AUTH_MODE=oauth`)

This fork adds one auth mode to upstream: every person who connects signs in
with **their own NinjaOne account**, and every tool call they make runs on
that person's own NinjaOne token. The server holds no API Services
(client credentials) token, so nothing runs as an anonymous "API app".

It works with Claude (custom connectors) and Microsoft 365 Copilot (custom
MCP connector), both over OAuth 2.1 with PKCE.

## How it works

```
client ──/authorize──▶ server ──302──▶ <region>.ninjarmm.com/ws/oauth/authorize   (NinjaOne sign-in)
NinjaOne ──302──▶ /oauth/ninja/callback?code=…   server redeems it for NinjaOne tokens
server ──302──▶ client redirect_uri?code=…
client ──/token──▶ access + refresh token (this server's own)
client ──/mcp, Bearer token──▶ tools run on that person's NinjaOne access token
```

- Towards Claude and Copilot the server is its own OAuth authorization server:
  `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`,
  `/authorize`, `/token`, `/register` (dynamic client registration), `/revoke`.
  Scope: `ninjaone`. PKCE `S256` is required.
- Towards NinjaOne it is a **Web** application using the authorization code
  grant with `offline_access`. The NinjaOne refresh token is stored
  AES-256-GCM-encrypted under `MCP_SECRET_KEY` in SQLite on the `/data`
  volume. Tokens this server issues are stored only as SHA-256 digests.
- The NinjaOne access token (about one hour) is refreshed with the stored
  refresh token when it is close to expiry, or after NinjaOne answers 401.
  When NinjaOne refuses the refresh token (revoked, user disabled), the person
  and all their tokens are forgotten and the client is sent back to sign in.
  A NinjaOne outage does not sign anyone out.
- The SDK (`@wyre-ai/node-ninjaone`) only implements client credentials, so in
  this mode `createClientDirect` points that one client instance's token
  manager at the person's token (`src/utils/client.ts`).
- `CONDUIT_S2S_SECRET` and the `X-Ninja-*` headers are not used: the Bearer
  token is the caller check. `ninjaone_scripts_run` treats the signed-in person
  as the caller and still only runs scripts in `NINJAONE_ALLOWED_SCRIPT_IDS`
  (empty = none).

## 1. Create the NinjaOne application

Only a NinjaOne system administrator can do this.

NinjaOne → Administration → Apps → API → Client App IDs → **Add client app**:

1. Application platform: **Web** (not "API Services").
2. Name: `NinjaOne MCP`.
3. Redirect URI: `https://<host>/oauth/ninja/callback`, exactly.
4. Scopes: **Monitoring** and **Management** (add **Control** only if you want
   remote script runs, and set `NINJAONE_SCOPES=monitoring,management,control`).
5. Allowed grant types: **Authorization Code** and **Refresh Token**. Without
   Refresh Token the sign-in fails with a message saying so.
6. Save, then copy the Client ID and the Client Secret (shown only once).

## 2. Deploy with Portainer + Traefik

1. Create a stack from this repository (git), compose path `docker-compose.vbc.yml`.
2. Environment variables (see the `AUTH_MODE=oauth` part of `.env.example`):
   - `SUBDOMAIN`, `DOMAIN_NAME` for the Traefik host rule
   - `MCP_PUBLIC_URL=https://<subdomain>.<domain>` (no `/mcp`)
   - `MCP_SECRET_KEY` from `openssl rand -hex 32`
   - `NINJAONE_CLIENT_ID`, `NINJAONE_CLIENT_SECRET` from step 1
   - `NINJAONE_REGION` (`eu` for eu.ninjarmm.com)
   - `GITHUB_TOKEN`: a GitHub personal access token with only `read:packages`.
     The NinjaOne SDK is published on GitHub Packages, which has no anonymous
     reads. It is passed as a build argument only, not into the container.
3. Deploy, then check:

   ```bash
   curl -s https://ninjaone.example.com/health                                    # {"status":"ok"}
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://ninjaone.example.com/mcp   # 401
   ```

   A `401` on `/mcp` is the point: nothing is reachable without signing in.

## 3. Connect Claude

Settings → Connectors → Add custom connector, URL `https://<host>/mcp`.
Claude registers itself and opens the NinjaOne sign-in.

## 4. Connect Microsoft 365 Copilot

Copilot does not register dynamically, so configure a fixed client:

1. Teams Developer Portal → Tools → OAuth client registration:
   - Authorization endpoint `https://<host>/authorize`
   - Token and refresh endpoint `https://<host>/token`
   - Scope `ninjaone`, PKCE enabled
   - Client ID and secret: pick them yourself (secret: `openssl rand -hex 32`)
2. Put the same values in the stack:

   ```
   MCP_OAUTH_CLIENT_ID=m365-copilot
   MCP_OAUTH_CLIENT_SECRET=<the secret>
   MCP_OAUTH_CLIENT_REDIRECT_URIS=https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect
   ```

   If the token exchange fails with `invalid_client`, set
   `MCP_OAUTH_CLIENT_AUTH_METHOD=client_secret_basic`.
3. Microsoft 365 admin center → Copilot → Connectors → create a connector for
   an MCP server, URL `https://<host>/mcp`, with the OAuth registration ID
   from step 1.

## What a signed-in person can do

Every call runs on the token NinjaOne issued to that person, so NinjaOne
decides what it may see and change. The app's scopes are the ceiling for
everyone (Monitoring = read, Management = changes, Control = remote access).
Test once with a technician whose role is restricted to check that NinjaOne
applies that role to API calls as well.
