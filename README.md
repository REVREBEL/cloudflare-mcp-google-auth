# Google Calendar MCP OAuth Proxy

This Worker acts as the OAuth boundary between an MCP client such as Codex and Google's official Calendar MCP.

```text
Codex / MCP client
        |
        | OAuth to this Worker
        v
Cloudflare OAuth Provider
        |
        | Google OAuth (client ID + client secret)
        v
Google OAuth
        |
        | Google access token
        v
Google Calendar MCP
https://calendarmcp.googleapis.com/mcp/v1
```

The client never receives the Google OAuth client secret. Google access and refresh tokens are stored in the encrypted OAuth grant props managed by the Cloudflare OAuth provider. The protected `/mcp` handler replaces the client's local bearer token with the user's Google access token before forwarding MCP traffic upstream.

## Google scopes

`wrangler.jsonc` defines the Google Calendar scopes in `GOOGLE_OAUTH_SCOPES`:

```text
https://www.googleapis.com/auth/calendar.calendarlist.readonly
https://www.googleapis.com/auth/calendar.events.freebusy
https://www.googleapis.com/auth/calendar.events.readonly
https://www.googleapis.com/auth/calendar.calendars
```

The Worker automatically adds `email profile` because the callback uses Google's user-info endpoint to identify the authorized user.

The Google authorization request also uses `access_type=offline` and `prompt=consent` so Google returns a refresh token.

## Local secrets

Copy the example file:

```bash
cp .dev.vars.example .dev.vars
```

Set:

```text
GOOGLE_CLIENT_ID=<Google OAuth web client ID>
GOOGLE_CLIENT_SECRET=<Google OAuth client secret>
COOKIE_ENCRYPTION_KEY=<strong random secret>
HOSTED_DOMAIN=<optional Google Workspace domain restriction>
```

`GOOGLE_OAUTH_SCOPES` and `GOOGLE_MCP_URL` are non-secret Worker variables in `wrangler.jsonc`.

## Google Cloud OAuth client

Use a Google OAuth **Web application** client.

The authorized redirect URI must be the public hostname of this Worker or tunnel plus `/callback`:

```text
https://mcp-auth.example.com/callback
```

Add the Calendar scopes listed above to the Google Auth Platform consent/data-access configuration.

## Run locally

Install dependencies and generate Worker types:

```bash
npm install
npm run cf-typegen
```

Start Wrangler locally on port `5555`:

```bash
npm run dev
```

The local endpoint is:

```text
http://localhost:5555/mcp
```

OAuth requires a public HTTPS callback, so for end-to-end local testing use a Cloudflare Tunnel.

### Stable named tunnel

A stable hostname is preferable because the same callback must be registered in Google Cloud.

```bash
npx wrangler dev --tunnel-name=mcp-google-auth --tunnel
```

Configure the named tunnel hostname to route to the Wrangler development server. For example:

```text
https://mcp-auth.example.com  ->  local Wrangler dev server
```

Then register:

```text
https://mcp-auth.example.com/callback
```

as the Google OAuth redirect URI.

The MCP URL exposed to Codex is:

```text
https://mcp-auth.example.com/mcp
```

## Codex configuration

Because this Worker is the OAuth authorization server seen by Codex, Codex does not need the Google client ID or Google client secret.

```toml
[mcp_servers.google_calendar_proxy]
enabled = true
url = "https://mcp-auth.example.com/mcp"
auth = "oauth"
```

Then authenticate:

```bash
codex mcp login google_calendar_proxy
```

The expected flow is:

1. Codex discovers this Worker's OAuth endpoints.
2. Codex registers/authenticates with this Worker.
3. The Worker sends the browser to Google.
4. Google returns to `/callback` on the Worker/tunnel.
5. The Worker exchanges Google's authorization code using `GOOGLE_CLIENT_SECRET`.
6. Codex receives a Worker-issued OAuth token.
7. Calls to `/mcp` are forwarded to Google's official Calendar MCP using the user's Google access token.

## Token refresh behavior

Google's refresh token is retained in encrypted OAuth grant props. The proxy keeps a short-lived in-memory cache of refreshed Google access tokens. If the stored access token is expired, or Google's MCP returns `401`, the Worker uses the Google refresh token plus the Worker-side client secret to mint a new Google access token and retries once.

The in-memory cache is an optimization only. A new Worker isolate can always refresh from the encrypted grant props.
