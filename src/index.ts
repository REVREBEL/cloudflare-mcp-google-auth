import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { WorkerEntrypoint } from "cloudflare:workers";
import { z } from "zod";
import { GoogleHandler } from "./google-handler";
import { refreshGoogleAccessToken, type Props } from "./utils";

const TOKEN_REFRESH_SKEW_MS = 60_000;
const GOOGLE_TOKEN_CACHE_MAX_ENTRIES = 100;

type CachedGoogleToken = {
	accessToken: string;
	expiresAt: number;
};

class ReauthorizationRequiredError extends Error {
	constructor(message = "Google authorization must be renewed") {
		super(message);
		this.name = "ReauthorizationRequiredError";
	}
}

// This cache is an optimization only. The refresh token remains encrypted in OAuth props,
// so a new Worker isolate can always mint a fresh Google access token when needed.
// Entries are bounded and evicted when expired to avoid retaining plaintext tokens indefinitely.
const googleAccessTokenCache = new Map<string, CachedGoogleToken>();

function hasRefreshMetadata(
	props: Props,
): props is Props & Required<Pick<Props, "googleUserId" | "refreshToken" | "accessTokenExpiresAt">> {
	return Boolean(
		props.googleUserId &&
			props.refreshToken &&
			typeof props.accessTokenExpiresAt === "number" &&
			Number.isFinite(props.accessTokenExpiresAt),
	);
}

function pruneGoogleAccessTokenCache(now: number): void {
	for (const [userId, token] of googleAccessTokenCache) {
		if (token.expiresAt <= now + TOKEN_REFRESH_SKEW_MS) {
			googleAccessTokenCache.delete(userId);
		}
	}
}

function getCachedGoogleAccessToken(userId: string, now: number): string | undefined {
	pruneGoogleAccessTokenCache(now);
	const cached = googleAccessTokenCache.get(userId);
	if (!cached) return undefined;

	// Touch the entry so Map insertion order acts as a lightweight LRU.
	googleAccessTokenCache.delete(userId);
	googleAccessTokenCache.set(userId, cached);
	return cached.accessToken;
}

function cacheGoogleAccessToken(userId: string, accessToken: string, expiresAt: number, now: number): void {
	pruneGoogleAccessTokenCache(now);
	googleAccessTokenCache.delete(userId);

	while (googleAccessTokenCache.size >= GOOGLE_TOKEN_CACHE_MAX_ENTRIES) {
		const oldestUserId = googleAccessTokenCache.keys().next().value as string | undefined;
		if (!oldestUserId) break;
		googleAccessTokenCache.delete(oldestUserId);
	}

	googleAccessTokenCache.set(userId, { accessToken, expiresAt });
}

async function resolveGoogleAccessToken(env: Env, props: Props, forceRefresh = false): Promise<string> {
	const now = Date.now();

	// Grants minted before refresh-token support contain only accessToken/name/email.
	// Continue serving that access token while Google accepts it; once it is rejected,
	// require a fresh OAuth login rather than attempting to refresh undefined credentials.
	if (!hasRefreshMetadata(props)) {
		if (!forceRefresh && props.accessToken) {
			return props.accessToken;
		}
		throw new ReauthorizationRequiredError("Legacy Google OAuth grant requires reauthorization");
	}

	if (!forceRefresh) {
		const cachedAccessToken = getCachedGoogleAccessToken(props.googleUserId, now);
		if (cachedAccessToken) {
			return cachedAccessToken;
		}
	}

	if (!forceRefresh && props.accessTokenExpiresAt > now + TOKEN_REFRESH_SKEW_MS) {
		cacheGoogleAccessToken(props.googleUserId, props.accessToken, props.accessTokenExpiresAt, now);
		return props.accessToken;
	}

	const refreshed = await refreshGoogleAccessToken({
		clientId: env.GOOGLE_CLIENT_ID,
		clientSecret: env.GOOGLE_CLIENT_SECRET,
		refreshToken: props.refreshToken,
	});
	const expiresAt = now + refreshed.expires_in * 1000;

	cacheGoogleAccessToken(props.googleUserId, refreshed.access_token, expiresAt, now);
	return refreshed.access_token;
}

function buildUpstreamHeaders(request: Request, accessToken: string): Headers {
	const headers = new Headers();
	const passthrough = [
		"accept",
		"cache-control",
		"content-type",
		"last-event-id",
		"mcp-protocol-version",
		"mcp-session-id",
	];

	for (const name of passthrough) {
		const value = request.headers.get(name);
		if (value) headers.set(name, value);
	}

	headers.set("Authorization", `Bearer ${accessToken}`);
	return headers;
}

async function forwardToGoogleCalendarMcp(
	request: Request,
	env: Env,
	props: Props,
	body: ArrayBuffer | undefined,
	forceRefresh = false,
): Promise<Response> {
	const accessToken = await resolveGoogleAccessToken(env, props, forceRefresh);
	const incomingUrl = new URL(request.url);
	const upstreamUrl = new URL(env.GOOGLE_MCP_URL);
	upstreamUrl.search = incomingUrl.search;

	const upstreamResponse = await fetch(upstreamUrl, {
		method: request.method,
		headers: buildUpstreamHeaders(request, accessToken),
		body,
		redirect: "manual",
	});

	// A token can be revoked upstream before its nominal expiry. Refresh once and retry.
	if (upstreamResponse.status === 401 && !forceRefresh) {
		await upstreamResponse.body?.cancel();
		return forwardToGoogleCalendarMcp(request, env, props, body, true);
	}

	if (upstreamResponse.status === 401) {
		return new Response("Google Calendar MCP rejected the upstream Google authorization.", {
			status: 502,
		});
	}

	const responseHeaders = new Headers(upstreamResponse.headers);
	responseHeaders.delete("transfer-encoding");
	responseHeaders.delete("www-authenticate");

	return new Response(upstreamResponse.body, {
		status: upstreamResponse.status,
		statusText: upstreamResponse.statusText,
		headers: responseHeaders,
	});
}

/**
 * Protected MCP handler. OAuthProvider authenticates the Codex/client bearer token first,
 * then this handler swaps it for the user's Google access token and forwards the MCP request
 * to Google's official Calendar MCP endpoint.
 */
class GoogleCalendarMcpProxy extends WorkerEntrypoint<Env, Props> {
	async fetch(request: Request): Promise<Response> {
		try {
			const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
			return await forwardToGoogleCalendarMcp(request, this.env, this.ctx.props, body);
		} catch (error) {
			if (error instanceof ReauthorizationRequiredError) {
				return new Response("Google authorization expired. Reauthorize this MCP connection.", {
					status: 401,
					headers: {
						"WWW-Authenticate": 'Bearer error="invalid_token", error_description="Google authorization must be renewed"',
					},
				});
			}

			console.error("Google Calendar MCP proxy request failed", error);
			return new Response("Google Calendar MCP proxy request failed", { status: 502 });
		}
	}
}

// Retained for the existing Durable Object migration/binding. It is no longer the public MCP API.
export class MCP_DB extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "Google OAuth Proxy Internal",
		version: "0.0.1",
	});

	async init() {
		this.server.tool("add", { a: z.number(), b: z.number() }, async ({ a, b }) => ({
			content: [{ text: String(a + b), type: "text" }],
		}));
	}
}

export default new OAuthProvider({
	apiHandler: GoogleCalendarMcpProxy,
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: GoogleHandler as any,
	tokenEndpoint: "/token",
});