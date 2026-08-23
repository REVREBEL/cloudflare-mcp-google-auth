import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { exchangeGoogleAuthorizationCode, getUpstreamAuthorizeUrl, type Props } from "./utils";
import {
	addApprovedClient,
	bindStateToSession,
	createOAuthState,
	generateCSRFProtection,
	isClientApproved,
	OAuthError,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	const { clientId } = oauthReqInfo;
	if (!clientId) {
		return c.text("Invalid request", 400);
	}

	if (await isClientApproved(c.req.raw, clientId, c.env.COOKIE_ENCRYPTION_KEY)) {
		// Skip approval dialog but still create secure state and bind to session
		const { stateToken } = await createOAuthState(oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie: sessionBindingCookie } = await bindStateToSession(stateToken);
		return redirectToGoogle(c.req.raw, c.env, stateToken, {
			"Set-Cookie": sessionBindingCookie,
		});
	}

	const { token: csrfToken, setCookie } = generateCSRFProtection();

	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		csrfToken,
		server: {
			description: "Authorize access to the Google Calendar MCP through this proxy.",
			name: "Google Calendar MCP Proxy",
		},
		setCookie,
		state: { oauthReqInfo },
	});
});

app.post("/authorize", async (c) => {
	try {
		const formData = await c.req.raw.formData();
		validateCSRFToken(formData, c.req.raw);

		const encodedState = formData.get("state");
		if (!encodedState || typeof encodedState !== "string") {
			return c.text("Missing state in form data", 400);
		}

		let state: { oauthReqInfo?: AuthRequest };
		try {
			state = JSON.parse(atob(encodedState));
		} catch (_e) {
			return c.text("Invalid state data", 400);
		}

		if (!state.oauthReqInfo || !state.oauthReqInfo.clientId) {
			return c.text("Invalid request", 400);
		}

		const approvedClientCookie = await addApprovedClient(
			c.req.raw,
			state.oauthReqInfo.clientId,
			c.env.COOKIE_ENCRYPTION_KEY,
		);

		// Create OAuth state and bind it to this user's session
		const { stateToken } = await createOAuthState(state.oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie: sessionBindingCookie } = await bindStateToSession(stateToken);

		const headers = new Headers();
		headers.append("Set-Cookie", approvedClientCookie);
		headers.append("Set-Cookie", sessionBindingCookie);

		return redirectToGoogle(c.req.raw, c.env, stateToken, Object.fromEntries(headers));
	} catch (error: any) {
		console.error("POST /authorize error:", error);
		if (error instanceof OAuthError) {
			return error.toResponse();
		}
		return c.text(`Internal server error: ${error.message}`, 500);
	}
});

function getGoogleScopes(env: Env): string {
	const configuredScopes = (env.GOOGLE_OAUTH_SCOPES ?? "")
		.split(/\s+/)
		.map((scope) => scope.trim())
		.filter(Boolean);

	return [...new Set(["email", "profile", ...configuredScopes])].join(" ");
}

async function redirectToGoogle(
	request: Request,
	env: Env,
	stateToken: string,
	headers: Record<string, string> = {},
) {
	return new Response(null, {
		headers: {
			...headers,
			location: getUpstreamAuthorizeUrl({
				clientId: env.GOOGLE_CLIENT_ID,
				hostedDomain: env.HOSTED_DOMAIN,
				redirectUri: new URL("/callback", request.url).href,
				scope: getGoogleScopes(env),
				state: stateToken,
				upstreamUrl: "https://accounts.google.com/o/oauth2/v2/auth",
				accessType: "offline",
				prompt: "consent",
				includeGrantedScopes: true,
			}),
		},
		status: 302,
	});
}

app.get("/callback", async (c) => {
	let oauthReqInfo: AuthRequest;
	let clearSessionCookie: string;

	try {
		const result = await validateOAuthState(c.req.raw, c.env.OAUTH_KV);
		oauthReqInfo = result.oauthReqInfo;
		clearSessionCookie = result.clearCookie;
	} catch (error: any) {
		if (error instanceof OAuthError) {
			return error.toResponse();
		}
		return c.text("Internal server error", 500);
	}

	if (!oauthReqInfo.clientId) {
		return c.text("Invalid OAuth request data", 400);
	}

	const code = c.req.query("code");
	if (!code) {
		return c.text("Missing code", 400);
	}

	let googleTokens;
	try {
		googleTokens = await exchangeGoogleAuthorizationCode({
			clientId: c.env.GOOGLE_CLIENT_ID,
			clientSecret: c.env.GOOGLE_CLIENT_SECRET,
			code,
			redirectUri: new URL("/callback", c.req.url).href,
		});
	} catch (error) {
		console.error("Google OAuth authorization-code exchange failed", error);
		return c.text("Failed to exchange Google authorization code", 502);
	}

	if (!googleTokens.refresh_token) {
		return c.text(
			"Google did not return a refresh token. Revoke the existing app grant and authorize again.",
			502,
		);
	}

	const userResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
		headers: {
			Authorization: `Bearer ${googleTokens.access_token}`,
		},
	});
	if (!userResponse.ok) {
		return c.text(`Failed to fetch user info: ${await userResponse.text()}`, 500);
	}

	const { id, name, email } = (await userResponse.json()) as {
		id: string;
		name: string;
		email: string;
	};

	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		metadata: {
			label: name,
		},
		props: {
			googleUserId: id,
			accessToken: googleTokens.access_token,
			refreshToken: googleTokens.refresh_token,
			accessTokenExpiresAt: Date.now() + googleTokens.expires_in * 1000,
			email,
			name,
		} as Props,
		request: oauthReqInfo,
		scope: oauthReqInfo.scope,
		userId: id,
	});

	const headers = new Headers({ Location: redirectTo });
	if (clearSessionCookie) {
		headers.set("Set-Cookie", clearSessionCookie);
	}

	return new Response(null, {
		status: 302,
		headers,
	});
});

export { app as GoogleHandler };
