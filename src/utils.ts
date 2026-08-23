/**
 * Constructs an authorization URL for an upstream service.
 */
export function getUpstreamAuthorizeUrl({
	upstreamUrl,
	clientId,
	scope,
	redirectUri,
	state,
	hostedDomain,
	accessType,
	prompt,
	includeGrantedScopes,
}: {
	upstreamUrl: string;
	clientId: string;
	scope: string;
	redirectUri: string;
	state?: string;
	hostedDomain?: string;
	accessType?: "online" | "offline";
	prompt?: string;
	includeGrantedScopes?: boolean;
}) {
	const upstream = new URL(upstreamUrl);
	upstream.searchParams.set("client_id", clientId);
	upstream.searchParams.set("redirect_uri", redirectUri);
	upstream.searchParams.set("scope", scope);
	upstream.searchParams.set("response_type", "code");
	if (state) upstream.searchParams.set("state", state);
	if (hostedDomain) upstream.searchParams.set("hd", hostedDomain);
	if (accessType) upstream.searchParams.set("access_type", accessType);
	if (prompt) upstream.searchParams.set("prompt", prompt);
	if (includeGrantedScopes) upstream.searchParams.set("include_granted_scopes", "true");
	return upstream.href;
}

export type GoogleTokenResponse = {
	access_token: string;
	expires_in: number;
	refresh_token?: string;
	scope?: string;
	token_type?: string;
};

async function fetchGoogleToken(body: URLSearchParams): Promise<GoogleTokenResponse> {
	const response = await fetch("https://oauth2.googleapis.com/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: body.toString(),
	});

	if (!response.ok) {
		const errorBody = await response.text();
		console.error(`Google OAuth token request failed (${response.status}): ${errorBody}`);
		throw new Error(`Google OAuth token request failed with status ${response.status}`);
	}

	const token = (await response.json()) as GoogleTokenResponse;
	if (!token.access_token) {
		throw new Error("Google OAuth token response did not include an access token");
	}
	return token;
}

export async function exchangeGoogleAuthorizationCode({
	clientId,
	clientSecret,
	code,
	redirectUri,
}: {
	clientId: string;
	clientSecret: string;
	code: string;
	redirectUri: string;
}): Promise<GoogleTokenResponse> {
	return fetchGoogleToken(
		new URLSearchParams({
			client_id: clientId,
			client_secret: clientSecret,
			code,
			grant_type: "authorization_code",
			redirect_uri: redirectUri,
		}),
	);
}

export async function refreshGoogleAccessToken({
	clientId,
	clientSecret,
	refreshToken,
}: {
	clientId: string;
	clientSecret: string;
	refreshToken: string;
}): Promise<GoogleTokenResponse> {
	return fetchGoogleToken(
		new URLSearchParams({
			client_id: clientId,
			client_secret: clientSecret,
			refresh_token: refreshToken,
			grant_type: "refresh_token",
		}),
	);
}

// Context encrypted into the local OAuth grant and exposed to the protected MCP handler.
export type Props = {
	googleUserId: string;
	name: string;
	email: string;
	accessToken: string;
	refreshToken: string;
	accessTokenExpiresAt: number;
};
