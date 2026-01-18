import { deleteCookie, getSignedCookie, setSignedCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import {
    AuthorizationRequest,
    AuthorizationResponse,
    Client,
    createIdentityProvider,
    Identity,
    IdentityProvider,
    IdentityToken,
    TokenResponse,
    TokenSet,
} from "@shad-claiborne/basic-oidc";
import randomstring from "randomstring";
import { env } from "hono/adapter";

export const withIdentity = createMiddleware(async (c, next) => {
    const {
        HONO_OIDC_ISSUER,
        HONO_OIDC_CLIENT_ID,
        HONO_OIDC_CLIENT_SECRET,
        HONO_OIDC_REDIRECT_URI,
        HONO_OIDC_COOKIE_SECRET,
        HONO_OIDC_ACCESS_TOKEN_COOKIE,
        HONO_OIDC_REFRESH_TOKEN_COOKIE,
        HONO_OIDC_ID_TOKEN_COOKIE,
        HONO_OIDC_CODE_VERIFIER_COOKIE,
    } = env<HonoMiddlewareOidcEnv>(c);
    const provider: IdentityProvider = await createIdentityProvider(
        HONO_OIDC_ISSUER
    );
    const client: Client = provider.createClient(
        HONO_OIDC_CLIENT_ID,
        HONO_OIDC_CLIENT_SECRET
    );
    const tokenSet = {
        id_token: await getSignedCookie(
            c,
            HONO_OIDC_COOKIE_SECRET,
            HONO_OIDC_ID_TOKEN_COOKIE
        ),
        access_token: await getSignedCookie(
            c,
            HONO_OIDC_COOKIE_SECRET,
            HONO_OIDC_ACCESS_TOKEN_COOKIE
        ),
        refresh_token: await getSignedCookie(
            c,
            HONO_OIDC_COOKIE_SECRET,
            HONO_OIDC_REFRESH_TOKEN_COOKIE
        ),
    } as TokenSet;
    let id: Identity | null;

    try {
        id = await provider.getIdentity(tokenSet);
    } catch (err) {
        id = null;
    }
    if (id === null) {
        try {
            const tokenResponse: TokenResponse = await client.refreshAccess(tokenSet);
            id = await provider.getIdentity(tokenResponse);

            if (tokenResponse.access_token)
                await setSignedCookie(
                    c,
                    HONO_OIDC_ACCESS_TOKEN_COOKIE,
                    tokenResponse.access_token,
                    HONO_OIDC_COOKIE_SECRET,
                    { httpOnly: true, secure: true, sameSite: 'Lax' }
                );
            if (tokenResponse.refresh_token) {
                const maxAge = tokenResponse.refresh_token_expires_in ?? (24 * 60 * 60);
                await setSignedCookie(
                    c,
                    HONO_OIDC_REFRESH_TOKEN_COOKIE,
                    tokenResponse.refresh_token,
                    HONO_OIDC_COOKIE_SECRET,
                    { httpOnly: true, secure: true, sameSite: 'Lax', maxAge }
                );
            }
            if (tokenResponse.id_token) {
                const idToken: IdentityToken = await provider.decodeIdentityToken(tokenResponse.id_token);
                const maxAge = idToken.exp - Math.floor(Date.now() / 1000);
                await setSignedCookie(
                    c,
                    HONO_OIDC_ID_TOKEN_COOKIE,
                    tokenResponse.id_token,
                    HONO_OIDC_COOKIE_SECRET,
                    { httpOnly: true, secure: true, sameSite: 'Lax', maxAge }
                );
            }
        } catch (err) {
            const stateId = randomstring.generate(5);
            const state = { originUrl: c.req.url };
            await setSignedCookie(
                c,
                `_authstate-${stateId}`,
                JSON.stringify(state),
                HONO_OIDC_COOKIE_SECRET,
                { httpOnly: true, secure: true, sameSite: 'Lax' }
            );
            const codeVerifier = randomstring.generate(16);
            await setSignedCookie(
                c,
                HONO_OIDC_CODE_VERIFIER_COOKIE,
                codeVerifier,
                HONO_OIDC_COOKIE_SECRET,
                { httpOnly: true, secure: true, sameSite: 'Lax' }
            );
            const authRequest: AuthorizationRequest = client
                .newAuthorizationRequest()
                .setRedirectUri(HONO_OIDC_REDIRECT_URI)
                .setResponseMode("query")
                .setResponseType("code id_token")
                .setScope(["profile"])
                .setCodeChallenge(codeVerifier)
                .setState(stateId);
            const authRequestURL = authRequest.toURL();
            return c.redirect(authRequestURL.toString());
        }
    }
    c.set("identity", id);
    await next();
});

export const forAuthorization = createMiddleware(async (c) => {
    const {
        HONO_OIDC_ISSUER,
        HONO_OIDC_CLIENT_ID,
        HONO_OIDC_CLIENT_SECRET,
        HONO_OIDC_REDIRECT_URI,
        HONO_OIDC_COOKIE_SECRET,
        HONO_OIDC_ACCESS_TOKEN_COOKIE,
        HONO_OIDC_REFRESH_TOKEN_COOKIE,
        HONO_OIDC_ID_TOKEN_COOKIE,
        HONO_OIDC_CODE_VERIFIER_COOKIE,
    } = env<HonoMiddlewareOidcEnv>(c);
    const provider: IdentityProvider = await createIdentityProvider(
        HONO_OIDC_ISSUER
    );
    const client: Client = provider.createClient(
        HONO_OIDC_CLIENT_ID,
        HONO_OIDC_CLIENT_SECRET
    );
    const requestURL = new URL(c.req.url),
        requestParams = requestURL.searchParams;
    const authResponse = Object.fromEntries(
        requestParams
    ) as AuthorizationResponse;
    const stateId = requestParams.get("state");

    if (stateId === undefined)
        throw new Error("state missing from authorization response");
    const stateCookie = `_authstate-${stateId}`;
    const stateJson = await getSignedCookie(
        c,
        HONO_OIDC_COOKIE_SECRET,
        stateCookie
    );
    deleteCookie(c, stateCookie);

    if (stateJson === false || stateJson === undefined)
        throw new Error("state cookie failed");
    const state = JSON.parse(stateJson);
    const codeVerifier = await getSignedCookie(
        c,
        HONO_OIDC_COOKIE_SECRET,
        HONO_OIDC_CODE_VERIFIER_COOKIE
    );
    deleteCookie(c, HONO_OIDC_CODE_VERIFIER_COOKIE);

    if (codeVerifier === false || codeVerifier === undefined)
        throw new Error("code verifier cookie failed");
    const tokenResponse: TokenResponse = await client.requestAccess(
        authResponse,
        { codeVerifier, redirectUri: HONO_OIDC_REDIRECT_URI }
    );

    if (tokenResponse.access_token)
        await setSignedCookie(
            c,
            HONO_OIDC_ACCESS_TOKEN_COOKIE,
            tokenResponse.access_token,
            HONO_OIDC_COOKIE_SECRET,
            { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: tokenResponse.expires_in }
        );
    if (tokenResponse.refresh_token)
        await setSignedCookie(
            c,
            HONO_OIDC_REFRESH_TOKEN_COOKIE,
            tokenResponse.refresh_token,
            HONO_OIDC_COOKIE_SECRET,
            { httpOnly: true, secure: true, sameSite: 'Lax' }
        );
    if (tokenResponse.id_token) {
        const idToken: IdentityToken = await provider.decodeIdentityToken(tokenResponse.id_token);
        const maxAge = idToken.exp - Math.floor(Date.now() / 1000);
        await setSignedCookie(
            c,
            HONO_OIDC_ID_TOKEN_COOKIE,
            tokenResponse.id_token,
            HONO_OIDC_COOKIE_SECRET,
            { httpOnly: true, secure: true, sameSite: 'Lax', maxAge }
        );
    }
    return c.redirect(state.originUrl);
});
