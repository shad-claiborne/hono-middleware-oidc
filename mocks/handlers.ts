// mocks/handlers.ts
import { http, HttpResponse } from 'msw';
import openidConfig from './openid-configuration.json';
import publicJwks from './jwks.json';
import privateJwk from './private-jwk.json';
import sha256 from 'crypto-js/sha256';
import base64Url from 'crypto-js/enc-base64url';
import { importJWK, SignJWT } from 'jose';

const cacheMap = new Map();

const generateRandomCode = (len = 16) => {
    const randomValues = new Uint8Array(Math.ceil(len / 2));
    crypto.getRandomValues(randomValues);
    return Array.from(randomValues).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, len);
};

const generateIdToken = async (clientId: string, data: object) => {
    // Import private key
    const privateKey = await importJWK(privateJwk, privateJwk.alg);

    // Standard OIDC claims
    const subject = 'user-123';

    const now = Math.floor(Date.now() / 1000);

    // Create ID Token
    const idToken = await new SignJWT({
        ...data,
        auth_time: now,
        nonce: 'n-0S6_WzA2Mj',
    })
        .setProtectedHeader({
            alg: privateJwk.alg,
            kid: privateJwk.kid,
            typ: 'JWT',
        })
        .setIssuer(openidConfig.issuer)
        .setAudience(clientId)
        .setSubject(subject)
        .setIssuedAt(now)
        .setExpirationTime(now + 60 * 60) // 1 hour
        .setNotBefore(now)
        .sign(privateKey);

    return idToken.toString();
};

export const handlers = [
    http.get('http://localhost/hono-middleware-oidc/callback', ({ request }) => {
        const reqURL: URL = new URL(request.url);
        return HttpResponse.json(Object.fromEntries(reqURL.searchParams));
    }),
    http.get('http://localhost/.well-known/openid-configuration', () => {
        return HttpResponse.json(openidConfig);
    }),
    http.get('http://localhost/oauth2/v1/keys', () => {
        return HttpResponse.json(publicJwks);
    }),
    http.get('http://localhost/oauth2/v1/authorize', async ({ request }) => {
        const requestURL = new URL(request.url),
            requestParams = requestURL.searchParams;
        const clientId = requestParams.get('client_id');
        
        if (clientId === null)
            throw new Error('client_id is required');
        const redirectURL = new URL('http://localhost/auth/callback');
        const responseParams = new URLSearchParams();

        if (requestParams.has('state'))
            responseParams.append('state', requestParams.get('state') as string);
        const responseType: string[] = requestParams.get('response_type')?.split(' ') ?? [];

        if (responseType.includes('code')) {
            const code = generateRandomCode();
            responseParams.append('code', code);
            cacheMap.set(`t-${code}`, { requestUrl: request.url, clientId });
        }
        if (responseType.includes('id_token')) {
            responseParams.append('id_token', await generateIdToken(clientId, {
                name: 'John Doe',
                email: 'john@doe.com'
            }));
        }
        redirectURL.search = responseParams.toString();

        return new HttpResponse(null, {
            status: 302,
            headers: {
                'Location': redirectURL.toString(),
            },
        });
    }),
    http.post('http://localhost/oauth2/v1/token', async ({ request }) => {
        const body = await request.text();
        const requestData = Object.fromEntries(new URLSearchParams(body));
        const responseData: any = {};
        let entryKey: string | null = null;

        if (requestData.grant_type === 'authorization_code') {
            entryKey = `t-${requestData.code}`;
        }
        else if (requestData.grant_type === 'refresh_token') {
            entryKey = `t-${requestData.refresh_token}`;
        }
        if (entryKey && cacheMap.has(entryKey)) {
            const cacheEntry = cacheMap.get(entryKey);
            cacheMap.delete(entryKey);

            if (requestData.grant_type === 'refresh_token') {
                cacheMap.delete(`tt-${cacheEntry.access_token}`);
            }
            const requestURL = new URL(cacheEntry.requestUrl),
                requestParams = requestURL.searchParams;

            if (
                requestData.grant_type === 'authorization_code' &&
                requestParams.has('code_challenge') &&
                base64Url.stringify(sha256(requestData.code_verifier)) !== requestParams.get('code_challenge')
            )
                throw new Error('invalid code verifier');

            const responseType: string[] = requestParams.get('response_type')?.split(' ') ?? [];
            const accessToken = generateRandomCode();
            const refreshToken = generateRandomCode();
            Object.assign(responseData, {
                token_type: 'Bearer',
                access_token: accessToken,
                expires_in: 30 * 60,
                refresh_token: refreshToken
            });

            if (responseType.includes('id_token')) {
                responseData.id_token = await generateIdToken(cacheEntry.clientId, {
                    name: 'John Doe',
                    email: 'john@doe.com'
                });
            }
            Object.assign(cacheEntry, responseData);
            cacheMap.set(`t-${refreshToken}`, cacheEntry);
            cacheMap.set(`tt-${accessToken}`, cacheEntry);
        } else
            throw new Error('invalid authorization code');
        return HttpResponse.json(responseData);
    }),
    http.get('http://localhost/oauth2/v1/userinfo', async ({ request }) => {
        const authorization = request.headers.get('authorization');

        if (authorization === null || authorization.toLowerCase().startsWith('bearer ') === false)
            throw new Error('unauthorized');
        const accessToken = authorization.substring(7);
        const cacheKey = `tt-${accessToken}`;

        if (cacheMap.has(cacheKey) === false)
            throw new Error('unauthorized');

        return HttpResponse.json({
            sub: '1234567890',
            name: 'John Doe',
        });
    }),
    http.post('http://localhost/oauth2/v1/revoke', async ({ request }) => {
        const body = await request.text();
        const requestData = Object.fromEntries(new URLSearchParams(body));
        let cacheEntry = undefined;

        switch (requestData.token_type_hint) {
            case 'access_token':
                cacheEntry = cacheMap.get(`tt-${requestData.token}`);
                break;
            case 'refresh_token':
                cacheEntry = cacheMap.get(`t-${requestData.token}`);
                break;
            default:
                cacheEntry = cacheMap.get(`tt-${requestData.token}`);

                if (cacheEntry === undefined) {
                    cacheEntry = cacheMap.get(`t-${requestData.token}`);
                }
                break;
        }
        if (cacheEntry === undefined)
            throw new Error('invalid token type');

        cacheMap.delete(`tt-${cacheEntry.access_token}`);
        cacheMap.delete(`t-${cacheEntry.refresh_token}`);
        return HttpResponse.json({});
    })
];