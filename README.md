# This package is not intended for production environments.
`wrangler configuration`
```json
"vars": {
        "HONO_OIDC_ISSUER": "https://some-idp",
        "HONO_OIDC_CLIENT_ID": "client-id",
        "HONO_OIDC_CLIENT_SECRET": "client-secret",
        "HONO_OIDC_REDIRECT_URI": "https://your-authenticated-app/auth/callback",
        "HONO_OIDC_COOKIE_SECRET": "cookie-secret",
        "HONO_OIDC_ID_TOKEN_COOKIE": "id-token",
        "HONO_OIDC_REFRESH_TOKEN_COOKIE": "refresh-token",
        "HONO_OIDC_ACCESS_TOKEN_COOKIE": "access-token",
        "HONO_OIDC_CODE_VERIFIER_COOKIE": "code-verifier"
}
```
### Usage
```ts
app.use('*', except('/auth/callback', withIdentity));

app.use('/auth/callback', forAuthorization);

app.get('/async/api/identity', async (c) => {
    return c.json(c.get('identity'));
});

app.get('/', async (c) => {
    return c.text('hello world');
});
```