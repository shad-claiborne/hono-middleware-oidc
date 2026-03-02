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
import {addIdentity, receiveAuth, handleFlow} from '@shad-claiborne/hono-middleware-oidc'

...

// Add the identity claims to the request for all routes except the redirect URI
app.use('*', except('/auth/callback', addIdentity));

// The endpoint to which the authorization server provides the user's authorization
app.use('/auth/callback', receiveAuth);

// Send the browser to this endpoint to begin the authorization flow
// Note this endpoint assumes "addIdentity" precedes it
app.use('/login', handleFlow);

// Example ajax endpoint for getting the identity claims
app.get('/async/api/identity', async (c) => {
    return c.json(c.get('identity'));
});

...
```