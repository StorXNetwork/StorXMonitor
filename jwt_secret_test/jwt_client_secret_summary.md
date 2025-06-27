# JWT Client Secret for OAuth2 Token Request

## Overview

This document contains the generated JWT client_secret for the OAuth2 token request endpoint according to the workplan specifications in `workplan/oauth2_token_workplan.md`.

## Client Credentials

```json
{
  "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
  "client_secret": "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
}
```

## Generated JWT Client Secret

**JWT Token:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJlNDVmYTc5YS0wNWY1LTRmMDAtYmJmZS1iZDBhMTRhZWFkMGEiLCJleHAiOjE3NTEwMTkzNjF9.2USHN3Ad7nu7hoHY1keDqst1sI9R-ONHsx_GJotsPvI`

**JWT Payload:**
```json
{
  "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
  "exp": 1751019361
}
```

**Expiry:** 2025-06-27T15:46:01+05:30 (5 minutes from generation)

## Usage in Token Request

### Complete Request Body

```json
{
  "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
  "client_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJlNDVmYTc5YS0wNWY1LTRmMDAtYmJmZS1iZDBhMTRhZWFkMGEiLCJleHAiOjE3NTEwMTkzNjF9.2USHN3Ad7nu7hoHY1keDqst1sI9R-ONHsx_GJotsPvI",
  "redirect_uri": "https://myapp.com/callback",
  "code": "AUTH_CODE_FROM_CONSENT",
  "passphrase": "your-passphrase"
}
```

### curl Example

```bash
curl -X POST \
  http://localhost:10100/api/v0/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
    "client_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJlNDVmYTc5YS0wNWY1LTRmMDAtYmJmZS1iZDBhMTRhZWFkMGEiLCJleHAiOjE3NTEwMTkzNjF9.2USHN3Ad7nu7hoHY1keDqst1sI9R-ONHsx_GJotsPvI",
    "redirect_uri": "https://myapp.com/callback",
    "code": "AUTH_CODE_FROM_CONSENT",
    "passphrase": "your-passphrase"
  }'
```

## JWT Specifications

According to the workplan:

- **Algorithm:** HS256
- **Header:** `{"alg": "HS256", "typ": "JWT"}`
- **Payload:** Contains `client_id` and `exp` (expiry timestamp)
- **Signing Key:** The actual `client_secret` is used as the HMAC key
- **Expiry:** 5 minutes from generation (configurable)

## Security Notes

1. **JWT Expiry:** The JWT expires after 5 minutes for security
2. **One-time Use:** Each JWT should be used only once
3. **Secure Storage:** The actual client_secret should be stored securely
4. **No Logging:** Never log the JWT or client_secret in production

## Generation Scripts

Two scripts are provided for generating JWTs:

1. **Python:** `create_jwt_client_secret.py` (requires PyJWT library)
2. **Go:** `create_jwt_client_secret.go` (requires golang-jwt/jwt/v5)

Both scripts generate identical JWTs when run with the same parameters.

## Expected Response

On successful token exchange, the endpoint should return:

```json
{
  "access_grant": "storj_access_grant_string",
  "scopes": ["read", "write"]
}
```

On error, it should return:

```json
{
  "error": "invalid_code"
}
```

Or for expired JWT:

```json
{
  "error": "client_secret_expired"
}
```

## Important Notes

- Replace `AUTH_CODE_FROM_CONSENT` with the actual authorization code from the consent flow
- Replace `your-passphrase` with the actual user passphrase
- The JWT in this document will expire and needs to be regenerated for testing
- Always use HTTPS in production environments 