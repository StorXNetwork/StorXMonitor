# HOW TO USE: StorX OAuth2 Integration

This guide explains how to integrate your external application with StorX using the OAuth2 UI flow to obtain S3-compatible credentials for direct upload/download.

---

## Prerequisites

Before you begin, you must have:

1. **client_id**: Provided by StorX for your application.
2. **client_secret**: Provided by StorX for your application.
3. **redirect_uri**: The URL in your app where users will be redirected after authentication (must be registered with StorX).
4. **scope**: The permissions your app needs (e.g., `read`, `write`).

---

## 1. How to Create an Encrypted Client Secret (JWT)

To securely authenticate your application, you must generate a **JWT (JSON Web Token) client_secret** for each OAuth2 request. This JWT is used as the `client_secret` parameter in the integration URL.

**Steps to create the JWT client_secret:**

1. **Create a JWT payload** that includes:
    - `client_id`: Your application's client ID.
    - `exp`: The expiry time (as a Unix timestamp), typically 5 minutes from the current time.
2. **Sign the JWT** using your application's original client secret as the signing key.
3. **Use the resulting JWT string** as the `client_secret` in the OAuth2 integration URL.

**Example JWT payload:**
```
{
  "client_id": "<CLIENT_ID>",
  "exp": <EXPIRY_UNIX_TIMESTAMP>
}
```

- The JWT should be signed using a secure algorithm (e.g., HS256) and your `<CLIENT_SECRET>` as the key.
- The expiry (`exp`) ensures the token is only valid for a short period (e.g., 5 minutes).

**How to verify/debug the JWT:**
- You can decode the JWT to inspect its payload and expiry.
- To verify the JWT, use your `<CLIENT_SECRET>` as the key.
- Check that the `client_id` matches and the `exp` is in the future.

**Note:**
- Never expose your original `<CLIENT_SECRET>` in client-side code.
- Always generate the JWT on your backend/server.

---

## 2. Construct the OAuth2 Integration URL

Build a URL like this:

```
https://storx.io/oauth2-integration?client_id=<CLIENT_ID>&client_secret=<JWT_CLIENT_SECRET>&redirect_uri=https://redirect_host/callback&scope=<SCOPES>
```

- Replace `<CLIENT_ID>`, `<JWT_CLIENT_SECRET>`, `<REDIRECT_URI>`, and `<SCOPES>` with your actual values.

---

## 3. User Authentication Flow

1. **User visits the OAuth2 integration URL** (constructed above).
2. StorX UI will:
    - Validate all required parameters (`client_id`, `client_secret`, `redirect_uri`, `scope`).
    - Show a consent screen for the user to approve requested scopes.
    - If the user approves, the UI completes the OAuth2 flow.
    - If any error occurs, the user is redirected to your `redirect_uri` with an error parameter.
3. **On success:**
    - The user is redirected to your `redirect_uri` with an `access_grant` parameter.

**Example redirect:**
```
https://redirect_host/callback?access_grant=<ACCESS_GRANT>
```

---

## 4. Exchange the Access Grant for S3 Credentials

On your backend, use the `access_grant` to obtain S3 credentials from StorX:

```
curl --location 'https://storx.io/v1/access' \
--data '{
    "access_grant": "<ACCESS_GRANT>",
    "public": false
}'
```

**Replace `<ACCESS_GRANT>` with the value received in the redirect.**

**Example response:**
```
{
    "access_key_id": "<ACCESS_KEY_ID>",
    "secret_key": "<SECRET_KEY>",
    "endpoint": "https://storx.io"
}
```

---

## 5. Use the S3 Credentials

You can now use the returned S3 credentials to upload/download data to StorX using any S3-compatible SDK or tool.

- **endpoint**: S3 API endpoint for StorX
- **access_key_id**: S3 access key
- **secret_key**: S3 secret key

**Example (using AWS CLI):**
```
aws configure set aws_access_key_id <ACCESS_KEY_ID>
aws configure set aws_secret_access_key <SECRET_KEY>
aws configure set default.region us-east-1
aws --endpoint-url <ENDPOINT> s3 ls
```

---

## 6. Error Handling

- If any required parameter is missing or invalid, the user will be redirected to your `redirect_uri` with an `error` parameter.
- If the user denies consent, or any backend error occurs, the user will be redirected with an `error` parameter.
- Only redirect with `access_grant` if all steps succeed.

---

## 7. Notes & Caveats

- Make sure your `redirect_uri` is registered and matches exactly.
- The `access_grant` is sensitive and should be handled securely.
- S3 credentials are short-lived; refresh as needed by repeating the flow.

---

For more details, see the full [OAuth2 Integration Work Plan](work_plan/oauth2_integration_work_plan.md). 