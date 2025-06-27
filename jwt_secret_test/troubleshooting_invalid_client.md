# Troubleshooting "invalid_client" Error

## Fresh JWT for Testing

**Current JWT (generated at 2025-06-27 15:44:13):**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJlNDVmYTc5YS0wNWY1LTRmMDAtYmJmZS1iZDBhMTRhZWFkMGEiLCJleHAiOjE3NTEwMTk1NTN9.UsHQ3A0EHWRahd4_zDf58Kjr4oLF7DsMfoIamqV6oZo
```

**Complete Request Body:**
```json
{
  "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
  "client_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJlNDVmYTc5YS0wNWY1LTRmMDAtYmJmZS1iZDBhMTRhZWFkMGEiLCJleHAiOjE3NTEwMTk1NTN9.UsHQ3A0EHWRahd4_zDf58Kjr4oLF7DsMfoIamqV6oZo",
  "redirect_uri": "https://myapp.com/callback",
  "code": "AUTH_CODE_FROM_CONSENT",
  "passphrase": "your-passphrase"
}
```

## Common Causes of "invalid_client" Error

### 1. **Client Not Registered in Database**
- The `client_id` might not exist in the StorX database
- The client registration might have failed or been deleted

**Check:** Verify that the client is properly registered in the database

### 2. **JWT Signature Validation Failure**
- The backend might be using a different client_secret than expected
- The JWT algorithm might not match what the backend expects

**Check:** Ensure the client_secret in the database matches: `2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102`

### 3. **JWT Payload Validation Issues**
- The `client_id` in the JWT payload doesn't match the `client_id` in the request
- Missing or invalid `exp` claim
- JWT has expired

**Check:** Verify JWT payload contains:
```json
{
  "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
  "exp": 1751019553
}
```

### 4. **Backend Implementation Issues**
- The JWT validation logic might not be implemented correctly
- The endpoint might not be handling JWT authentication yet

**Check:** Verify the `/oauth2/token` endpoint implementation

### 5. **Request Format Issues**
- Missing required fields
- Wrong Content-Type header
- Malformed JSON

**Check:** Ensure request has:
- `Content-Type: application/json` header
- All required fields: `client_id`, `client_secret`, `redirect_uri`, `code`, `passphrase`

## Debugging Steps

### Step 1: Test with curl
```bash
curl -X POST \
  http://localhost:10100/api/v0/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a",
    "client_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJlNDVmYTc5YS0wNWY1LTRmMDAtYmJmZS1iZDBhMTRhZWFkMGEiLCJleHAiOjE3NTEwMTk1NTN9.UsHQ3A0EHWRahd4_zDf58Kjr4oLF7DsMfoIamqV6oZo",
    "redirect_uri": "https://myapp.com/callback",
    "code": "AUTH_CODE_FROM_CONSENT",
    "passphrase": "your-passphrase"
  }'
```

### Step 2: Check Backend Logs
Look for detailed error messages in the backend logs that might indicate the specific validation failure.

### Step 3: Verify Client Registration
Check if the client is properly registered in the database with the correct credentials.

### Step 4: Test JWT Validation
Use the debug script to verify JWT is valid:
```bash
python3 debug_jwt_validation.py
```

## Expected Backend Validation Flow

According to the workplan, the backend should:

1. **Parse JWT** from `client_secret` field
2. **Extract client_id** and `exp` from JWT payload
3. **Fetch stored client_secret** from database using `client_id`
4. **Validate JWT signature** using stored `client_secret`
5. **Check JWT expiry** (`exp` claim)
6. **Verify client_id** matches between JWT and request

## Error Response Codes

- `invalid_client`: Client authentication failed
- `client_secret_expired`: JWT has expired
- `invalid_code`: Authorization code is invalid/expired
- `invalid_redirect_uri`: Redirect URI doesn't match

## Next Steps

1. **Generate fresh JWT** if current one expires
2. **Check backend implementation** of JWT validation
3. **Verify client registration** in database
4. **Review backend logs** for detailed error messages
5. **Test with minimal request** to isolate the issue

## Quick JWT Regeneration

If you need a fresh JWT, run:
```bash
python3 create_jwt_client_secret.py
```

This will generate a new JWT with 5-minute expiry. 