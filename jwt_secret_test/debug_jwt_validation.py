#!/usr/bin/env python3
"""
JWT Validation Debug Script for OAuth2 Token Request

This script helps debug JWT validation issues that might cause "invalid_client" errors.
"""

import json
import time
import jwt
from datetime import datetime

def debug_jwt_validation(client_id, client_secret, jwt_token):
    """
    Debug JWT validation step by step.
    """
    print("=== JWT Validation Debug ===")
    print(f"Client ID: {client_id}")
    print(f"Client Secret: {client_secret}")
    print(f"JWT Token: {jwt_token}")
    print()
    
    # Step 1: Decode JWT without verification to see payload
    try:
        decoded_payload = jwt.decode(jwt_token, options={"verify_signature": False})
        print("=== Step 1: JWT Payload (without verification) ===")
        print(json.dumps(decoded_payload, indent=2))
        print()
        
        # Check if client_id matches
        if decoded_payload.get("client_id") != client_id:
            print("❌ ERROR: client_id in JWT doesn't match provided client_id")
            print(f"   JWT client_id: {decoded_payload.get('client_id')}")
            print(f"   Expected: {client_id}")
            return False
        else:
            print("✅ client_id matches")
        
        # Check expiry
        exp_timestamp = decoded_payload.get("exp")
        if exp_timestamp:
            exp_datetime = datetime.fromtimestamp(exp_timestamp)
            current_time = datetime.now()
            if exp_timestamp < time.time():
                print(f"❌ ERROR: JWT has expired")
                print(f"   Expiry: {exp_datetime}")
                print(f"   Current: {current_time}")
                return False
            else:
                print(f"✅ JWT is not expired (expires at {exp_datetime})")
        else:
            print("❌ ERROR: No 'exp' claim in JWT")
            return False
            
    except jwt.DecodeError as e:
        print(f"❌ ERROR: Failed to decode JWT: {e}")
        return False
    
    # Step 2: Verify JWT signature
    try:
        verified_payload = jwt.decode(jwt_token, client_secret, algorithms=["HS256"])
        print("✅ JWT signature is valid")
        return True
    except jwt.ExpiredSignatureError:
        print("❌ ERROR: JWT has expired (signature verification)")
        return False
    except jwt.InvalidSignatureError:
        print("❌ ERROR: JWT signature is invalid")
        print("   This could mean:")
        print("   - Wrong client_secret used for signing")
        print("   - JWT was tampered with")
        print("   - Different algorithm used")
        return False
    except jwt.InvalidTokenError as e:
        print(f"❌ ERROR: Invalid JWT: {e}")
        return False

def test_different_scenarios():
    """
    Test different scenarios that might cause invalid_client error.
    """
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    
    print("=== Testing Different Scenarios ===")
    
    # Scenario 1: Valid JWT
    print("\n--- Scenario 1: Valid JWT ---")
    valid_jwt = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    debug_jwt_validation(client_id, client_secret, valid_jwt)
    
    # Scenario 2: Wrong client_secret
    print("\n--- Scenario 2: Wrong client_secret ---")
    wrong_secret = "wrong_secret"
    debug_jwt_validation(client_id, wrong_secret, valid_jwt)
    
    # Scenario 3: Wrong client_id in JWT
    print("\n--- Scenario 3: Wrong client_id in JWT ---")
    wrong_client_jwt = jwt.encode(
        {"client_id": "wrong-client-id", "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    debug_jwt_validation(client_id, client_secret, wrong_client_jwt)
    
    # Scenario 4: Expired JWT
    print("\n--- Scenario 4: Expired JWT ---")
    expired_jwt = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) - 300},
        client_secret,
        algorithm="HS256"
    )
    debug_jwt_validation(client_id, client_secret, expired_jwt)

def create_test_request():
    """
    Create a test request with fresh JWT.
    """
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    
    # Create fresh JWT
    jwt_token = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    
    print("=== Fresh Test Request ===")
    print("Use this JWT for testing:")
    print(f"JWT: {jwt_token}")
    print()
    
    # Test request body
    request_body = {
        "client_id": client_id,
        "client_secret": jwt_token,
        "redirect_uri": "https://myapp.com/callback",
        "code": "AUTH_CODE_FROM_CONSENT",
        "passphrase": "your-passphrase"
    }
    
    print("Request Body:")
    print(json.dumps(request_body, indent=2))
    print()
    
    # curl command
    print("curl command:")
    print(f"""curl -X POST \\
  http://localhost:10100/api/v0/oauth2/token \\
  -H "Content-Type: application/json" \\
  -d '{json.dumps(request_body)}'""")

if __name__ == "__main__":
    print("JWT Validation Debug Tool")
    print("=" * 50)
    
    # Test scenarios
    test_different_scenarios()
    
    print("\n" + "=" * 50)
    
    # Create fresh test request
    create_test_request() 