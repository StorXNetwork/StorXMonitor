#!/usr/bin/env python3
"""
Test script for OAuth2 Token Endpoint

This script helps test the /oauth2/token endpoint with proper error handling.
"""

import json
import requests
import time
import jwt

def test_token_endpoint(base_url="http://localhost:10100"):
    """
    Test the OAuth2 token endpoint with fresh JWT.
    """
    
    # Client credentials
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    
    # Create fresh JWT
    jwt_token = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    
    # Request payload
    payload = {
        "client_id": client_id,
        "client_secret": jwt_token,
        "redirect_uri": "https://myapp.com/callback",
        "code": "AUTH_CODE_FROM_CONSENT",
        "passphrase": "your-passphrase"
    }
    
    # Headers
    headers = {
        "Content-Type": "application/json"
    }
    
    # Make request
    url = f"{base_url}/api/v0/oauth2/token"
    
    print("=== Testing OAuth2 Token Endpoint ===")
    print(f"URL: {url}")
    print(f"Client ID: {client_id}")
    print(f"JWT: {jwt_token}")
    print()
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print()
        
        try:
            response_json = response.json()
            print("Response Body:")
            print(json.dumps(response_json, indent=2))
        except json.JSONDecodeError:
            print("Response Body (not JSON):")
            print(response.text)
        
        print()
        
        # Analyze response
        if response.status_code == 200:
            print("✅ SUCCESS: Token exchange successful!")
        elif response.status_code == 400:
            error = response_json.get("error", "unknown_error")
            print(f"❌ CLIENT ERROR: {error}")
            
            if error == "invalid_client":
                print("\nPossible causes:")
                print("1. Client not registered in database")
                print("2. JWT signature validation failed")
                print("3. Backend JWT validation not implemented")
                print("4. Wrong client_secret in database")
            elif error == "client_secret_expired":
                print("\nJWT has expired. Generate a fresh one.")
            elif error == "invalid_code":
                print("\nAuthorization code is invalid or expired.")
            elif error == "invalid_redirect_uri":
                print("\nRedirect URI doesn't match registered URI.")
        elif response.status_code == 401:
            print("❌ UNAUTHORIZED: Authentication required")
        elif response.status_code == 500:
            print("❌ SERVER ERROR: Backend error occurred")
        else:
            print(f"❌ UNEXPECTED STATUS: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ CONNECTION ERROR: Cannot connect to the server")
        print("   Make sure the StorX server is running on the specified URL")
    except requests.exceptions.Timeout:
        print("❌ TIMEOUT: Request timed out")
    except requests.exceptions.RequestException as e:
        print(f"❌ REQUEST ERROR: {e}")
    
    print("\n=== Debug Information ===")
    print("JWT Payload:")
    try:
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        print(json.dumps(decoded, indent=2))
    except Exception as e:
        print(f"Error decoding JWT: {e}")
    
    print(f"\nJWT Expiry: {time.ctime(decoded['exp'])}")
    print(f"Current Time: {time.ctime()}")

def test_with_different_payloads(base_url="http://localhost:10100"):
    """
    Test with different payload variations to isolate the issue.
    """
    
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    
    # Test 1: Minimal payload
    print("\n=== Test 1: Minimal Payload ===")
    jwt_token = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    
    minimal_payload = {
        "client_id": client_id,
        "client_secret": jwt_token
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/v0/oauth2/token",
            json=minimal_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 2: With all fields
    print("\n=== Test 2: Complete Payload ===")
    complete_payload = {
        "client_id": client_id,
        "client_secret": jwt_token,
        "redirect_uri": "https://myapp.com/callback",
        "code": "test_code",
        "passphrase": "test_passphrase"
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/v0/oauth2/token",
            json=complete_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("OAuth2 Token Endpoint Tester")
    print("=" * 50)
    
    # Test main endpoint
    test_token_endpoint()
    
    # Test with different payloads
    test_with_different_payloads() 