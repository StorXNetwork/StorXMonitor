#!/usr/bin/env python3
"""
Test script for OAuth2 Token Endpoint - User's Specific Setup

This script tests the /oauth2/token endpoint with the user's specific configuration:
- Server: http://localhost:10002
- Authorization Code: 84feaa9c-6782-417b-b77c-f9642b5562ff
"""

import json
import requests
import time
import jwt

def test_with_user_config():
    """
    Test with the user's specific configuration.
    """
    
    # User's configuration
    base_url = "http://localhost:10002"
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    auth_code = "84feaa9c-6782-417b-b77c-f9642b5562ff"
    
    # Create fresh JWT
    jwt_token = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    
    # Request payload (matching user's curl request)
    payload = {
        "client_id": client_id,
        "client_secret": jwt_token,
        "redirect_uri": "https://myapp.com/callback",
        "code": auth_code,
        "passphrase": ""
    }
    
    # Headers (matching user's curl request)
    headers = {
        "Accept": "*/*",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "DNT": "1",
        "Origin": "http://localhost:10002",
        "Referer": f"http://localhost:10002/oauth2-integration?client_id={client_id}&client_secret={jwt_token}&redirect_uri=https://myapp.com/callback&scope=read,write",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"'
    }
    
    # Make request
    url = f"{base_url}/api/v0/oauth2/token"
    
    print("=== Testing Your OAuth2 Token Endpoint ===")
    print(f"URL: {url}")
    print(f"Client ID: {client_id}")
    print(f"Auth Code: {auth_code}")
    print(f"Fresh JWT: {jwt_token}")
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
        print("   Make sure the StorX server is running on http://localhost:10002")
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

def test_with_minimal_headers():
    """
    Test with minimal headers to isolate the issue.
    """
    
    base_url = "http://localhost:10002"
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    auth_code = "84feaa9c-6782-417b-b77c-f9642b5562ff"
    
    # Create fresh JWT
    jwt_token = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    
    # Minimal payload
    payload = {
        "client_id": client_id,
        "client_secret": jwt_token,
        "redirect_uri": "https://myapp.com/callback",
        "code": auth_code,
        "passphrase": ""
    }
    
    # Minimal headers
    headers = {
        "Content-Type": "application/json"
    }
    
    url = f"{base_url}/api/v0/oauth2/token"
    
    print("\n=== Test with Minimal Headers ===")
    print(f"URL: {url}")
    print(f"JWT: {jwt_token}")
    print()
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

def generate_curl_command():
    """
    Generate the exact curl command for the user.
    """
    
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    auth_code = "84feaa9c-6782-417b-b77c-f9642b5562ff"
    
    # Create fresh JWT
    jwt_token = jwt.encode(
        {"client_id": client_id, "exp": int(time.time()) + 300},
        client_secret,
        algorithm="HS256"
    )
    
    print("\n=== Fresh curl Command ===")
    print("Use this curl command with the fresh JWT:")
    print()
    
    curl_command = f"""curl --location 'http://localhost:10002/api/v0/oauth2/token' \\
--header 'Content-Type: application/json' \\
--data '{{
    "client_id": "{client_id}",
    "client_secret": "{jwt_token}",
    "redirect_uri": "https://myapp.com/callback",
    "code": "{auth_code}",
    "passphrase": ""
}}'"""
    
    print(curl_command)
    print()
    print(f"Fresh JWT: {jwt_token}")

if __name__ == "__main__":
    print("OAuth2 Token Endpoint Tester - User's Setup")
    print("=" * 60)
    
    # Test with user's configuration
    test_with_user_config()
    
    # Test with minimal headers
    test_with_minimal_headers()
    
    # Generate fresh curl command
    generate_curl_command() 