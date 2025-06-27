#!/usr/bin/env python3
"""
JWT Client Secret Generator for StorX OAuth2 Token Request

This script creates a JWT client_secret according to the OAuth2 token workplan:
- Header: {"alg": "HS256", "typ": "JWT"}
- Payload: {"client_id": "...", "exp": unix_timestamp}
- Signed with the actual client_secret as HMAC key
"""

import json
import time
import jwt
from datetime import datetime, timedelta

def create_jwt_client_secret(client_id, client_secret, expiry_minutes=5):
    """
    Create a JWT client_secret for OAuth2 token request.
    
    Args:
        client_id (str): The client ID
        client_secret (str): The actual client secret used as HMAC key
        expiry_minutes (int): JWT expiry time in minutes (default: 5)
    
    Returns:
        str: JWT token string
    """
    
    # Calculate expiry timestamp (current time + expiry_minutes)
    expiry_timestamp = int(time.time()) + (expiry_minutes * 60)
    
    # JWT payload as specified in the workplan
    payload = {
        "client_id": client_id,
        "exp": expiry_timestamp
    }
    
    # Create JWT with HS256 algorithm
    jwt_token = jwt.encode(
        payload,
        client_secret,
        algorithm="HS256",
        headers={"typ": "JWT"}
    )
    
    return jwt_token

def main():
    # Client credentials from the provided data
    client_id = "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
    client_secret = "2b4719e00623ad66c4cde8681efc59e9d40bf96cdb43d4b9cf859e27d5252102"
    
    # Create JWT client_secret
    jwt_client_secret = create_jwt_client_secret(client_id, client_secret)
    
    # Display results
    print("=== JWT Client Secret Generator ===")
    print(f"Client ID: {client_id}")
    print(f"Client Secret: {client_secret}")
    print(f"JWT Client Secret: {jwt_client_secret}")
    print()
    
    # Decode and display JWT payload for verification
    try:
        decoded_payload = jwt.decode(jwt_client_secret, client_secret, algorithms=["HS256"])
        print("=== JWT Payload (Decoded) ===")
        print(json.dumps(decoded_payload, indent=2))
        print()
        
        # Show expiry information
        exp_timestamp = decoded_payload["exp"]
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        current_time = datetime.now()
        
        print("=== Expiry Information ===")
        print(f"Current Time: {current_time}")
        print(f"Expiry Time: {exp_datetime}")
        print(f"Time Remaining: {exp_datetime - current_time}")
        print()
        
    except jwt.ExpiredSignatureError:
        print("ERROR: JWT has expired!")
    except jwt.InvalidTokenError as e:
        print(f"ERROR: Invalid JWT: {e}")
    
    # Example curl request
    print("=== Example curl Request ===")
    print("""curl -X POST \\
  http://localhost:10100/api/v0/oauth2/token \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_id": "%s",
    "client_secret": "%s",
    "redirect_uri": "https://myapp.com/callback",
    "code": "AUTH_CODE_FROM_CONSENT",
    "passphrase": "your-passphrase"
  }'""" % (client_id, jwt_client_secret))

if __name__ == "__main__":
    main() 