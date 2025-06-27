#!/usr/bin/env python3
"""
Script to register an OAuth2 client in the StorX database.

This script registers the OAuth2 client that we're using for testing.
"""

import json
import requests

def register_oauth_client():
    """
    Register the OAuth2 client in the database.
    """
    
    # Client registration data
    client_data = {
        "name": "New Test App",
        "redirect_uris": ["https://myapp.com/callback"]
    }
    
    # Headers
    headers = {
        "Content-Type": "application/json"
    }
    
    # Make request to register client
    url = "http://localhost:10002/api/v0/developer/auth/oauth2/clients"
    
    print("=== Registering OAuth2 Client ===")
    print(f"URL: {url}")
    print(f"Client Data: {json.dumps(client_data, indent=2)}")
    print()
    
    try:
        response = requests.post(url, json=client_data, headers=headers, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print()
        
        try:
            response_json = response.json()
            print("Response Body:")
            print(json.dumps(response_json, indent=2))
            
            if response.status_code == 200:
                print("\n✅ SUCCESS: OAuth2 client registered!")
                print(f"Client ID: {response_json.get('client_id')}")
                print(f"Client Secret: {response_json.get('client_secret')}")
                print("\n⚠️  IMPORTANT: Save the client_secret securely - it won't be shown again!")
                
                # Create a credentials file
                save_credentials(response_json.get('client_id'), response_json.get('client_secret'))
                
            else:
                print(f"\n❌ ERROR: Failed to register client")
                
        except json.JSONDecodeError:
            print("Response Body (not JSON):")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print("❌ CONNECTION ERROR: Cannot connect to the server")
        print("   Make sure the StorX server is running on http://localhost:10002")
    except requests.exceptions.Timeout:
        print("❌ TIMEOUT: Request timed out")
    except requests.exceptions.RequestException as e:
        print(f"❌ REQUEST ERROR: {e}")

def save_credentials(client_id, client_secret):
    """
    Save the client credentials to a file for use in test scripts.
    """
    credentials = {
        "client_id": client_id,
        "client_secret": client_secret
    }
    
    with open("oauth_client_credentials.json", "w") as f:
        json.dump(credentials, f, indent=2)
    
    print("\n✅ Saved credentials to oauth_client_credentials.json")
    print("You can now use these credentials in your test scripts.")

if __name__ == "__main__":
    register_oauth_client() 