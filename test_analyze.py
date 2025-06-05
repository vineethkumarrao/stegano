#!/usr/bin/env python3
"""
Simple test for the /analyze endpoint
"""
import requests
import os

def test_analyze_endpoint():
    print("Testing /analyze endpoint...")
    
    # Create a simple test file
    test_content = "This is a test file for steganography analysis."
    test_file = "test_upload.txt"
    
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    try:
        # Test the analyze endpoint
        with open(test_file, 'rb') as f:
            files = {'file': (test_file, f, 'text/plain')}
            data = {
                'analysis_type': 'basic',
                'ai_enabled': 'false',
                'forensics_enabled': 'false'
            }
            
            response = requests.post(
                'http://localhost:8000/analyze',
                files=files,
                data=data,
                timeout=30
            )
            
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:500]}...")
        
        if response.status_code == 200:
            print("✅ /analyze endpoint is working!")
            return True
        else:
            print(f"❌ /analyze endpoint failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing analyze endpoint: {e}")
        return False
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    test_analyze_endpoint()
