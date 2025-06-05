#!/usr/bin/env python3
"""
Test the /analyze endpoint directly
"""
import requests
import os

def test_analyze_endpoint():
    print("🧪 Testing /analyze endpoint...")
    
    # Create a test file
    test_content = b"This is a test file for steganography analysis."
    test_filename = "test_analysis.txt"
    
    with open(test_filename, 'wb') as f:
        f.write(test_content)
    
    try:
        # Test the analyze endpoint
        with open(test_filename, 'rb') as f:
            files = {'file': (test_filename, f, 'text/plain')}
            data = {
                'analysis_type': 'basic',
                'ai_enabled': 'false',
                'forensics_enabled': 'false'
            }
            
            print(f"📤 Sending request to http://localhost:8000/analyze")
            print(f"   File: {test_filename}")
            print(f"   Data: {data}")
            
            response = requests.post(
                'http://localhost:8000/analyze',
                files=files,
                data=data,
                timeout=30
            )
            
        print(f"📥 Response received:")
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Analysis successful!")
            print(f"   Filename: {result.get('filename', 'N/A')}")
            print(f"   Risk Score: {result.get('risk_score', 'N/A')}")
            print(f"   Risk Level: {result.get('risk_level', 'N/A')}")
            print(f"   Analysis Results: {list(result.get('results', {}).keys())}")
            return True
        else:
            print(f"❌ Analysis failed!")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend server (http://localhost:8000)")
        print("   Make sure the backend server is running!")
        return False
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        return False
    finally:
        # Cleanup
        if os.path.exists(test_filename):
            os.remove(test_filename)

if __name__ == "__main__":
    success = test_analyze_endpoint()
    if success:
        print("\n🎉 Backend /analyze endpoint is working correctly!")
    else:
        print("\n💥 Backend /analyze endpoint has issues.")
