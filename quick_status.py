#!/usr/bin/env python3
"""
Quick Status Check - Verify system is operational
"""
import requests
import json

def quick_status_check():
    print("🔍 Quick System Status Check")
    print("=" * 40)
    
    # Test backend health
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print("✅ Backend Health: ONLINE")
            print(f"   Status: {health_data.get('status', 'Unknown')}")
            print(f"   Systems: {health_data.get('systems_status', {})}")
        else:
            print(f"❌ Backend Health: OFFLINE (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"❌ Backend Health: ERROR - {e}")
        return False
    
    # Test frontend
    try:
        response = requests.get("http://localhost:3000", timeout=5)
        if response.status_code == 200:
            print("✅ Frontend: ONLINE")
        else:
            print(f"❌ Frontend: OFFLINE (Status: {response.status_code})")
    except Exception as e:
        print(f"❌ Frontend: ERROR - {e}")
    
    # Test analyze endpoint with a simple request
    print("\n🧪 Testing /analyze endpoint...")
    try:
        # Create a small test file
        test_content = b"Hello, this is a test file for steganography analysis!"
        files = {'file': ('test.txt', test_content, 'text/plain')}
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
        
        if response.status_code == 200:
            result = response.json()
            print("✅ /analyze endpoint: WORKING")
            print(f"   Risk Score: {result.get('risk_score', 'N/A')}")
            print(f"   Analysis completed for: {result.get('filename', 'Unknown')}")
            return True
        else:
            print(f"❌ /analyze endpoint: FAILED (Status: {response.status_code})")
            print(f"   Error: {response.text[:100]}...")
            return False
            
    except Exception as e:
        print(f"❌ /analyze endpoint: ERROR - {e}")
        return False

if __name__ == "__main__":
    success = quick_status_check()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 SYSTEM STATUS: FULLY OPERATIONAL")
        print("\n🌐 Access Points:")
        print("   • Web Interface: http://localhost:3000")
        print("   • API Documentation: http://localhost:8000/docs")
        print("   • Health Check: http://localhost:8000/health")
        print("\n✨ Ready for steganography analysis!")
    else:
        print("⚠️  SYSTEM STATUS: PARTIAL FUNCTIONALITY")
        print("   Some components may need attention.")
