#!/usr/bin/env python3
"""
Complete Frontend-Backend Integration Test
Tests the exact workflow that the user is experiencing
"""
import requests
import json
import time

def test_backend_health():
    """Test if backend is responsive"""
    print("🏥 Testing Backend Health...")
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            health = response.json()
            print("✅ Backend is healthy")
            print(f"   Status: {health.get('status')}")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend not accessible: {e}")
        return False

def test_analyze_endpoint_with_image():
    """Test analyze endpoint with an actual image file"""
    print("\n🖼️ Testing /analyze endpoint with image file...")
    
    # Create a simple test image (PNG format)
    try:
        from PIL import Image
        import numpy as np
        
        # Create a small test image
        img_array = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        img = Image.fromarray(img_array)
        img.save("test_image_analysis.png")
        print("✅ Created test image: test_image_analysis.png")
        
    except ImportError:
        print("⚠️ PIL not available, creating text file instead")
        with open("test_image_analysis.txt", 'w') as f:
            f.write("This is a test file that simulates an image for analysis.")
        test_file = "test_image_analysis.txt"
        content_type = "text/plain"
    else:
        test_file = "test_image_analysis.png"
        content_type = "image/png"
    
    try:
        # Test with the exact parameters the frontend sends
        with open(test_file, 'rb') as f:
            files = {'file': (test_file, f, content_type)}
            data = {
                'analysis_type': 'comprehensive',
                'ai_enabled': 'true',
                'forensics_enabled': 'true'
            }
            
            print(f"📤 Sending analysis request...")
            print(f"   File: {test_file}")
            print(f"   Analysis Type: comprehensive")
            print(f"   AI Enabled: true")
            print(f"   Forensics Enabled: true")
            
            response = requests.post(
                'http://localhost:8000/analyze',
                files=files,
                data=data,
                timeout=60
            )
            
        print(f"📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                result = response.json()
                print("✅ Analysis completed successfully!")
                print(f"   📁 Filename: {result.get('filename')}")
                print(f"   📊 Risk Score: {result.get('risk_score')}")
                print(f"   🎯 Risk Level: {result.get('risk_level')}")
                print(f"   🔬 Analysis Type: {result.get('analysis_type')}")
                
                # Check what analysis modules ran
                results_section = result.get('results', {})
                if results_section:
                    print(f"   🧪 Completed Analyses: {', '.join(results_section.keys())}")
                    
                    # Check for specific results
                    if 'steganography' in results_section:
                        stego = results_section['steganography']
                        print(f"   🕵️ Steganography Detection: {stego.get('status', 'Unknown')}")
                    
                    if 'entropy' in results_section:
                        entropy = results_section['entropy']
                        print(f"   📈 Entropy Analysis: {entropy.get('status', 'Unknown')}")
                        
                return True
                
            except json.JSONDecodeError:
                print(f"❌ Invalid JSON response")
                print(f"   Raw response: {response.text[:200]}...")
                return False
                
        elif response.status_code == 404:
            print("❌ Endpoint not found - /analyze endpoint doesn't exist")
            return False
        elif response.status_code == 422:
            print("❌ Validation error - check request format")
            print(f"   Error details: {response.text}")
            return False
        elif response.status_code == 500:
            print("❌ Internal server error")
            print(f"   Error details: {response.text[:200]}...")
            return False
        else:
            print(f"❌ Unexpected response: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection refused - backend server not running")
        return False
    except requests.exceptions.Timeout:
        print("❌ Request timeout - analysis taking too long")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    finally:
        # Cleanup
        import os
        for cleanup_file in ["test_image_analysis.png", "test_image_analysis.txt"]:
            if os.path.exists(cleanup_file):
                os.remove(cleanup_file)

def test_frontend_api_compatibility():
    """Test the exact API calls the frontend makes"""
    print("\n🌐 Testing Frontend-Backend API Compatibility...")
    
    # Simulate exact frontend API call structure
    test_data = b"Frontend compatibility test file content"
    
    try:
        files = {'file': ('frontend_test.txt', test_data, 'text/plain')}
        
        # These are the exact parameters the frontend sends after our fix
        data = {
            'analysis_type': 'basic',  # Default for minimal options
            'ai_enabled': 'false',
            'forensics_enabled': 'false'
        }
        
        print("📤 Testing basic analysis (minimal options)...")
        response = requests.post(
            'http://localhost:8000/analyze',
            files=files,
            data=data,
            timeout=30
        )
        
        if response.status_code == 200:
            print("✅ Basic analysis API call successful")
            
            # Test comprehensive analysis
            data_comprehensive = {
                'analysis_type': 'comprehensive',
                'ai_enabled': 'true', 
                'forensics_enabled': 'true'
            }
            
            files = {'file': ('frontend_test.txt', test_data, 'text/plain')}
            response2 = requests.post(
                'http://localhost:8000/analyze',
                files=files,
                data=data_comprehensive,
                timeout=30
            )
            
            if response2.status_code == 200:
                print("✅ Comprehensive analysis API call successful")
                return True
            else:
                print(f"❌ Comprehensive analysis failed: {response2.status_code}")
                return False
        else:
            print(f"❌ Basic analysis failed: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"❌ API compatibility test failed: {e}")
        return False

def main():
    """Run all integration tests"""
    print("🚀 COMPLETE FRONTEND-BACKEND INTEGRATION TEST")
    print("=" * 55)
    
    # Test 1: Backend Health
    health_ok = test_backend_health()
    if not health_ok:
        print("\n💥 Backend is not running or accessible!")
        print("   Please ensure the backend server is started")
        return False
    
    # Test 2: Analyze Endpoint
    analyze_ok = test_analyze_endpoint_with_image()
    
    # Test 3: Frontend API Compatibility
    api_ok = test_frontend_api_compatibility()
    
    # Summary
    print("\n" + "=" * 55)
    print("📊 TEST SUMMARY")
    print(f"✅ Backend Health: {'PASS' if health_ok else 'FAIL'}")
    print(f"✅ Analyze Endpoint: {'PASS' if analyze_ok else 'FAIL'}")
    print(f"✅ Frontend API Compatibility: {'PASS' if api_ok else 'FAIL'}")
    
    if health_ok and analyze_ok and api_ok:
        print("\n🎉 ALL TESTS PASSED!")
        print("   The 'Not Found' error should now be resolved")
        print("   Try uploading a file in the web interface again")
        return True
    else:
        print("\n❌ SOME TESTS FAILED")
        print("   There are still issues that need to be addressed")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎯 Integration test completed successfully!")
        print("   Frontend should now communicate properly with backend")
    else:
        print("\n💥 Integration test revealed issues that need fixing")
