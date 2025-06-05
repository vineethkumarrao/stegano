#!/usr/bin/env python3
"""
Final Integration Test - Test the complete steganography analysis workflow
"""
import requests
import json
import time
import os
from pathlib import Path

def create_test_files():
    """Create test files for analysis"""
    print("📁 Creating test files...")
    
    # Create a simple text file
    text_content = "This is a test file for steganography analysis. It contains some test data that we can analyze for hidden content."
    with open("test_text.txt", "w") as f:
        f.write(text_content)
    
    # Create a simple image file using PIL
    try:
        from PIL import Image
        import numpy as np
        
        # Create a simple test image
        img_array = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        img = Image.fromarray(img_array)
        img.save("test_image.png")
        print("✅ Created test image: test_image.png")
    except Exception as e:
        print(f"⚠️ Could not create test image: {e}")
    
    print("✅ Test files created")

def test_backend_health():
    """Test backend health endpoint"""
    print("\n🏥 Testing backend health...")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print("✅ Backend health check passed")
            print(f"   Status: {health_data.get('status', 'Unknown')}")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend health check error: {e}")
        return False

def test_analyze_endpoint():
    """Test the analyze endpoint with different file types"""
    print("\n🔍 Testing /analyze endpoint...")
    
    test_files = [
        ("test_text.txt", "text/plain"),
    ]
    
    # Add image file if it exists
    if os.path.exists("test_image.png"):
        test_files.append(("test_image.png", "image/png"))
    
    results = []
    
    for filename, content_type in test_files:
        print(f"\n📄 Testing with {filename}...")
        
        try:
            with open(filename, 'rb') as f:
                files = {'file': (filename, f, content_type)}
                data = {
                    'analysis_type': 'basic',
                    'ai_enabled': 'false',
                    'forensics_enabled': 'false'
                }
                
                response = requests.post(
                    'http://localhost:8000/analyze',
                    files=files,
                    data=data,
                    timeout=60  # Give it more time for analysis
                )
                
            print(f"   Response Code: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    result_data = response.json()
                    print("   ✅ Analysis completed successfully")
                    print(f"   📊 Risk Score: {result_data.get('risk_score', 'N/A')}")
                    print(f"   🎯 Risk Level: {result_data.get('risk_level', 'N/A')}")
                    
                    # Check for analysis results
                    results_section = result_data.get('results', {})
                    if results_section:
                        print(f"   🔬 Analysis modules completed: {list(results_section.keys())}")
                    
                    results.append({"filename": filename, "success": True, "data": result_data})
                    
                except json.JSONDecodeError as e:
                    print(f"   ❌ Invalid JSON response: {e}")
                    print(f"   Response text: {response.text[:200]}...")
                    results.append({"filename": filename, "success": False, "error": "Invalid JSON"})
            else:
                print(f"   ❌ Analysis failed with status {response.status_code}")
                print(f"   Error: {response.text[:200]}...")
                results.append({"filename": filename, "success": False, "error": response.text})
                
        except Exception as e:
            print(f"   ❌ Request error: {e}")
            results.append({"filename": filename, "success": False, "error": str(e)})
    
    return results

def test_frontend():
    """Test if frontend is accessible"""
    print("\n🌐 Testing frontend accessibility...")
    
    try:
        response = requests.get("http://localhost:3000", timeout=5)
        if response.status_code == 200:
            print("✅ Frontend is accessible")
            return True
        else:
            print(f"❌ Frontend returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Frontend test error: {e}")
        return False

def cleanup_test_files():
    """Clean up test files"""
    print("\n🧹 Cleaning up test files...")
    
    test_files = ["test_text.txt", "test_image.png"]
    for filename in test_files:
        if os.path.exists(filename):
            os.remove(filename)
            print(f"   🗑️ Removed {filename}")

def main():
    """Run the complete integration test"""
    print("🚀 Starting Comprehensive Integration Test")
    print("=" * 50)
    
    # Create test files
    create_test_files()
    
    # Test backend health
    health_ok = test_backend_health()
    if not health_ok:
        print("\n❌ Backend health check failed. Stopping tests.")
        cleanup_test_files()
        return False
    
    # Test analyze endpoint
    analyze_results = test_analyze_endpoint()
    
    # Test frontend
    frontend_ok = test_frontend()
    
    # Summary
    print("\n📊 TEST SUMMARY")
    print("=" * 30)
    
    successful_analyses = sum(1 for r in analyze_results if r["success"])
    total_analyses = len(analyze_results)
    
    print(f"✅ Backend Health: {'PASS' if health_ok else 'FAIL'}")
    print(f"✅ Frontend Access: {'PASS' if frontend_ok else 'FAIL'}")
    print(f"✅ File Analysis: {successful_analyses}/{total_analyses} files processed successfully")
    
    if successful_analyses > 0:
        print("\n🎉 SUCCESS! The steganography analysis system is working!")
        print("   - Backend server is running and healthy")
        print("   - File analysis endpoint is functional")
        print("   - Analysis engines are processing files")
        
        if frontend_ok:
            print("   - Frontend is accessible")
            
        print("\n🌐 You can now:")
        print("   - Visit http://localhost:3000 for the web interface")
        print("   - Use http://localhost:8000/docs for API documentation")
        print("   - Upload files for steganography analysis")
        
    else:
        print("\n❌ FAILURE! There are issues with the analysis system.")
        print("   Check the error messages above for details.")
    
    # Cleanup
    cleanup_test_files()
    
    return successful_analyses > 0

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎯 Integration test completed successfully!")
    else:
        print("\n💥 Integration test failed!")
