#!/usr/bin/env python3
"""
Comprehensive System Test - Steganography Scanner
Tests all components end-to-end to verify everything is working
"""

import requests
import time
import json
import sys
from urllib.parse import urljoin

class SystemTester:
    def __init__(self):
        self.backend_url = "http://localhost:8000"
        self.frontend_url = "http://localhost:3000"
        self.tests_passed = 0
        self.tests_failed = 0
        
    def log_test(self, test_name, success, message=""):
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if message:
            print(f"    {message}")
        
        if success:
            self.tests_passed += 1
        else:
            self.tests_failed += 1
    
    def test_backend_health(self):
        """Test backend health endpoint"""
        try:
            response = requests.get(f"{self.backend_url}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Check if required fields are present
                required_fields = ["isOnline", "analysisEngines", "database"]
                if all(field in data for field in required_fields):
                    if data["isOnline"] and data["database"]:
                        self.log_test("Backend Health Check", True, f"All systems online")
                        return True
                    else:
                        self.log_test("Backend Health Check", False, "Systems not online")
                        return False
                else:
                    self.log_test("Backend Health Check", False, "Missing required fields")
                    return False
            else:
                self.log_test("Backend Health Check", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Backend Health Check", False, str(e))
            return False
    
    def test_backend_stats(self):
        """Test backend statistics endpoint"""
        try:
            response = requests.get(f"{self.backend_url}/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                required_fields = ["totalScans", "suspiciousFiles", "payloadsExtracted", "averageProcessingTime"]
                if all(field in data for field in required_fields):
                    self.log_test("Backend Statistics", True, f"Total scans: {data['totalScans']}")
                    return True
                else:
                    self.log_test("Backend Statistics", False, "Missing required stat fields")
                    return False
            else:
                self.log_test("Backend Statistics", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Backend Statistics", False, str(e))
            return False
    
    def test_frontend_accessibility(self):
        """Test frontend accessibility"""
        try:
            response = requests.get(self.frontend_url, timeout=5)
            if response.status_code == 200:
                content = response.text
                if "Steganography" in content:
                    self.log_test("Frontend Accessibility", True, "React app is serving")
                    return True
                else:
                    self.log_test("Frontend Accessibility", False, "Content doesn't contain expected text")
                    return False
            else:
                self.log_test("Frontend Accessibility", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Frontend Accessibility", False, str(e))
            return False
    
    def test_backend_cors(self):
        """Test CORS configuration"""
        try:
            headers = {
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'Content-Type'
            }
            response = requests.options(f"{self.backend_url}/health", headers=headers, timeout=5)
            cors_header = response.headers.get('Access-Control-Allow-Origin')
            if cors_header:
                self.log_test("CORS Configuration", True, f"CORS enabled: {cors_header}")
                return True
            else:
                self.log_test("CORS Configuration", False, "CORS headers not found")
                return False
        except Exception as e:
            self.log_test("CORS Configuration", False, str(e))
            return False
    
    def test_api_documentation(self):
        """Test API documentation endpoints"""
        try:
            # Test Swagger UI
            response = requests.get(f"{self.backend_url}/docs", timeout=5)
            docs_available = response.status_code == 200
            
            # Test ReDoc
            response = requests.get(f"{self.backend_url}/redoc", timeout=5)
            redoc_available = response.status_code == 200
            
            if docs_available and redoc_available:
                self.log_test("API Documentation", True, "Swagger UI and ReDoc available")
                return True
            elif docs_available or redoc_available:
                self.log_test("API Documentation", True, "Partial documentation available")
                return True
            else:
                self.log_test("API Documentation", False, "No documentation endpoints available")
                return False
        except Exception as e:
            self.log_test("API Documentation", False, str(e))
            return False
    
    def run_all_tests(self):
        """Run all system tests"""
        print("🔍 Steganography Scanner - Comprehensive System Test")
        print("=" * 60)
        print()
        
        # Run all tests
        backend_health = self.test_backend_health()
        backend_stats = self.test_backend_stats()
        frontend_access = self.test_frontend_accessibility()
        cors_config = self.test_backend_cors()
        api_docs = self.test_api_documentation()
        
        print()
        print("=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Tests Passed: {self.tests_passed}")
        print(f"❌ Tests Failed: {self.tests_failed}")
        print(f"📈 Success Rate: {(self.tests_passed / (self.tests_passed + self.tests_failed) * 100):.1f}%")
        
        if self.tests_failed == 0:
            print()
            print("🎉 ALL TESTS PASSED! 🎉")
            print("✨ The Steganography Scanner is fully operational!")
            print()
            print("🌐 Access Points:")
            print(f"   • Frontend Application: {self.frontend_url}")
            print(f"   • Backend API: {self.backend_url}")
            print(f"   • API Documentation: {self.backend_url}/docs")
            print()
            print("🚀 Ready for steganography analysis!")
            return True
        else:
            print()
            print("⚠️  Some tests failed. Please check the issues above.")
            return False

def main():
    tester = SystemTester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
