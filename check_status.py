#!/usr/bin/env python3
"""
Quick status check for Steganography Scanner
Run this to verify both frontend and backend are running
"""

import requests
import subprocess
import sys
from urllib.parse import urlparse

def check_service(url, name):
    """Check if a service is running at the given URL"""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"✅ {name} is running at {url}")
            return True
        else:
            print(f"⚠️ {name} responded with status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ {name} is not running at {url}")
        return False
    except requests.exceptions.Timeout:
        print(f"⏱️ {name} timed out at {url}")
        return False
    except Exception as e:
        print(f"❌ {name} error: {e}")
        return False

def main():
    print("🔍 Steganography Scanner - Service Status Check")
    print("=" * 50)
    
    # Check backend
    backend_running = check_service("http://localhost:8000/health", "Backend API")
    
    # Check frontend
    frontend_running = check_service("http://localhost:3000", "Frontend App")
    
    print("\n📊 Summary:")
    if backend_running and frontend_running:
        print("🎉 All services are running! Open http://localhost:3000 to use the app.")
    elif backend_running:
        print("⚠️ Backend is running, but frontend needs to be started.")
        print("💡 Run: cd frontend && npm start")
    elif frontend_running:
        print("⚠️ Frontend is running, but backend needs to be started.")
        print("💡 Run: cd backend && python main.py")
    else:
        print("❌ Neither service is running. Start both servers:")
        print("💡 Backend: cd backend && python main.py")
        print("💡 Frontend: cd frontend && npm start")
    
    return 0 if (backend_running and frontend_running) else 1

if __name__ == "__main__":
    sys.exit(main())
