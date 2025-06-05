#!/usr/bin/env python3
"""
Simple script to restart the backend server on DigitalOcean
"""
import subprocess
import sys
import time

# DigitalOcean droplet IP
DROPLET_IP = "64.23.144.46"

def restart_backend():
    """Restart the backend server"""
    print("Restarting backend server...")
    
    # Commands to run on the droplet
    commands = [
        # Kill any existing server process
        "pkill -f 'uvicorn main:app' || true",
        
        # Navigate to backend directory and activate virtual environment
        "cd /root/stegano/backend",
        "source venv/bin/activate",
        
        # Start the server in background
        "nohup uvicorn main:app --host 0.0.0.0 --port 8000 > server.log 2>&1 &",
        
        # Give it a moment to start
        "sleep 3",
        
        # Check if it's running
        "ps aux | grep uvicorn"
    ]
    
    # Combine commands with &&
    full_command = " && ".join(commands)
    
    try:
        # SSH into droplet and run commands
        ssh_command = [
            "ssh", "-o", "StrictHostKeyChecking=no", 
            f"root@{DROPLET_IP}", 
            full_command
        ]
        
        result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Backend server restarted successfully!")
            print("Server output:")
            print(result.stdout)
        else:
            print("❌ Error restarting server:")
            print(result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("⏰ SSH command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    
    return True

def check_backend_health():
    """Check if the backend is responding"""
    import requests
    
    try:
        response = requests.get(f"http://{DROPLET_IP}:8000/health", timeout=10)
        if response.status_code == 200:
            print("✅ Backend is healthy and responding!")
            print(f"Response: {response.json()}")
            return True
        else:
            print(f"❌ Backend responded with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Could not reach backend: {e}")
        return False

if __name__ == "__main__":
    print("🔄 Restarting Steganography Backend Server...")
    
    if restart_backend():
        print("\n⏳ Waiting for server to start...")
        time.sleep(5)
        
        print("\n🏥 Checking backend health...")
        if check_backend_health():
            print("\n🎉 All done! Backend is running and healthy.")
        else:
            print("\n⚠️ Backend started but health check failed. Check server logs.")
    else:
        print("\n💥 Failed to restart backend server.")
        sys.exit(1)
