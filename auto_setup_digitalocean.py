import requests
import time
import json
import sys

# User must provide their DigitalOcean API token here
API_TOKEN = "YOUR_DIGITALOCEAN_API_TOKEN_HERE"
HEADERS = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}

# 1. Create a new droplet
DROPLET_NAME = "stegano-backend-auto"
REGION = "nyc3"  # You can change to your preferred region
SIZE = "s-1vcpu-1gb"  # Smallest size (free/cheap)
IMAGE = "ubuntu-22-04-x64"
SSH_KEYS = []  # Add your SSH key fingerprints here for secure access

# 2. Cloud-init script to install all tools and run backend
CLOUD_INIT = '''
#cloud-config
runcmd:
  - apt-get update
  - apt-get upgrade -y
  - apt-get install -y python3 python3-pip git binwalk foremost libimage-exiftool-perl
  - git clone https://github.com/vineethkumarrao/stegano.git /root/stegano
  - pip3 install -r /root/stegano/backend/requirements.txt
  - cd /root/stegano/backend && nohup python3 main.py &
'''

# 3. Create droplet request
create_data = {
    "name": DROPLET_NAME,
    "region": REGION,
    "size": SIZE,
    "image": IMAGE,
    "ssh_keys": SSH_KEYS,
    "user_data": CLOUD_INIT,
    "backups": False,
    "ipv6": True,
    "tags": ["stegano-auto"]
}

print("Creating droplet...")
resp = requests.post("https://api.digitalocean.com/v2/droplets", headers=HEADERS, data=json.dumps(create_data))
if resp.status_code != 202:
    print("Failed to create droplet:", resp.text)
    sys.exit(1)

droplet = resp.json()["droplet"]
droplet_id = droplet["id"]
print(f"Droplet created with ID: {droplet_id}")

# 4. Wait for droplet to become active and get public IP
print("Waiting for droplet to become active and get public IP...")
public_ip = None
for _ in range(30):
    time.sleep(10)
    r = requests.get(f"https://api.digitalocean.com/v2/droplets/{droplet_id}", headers=HEADERS)
    d = r.json()["droplet"]
    if d["status"] == "active":
        for net in d["networks"]["v4"]:
            if net["type"] == "public":
                public_ip = net["ip_address"]
                break
    if public_ip:
        break
    print("Still waiting...")

if not public_ip:
    print("Failed to get public IP. Check your DigitalOcean dashboard.")
    sys.exit(1)

print(f"Droplet is ready! Public IP: {public_ip}")
print(f"Your backend API will be available at http://{public_ip}:8000 once setup completes.")
