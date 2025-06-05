# PowerShell Setup Script for Steganography Payload Scanner & Extractor
# This script will:
# 1. Install Python, Node.js, and Docker if not present
# 2. Set up Python virtual environment and install backend dependencies
# 3. Set up React frontend and install dependencies
# 4. (Optional) Set up PostgreSQL using Docker
# 5. Provide commands to run backend and frontend

# --- CONFIGURATION ---
$backendDir = "backend"
$frontendDir = "frontend"
$pythonVersion = "3.9"
$nodeVersion = "14.21.3"

Write-Host "==== Steganography Project Automated Setup ====" -ForegroundColor Cyan

# 1. Check and Install Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Please install Python $pythonVersion+ manually from https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
} else {
    $pyVer = python --version
    Write-Host "Found $pyVer"
}

# 2. Check and Install Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "Node.js not found. Please install Node.js $nodeVersion+ from https://nodejs.org/en/download/" -ForegroundColor Yellow
    exit 1
} else {
    $nodeVer = node --version
    Write-Host "Found Node.js $nodeVer"
}

# 3. Check and Install Docker
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker not found. Please install Docker Desktop from https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "Found Docker"
}

# 4. Create backend and frontend folders if not exist
if (-not (Test-Path $backendDir)) { mkdir $backendDir }
if (-not (Test-Path $frontendDir)) { mkdir $frontendDir }

# 5. Backend Setup
Write-Host "\n--- Setting up Python backend ---" -ForegroundColor Green
cd $backendDir
python -m venv venv
.\venv\Scripts\Activate.ps1
if (-not (Test-Path requirements.txt)) {
    Write-Host "Generating sample requirements.txt..." -ForegroundColor Yellow
    @"
fastapi
uvicorn
python-multipart
pillow
opencv-python
scipy
numpy
matplotlib
pyyaml
python-dotenv
psycopg2-binary
"@ | Out-File requirements.txt -Encoding utf8
}
pip install --upgrade pip
pip install -r requirements.txt
cd ..

# 6. Frontend Setup
Write-Host "\n--- Setting up React frontend ---" -ForegroundColor Green
cd $frontendDir
if (-not (Test-Path package.json)) {
    npx create-react-app .
}
npm install
cd ..

# 7. (Optional) PostgreSQL via Docker
Write-Host "\n--- Setting up PostgreSQL (Docker) ---" -ForegroundColor Green
if (-not (docker ps -a | Select-String "stegano-postgres")) {
    docker run --name stegano-postgres -e POSTGRES_PASSWORD=stegano -e POSTGRES_USER=stegano -e POSTGRES_DB=stegano -p 5432:5432 -d postgres:14
    Write-Host "Started PostgreSQL container on port 5432 (user: stegano, pass: stegano, db: stegano)" -ForegroundColor Green
} else {
    Write-Host "PostgreSQL container already exists. Skipping." -ForegroundColor Yellow
}

# 8. Final Instructions
Write-Host "\n==== Setup Complete! ====" -ForegroundColor Cyan
Write-Host "To start the backend:"
Write-Host "cd $backendDir; .\\venv\\Scripts\\Activate.ps1; uvicorn main:app --reload" -ForegroundColor Yellow
Write-Host "To start the frontend:"
Write-Host "cd $frontendDir; npm start" -ForegroundColor Yellow
Write-Host "To stop PostgreSQL: docker stop stegano-postgres" -ForegroundColor Yellow
Write-Host "To remove PostgreSQL: docker rm stegano-postgres" -ForegroundColor Yellow
Write-Host "\nFor more, see the README or project documentation."
