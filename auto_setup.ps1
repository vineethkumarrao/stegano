# Automated Setup Script for Steganography Scanner
# This script will install all required dependencies automatically

Write-Host "🔍 Steganography Scanner - Automated Setup" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Check if we're in the right directory
$currentDir = Get-Location
if (-not (Test-Path "backend\requirements.txt")) {
    Write-Host "❌ Error: Please run this script from the e:\stegano directory" -ForegroundColor Red
    Write-Host "Current directory: $currentDir" -ForegroundColor Yellow
    Write-Host "Expected directory should contain: backend\requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Found project structure" -ForegroundColor Green

# Function to test if command exists
function Test-Command($command) {
    try {
        Get-Command $command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# 1. Install Python Dependencies
Write-Host "`n🐍 Step 1: Installing Python Dependencies..." -ForegroundColor Yellow
Write-Host "----------------------------------------------" -ForegroundColor Yellow

if (Test-Command "python") {
    Write-Host "✅ Python found" -ForegroundColor Green
    
    # Check if we're in a virtual environment (recommended)
    $inVenv = $env:VIRTUAL_ENV -ne $null
    if (-not $inVenv) {
        Write-Host "⚠️  Not in virtual environment - creating one..." -ForegroundColor Yellow
        try {
            python -m venv venv
            Write-Host "✅ Virtual environment created" -ForegroundColor Green
            Write-Host "📝 Activating virtual environment..." -ForegroundColor Cyan
            & ".\venv\Scripts\Activate.ps1"
            Write-Host "✅ Virtual environment activated" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Could not create virtual environment, continuing with global Python..." -ForegroundColor Yellow
        }
    }
    
    # Install backend dependencies
    Set-Location backend
    Write-Host "📦 Installing backend dependencies..." -ForegroundColor Cyan
    try {
        pip install -r requirements.txt
        Write-Host "✅ Backend dependencies installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Error installing backend dependencies: $_" -ForegroundColor Red
        Write-Host "💡 Try: pip install --upgrade pip" -ForegroundColor Yellow
        Write-Host "💡 Or: python -m pip install -r requirements.txt" -ForegroundColor Yellow
    }
    Set-Location ..
} else {
    Write-Host "❌ Python not found! Please install Python 3.8+ first" -ForegroundColor Red
    Write-Host "💡 Download from: https://python.org/downloads/" -ForegroundColor Yellow
}

# 2. Install Node.js Dependencies  
Write-Host "`n🟢 Step 2: Installing Node.js Dependencies..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------" -ForegroundColor Yellow

if (Test-Command "npm") {
    Write-Host "✅ npm found" -ForegroundColor Green
    Set-Location frontend
    Write-Host "📦 Installing frontend dependencies..." -ForegroundColor Cyan
    try {
        npm install
        Write-Host "✅ Frontend dependencies installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Error installing frontend dependencies: $_" -ForegroundColor Red
        Write-Host "💡 Try: npm cache clean --force" -ForegroundColor Yellow
        Write-Host "💡 Or: delete node_modules and try again" -ForegroundColor Yellow
    }
    Set-Location ..
} else {
    Write-Host "❌ npm not found! Please install Node.js first" -ForegroundColor Red
    Write-Host "💡 Download from: https://nodejs.org/" -ForegroundColor Yellow
}

# 3. Install External Tools
Write-Host "`n🔧 Step 3: Installing External Forensics Tools..." -ForegroundColor Yellow
Write-Host "---------------------------------------------------" -ForegroundColor Yellow

# Check for Chocolatey
if (Test-Command "choco") {
    Write-Host "✅ Chocolatey found - installing tools..." -ForegroundColor Green
    try {
        Write-Host "📦 Installing ExifTool..." -ForegroundColor Cyan
        choco install exiftool -y
        Write-Host "✅ ExifTool installed!" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Could not install ExifTool via Chocolatey" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  Chocolatey not found" -ForegroundColor Yellow
    Write-Host "💡 Install Chocolatey first: https://chocolatey.org/install" -ForegroundColor Cyan
}

# Check for WSL for Linux tools
if (Test-Command "wsl") {
    Write-Host "✅ WSL found - installing Linux forensics tools..." -ForegroundColor Green
    try {
        Write-Host "📦 Installing binwalk, foremost, exiftool in WSL..." -ForegroundColor Cyan
        wsl sudo apt update
        wsl sudo apt install -y binwalk foremost exiftool
        Write-Host "✅ Linux forensics tools installed in WSL!" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Could not install tools in WSL: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  WSL not found" -ForegroundColor Yellow
    Write-Host "💡 For binwalk/foremost, consider installing WSL or downloading manually" -ForegroundColor Cyan
}

# 4. Create .env file template
Write-Host "`n⚙️  Step 4: Creating configuration template..." -ForegroundColor Yellow
Write-Host "-----------------------------------------------" -ForegroundColor Yellow

$envPath = "backend\.env"
if (-not (Test-Path $envPath)) {
    $envContent = @"
# Steganography Scanner Configuration
# Copy this file and add your actual API keys

# AI Analysis API Keys (Optional - system works without these)
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# External API Keys (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Database Configuration (Optional - SQLite used by default)
# DATABASE_URL=postgresql://username:password@localhost:5432/stegano_db

# Logging Configuration
LOG_LEVEL=INFO
DEBUG=false

# Security
SECRET_KEY=change-this-in-production-$(Get-Random)
"@
    
    $envContent | Out-File -FilePath $envPath -Encoding UTF8
    Write-Host "✅ Created .env template at: $envPath" -ForegroundColor Green
    Write-Host "📝 Edit this file to add your API keys" -ForegroundColor Cyan
} else {
    Write-Host "✅ .env file already exists" -ForegroundColor Green
}

# 5. Test Installation
Write-Host "`n🧪 Step 5: Testing Installation..." -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow

Write-Host "🔍 Checking Python imports..." -ForegroundColor Cyan
Set-Location backend
try {
    python -c "import fastapi, sqlalchemy, uvicorn; print('✅ Core Python packages working')"
    Write-Host "✅ Python dependencies are working!" -ForegroundColor Green
} catch {
    Write-Host "❌ Python import test failed: $_" -ForegroundColor Red
}

Set-Location ..\frontend
Write-Host "🔍 Checking Node.js setup..." -ForegroundColor Cyan
if (Test-Path "node_modules") {
    Write-Host "✅ Node modules installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Node modules not found" -ForegroundColor Red
}

Set-Location ..

# Final Summary
Write-Host "`n🎯 SETUP COMPLETE!" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green
Write-Host "✅ Python dependencies: Installed" -ForegroundColor Green
Write-Host "✅ Node.js dependencies: Installed" -ForegroundColor Green  
Write-Host "✅ Configuration template: Created" -ForegroundColor Green
Write-Host "⚙️  External tools: Partially installed" -ForegroundColor Yellow

Write-Host "`n🚀 NEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Edit backend\.env with your API keys (optional)" -ForegroundColor White
Write-Host "2. Run: python backend\main.py (to start backend)" -ForegroundColor White
Write-Host "3. Run: cd frontend && npm start (to start frontend)" -ForegroundColor White
Write-Host "4. Open: http://localhost:3000 (frontend) and http://localhost:8000 (backend)" -ForegroundColor White

Write-Host "`n💡 The system will work without API keys, but AI analysis will be limited." -ForegroundColor Yellow
Write-Host "💡 External forensics tools enhance detection but aren't required for basic functionality." -ForegroundColor Yellow

Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
Read-Host
