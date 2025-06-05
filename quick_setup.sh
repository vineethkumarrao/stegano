#!/bin/bash
# Quick Start Script for Steganography Scanner
# This script will get you running in minimal time

echo "🔍 Steganography Scanner - Quick Start"
echo "======================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python
if command_exists python3; then
    echo "✅ Python3 found"
    cd backend
    echo "📦 Installing Python dependencies..."
    pip3 install -r requirements.txt
    cd ..
else
    echo "❌ Python3 not found - please install it first"
    exit 1
fi

# Check Node.js
if command_exists npm; then
    echo "✅ npm found"
    cd frontend  
    echo "📦 Installing Node.js dependencies..."
    npm install
    cd ..
else
    echo "❌ npm not found - please install Node.js first"
    exit 1
fi

# Install external tools (Linux/macOS)
echo "🔧 Installing external tools..."

if command_exists apt; then
    # Ubuntu/Debian
    echo "📦 Installing tools via apt..."
    sudo apt update
    sudo apt install -y binwalk foremost exiftool
elif command_exists brew; then
    # macOS
    echo "📦 Installing tools via Homebrew..."
    brew install binwalk foremost exiftool
else
    echo "⚠️  Package manager not found - you may need to install tools manually"
fi

# Create .env template
if [ ! -f "backend/.env" ]; then
    cat > backend/.env << EOF
# Steganography Scanner Configuration
# Add your actual API keys here

# AI Analysis API Keys (Optional)
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# External API Keys (Optional)  
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Database Configuration (Optional)
# DATABASE_URL=postgresql://username:password@localhost:5432/stegano_db

# Logging
LOG_LEVEL=INFO
DEBUG=false

# Security
SECRET_KEY=change-this-in-production-$(openssl rand -hex 32)
EOF
    echo "✅ Created .env template"
fi

echo ""
echo "🎯 SETUP COMPLETE!"
echo "=================="
echo "✅ Dependencies installed"
echo "✅ Configuration template created"
echo ""
echo "🚀 TO START THE APPLICATION:"
echo "1. Backend:  cd backend && python3 main.py"
echo "2. Frontend: cd frontend && npm start"
echo "3. Open:     http://localhost:3000"
echo ""
echo "💡 Edit backend/.env to add API keys for enhanced functionality"
