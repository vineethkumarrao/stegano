#!/usr/bin/env python3
"""
Simple API Test Server - Test without database
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI
import uvicorn

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="Steganography Scanner API Test",
    description="Test server for API key validation",
    version="1.0.0"
)

@app.get("/")
async def root():
    """Test endpoint"""
    return {"message": "Steganography Scanner API is running!"}

@app.get("/api/test")
async def test_api_keys():
    """Test API key configuration"""
    return {
        "gemini_api_configured": bool(os.getenv("GEMINI_API_KEY")),
        "virustotal_api_configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "gemini_key_preview": f"{os.getenv('GEMINI_API_KEY', '')[:10]}..." if os.getenv("GEMINI_API_KEY") else None,
        "virustotal_key_preview": f"{os.getenv('VIRUSTOTAL_API_KEY', '')[:10]}..." if os.getenv("VIRUSTOTAL_API_KEY") else None
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Server is running"}

if __name__ == "__main__":
    print("🚀 Starting Steganography Scanner Test API...")
    print(f"✅ Gemini API: {'Configured' if os.getenv('GEMINI_API_KEY') else 'Not configured'}")
    print(f"✅ VirusTotal API: {'Configured' if os.getenv('VIRUSTOTAL_API_KEY') else 'Not configured'}")
    uvicorn.run(
        "test_api:app",
        host="127.0.0.1", 
        port=8000,
        reload=True
    )
