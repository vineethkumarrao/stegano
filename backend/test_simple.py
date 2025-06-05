#!/usr/bin/env python3
"""
Simple test server without database
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Create FastAPI app
app = FastAPI(
    title="Steganography Scanner Test",
    description="Test version without database",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Steganography Scanner Backend is running!", "status": "ok"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "disabled"}

if __name__ == "__main__":
    print("🚀 Starting Steganography Scanner Test Server...")
    print("📡 Server will be available at: http://localhost:8000")
    print("📊 API docs will be available at: http://localhost:8000/docs")
    
    uvicorn.run(
        "test_simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
