"""
Simple test server to verify FastAPI installation
"""
from fastapi import FastAPI
import uvicorn

app = FastAPI(title="Steganography Scanner Test")

@app.get("/")
async def root():
    return {"message": "Steganography Scanner Backend is running!"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "backend"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
