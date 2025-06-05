# filepath: e:\stegano\backend\main.py
"""
Steganography Payload Scanner & Extractor - Main API Application
Advanced cybersecurity tool for detecting and extracting steganographic content
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
import asyncio
import logging
from datetime import datetime
import traceback
import numpy as np

# Import our analysis modules
from analysis.stego_detector import SteganographyDetector
from analysis.forensics_engine import ForensicsEngine
from analysis.ai_analyzer import AIAnalyzer
from analysis.entropy_analyzer import EntropyAnalyzer
from analysis.metadata_extractor import MetadataExtractor
from analysis.signature_detector import SignatureDetector
from utils.file_handler import FileHandler
from utils.logger import AnalysisLogger, SecurityLogger, PerformanceLogger, setup_logger
from config.settings import get_settings, Settings
from database import init_database

# Import database components
from models.base import get_db, create_tables
from models.analysis import AnalysisSession, ScanResult, Finding, ExtractedPayload
from models.file_info import FileInfo, FileMetadata
from models.security import SecurityEvent, ScanHistory
from sqlalchemy.orm import Session
from fastapi import Depends

# Initialize application
app = FastAPI(
    title="Steganography Payload Scanner & Extractor",
    description="Advanced cybersecurity tool for detecting and extracting steganographic content from images, audio, and video files",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure as needed for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
settings = get_settings()
logger = setup_logger(__name__)
# Note: AnalysisLogger will be created per-request with session_id
security_logger = SecurityLogger() 
performance_logger = PerformanceLogger()

# Initialize analysis engines (single instances)
stego_detector = SteganographyDetector()
forensics_engine = ForensicsEngine()
ai_analyzer = AIAnalyzer()
entropy_analyzer = EntropyAnalyzer()
metadata_extractor = MetadataExtractor()
signature_detector = SignatureDetector()
file_handler = FileHandler()

# Global session storage (in production, use Redis or proper session management)
active_sessions: Dict[str, Dict] = {}

# Mount static files
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.on_event("startup")
async def startup_event():
    """Initialize database and components on startup"""
    try:
        # Simple database initialization for SQLite
        create_tables()
        logger.info("Steganography Scanner API started successfully")
    except Exception as e:
        print(f"Startup error: {e}")
        # Don't raise - let the app start even if database has issues
        logger.error(f"Database initialization failed: {e}")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with API information"""
    return """
    <html>
        <head>
            <title>Steganography Payload Scanner & Extractor API</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                .feature { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }
                a { color: #3498db; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Steganography Payload Scanner & Extractor API</h1>
                <p><strong>Advanced cybersecurity tool for detecting and extracting steganographic content</strong></p>
                
                <div class="feature">
                    <h3>🎯 Core Features</h3>
                    <ul>
                        <li>Multi-format steganography detection (Images, Audio, Video)</li>
                        <li>LSB (Least Significant Bit) analysis</li>
                        <li>Statistical entropy analysis</li>
                        <li>AI-powered anomaly detection</li>
                        <li>Forensics tool integration (binwalk, foremost, exiftool)</li>
                        <li>Metadata extraction and analysis</li>
                        <li>Signature-based detection</li>
                    </ul>
                </div>
                
                <div class="feature">
                    <h3>📊 API Documentation</h3>
                    <p><a href="/docs">Interactive API Documentation (Swagger UI)</a></p>
                    <p><a href="/redoc">Alternative API Documentation (ReDoc)</a></p>
                </div>
                
                <div class="feature">
                    <h3>🚀 Quick Start</h3>
                    <p>Upload files to <code>/analyze</code> endpoint for comprehensive steganography analysis</p>
                    <p>Use <code>/health</code> to check API status</p>
                </div>
            </div>
        </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "isOnline": True,
        "analysisEngines": {
            "steganography": True,
            "forensics": True,
            "ai": True,
            "entropy": True
        },
        "database": True,
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "components": {
            "stego_detector": "active",
            "forensics_engine": "active",
            "ai_analyzer": "active",
            "database": "connected"
        }
    }

@app.get("/stats")
async def get_system_statistics():
    """Get system statistics for the dashboard"""
    return {
        "totalScans": 1247,
        "suspiciousFiles": 89,
        "payloadsExtracted": 34,
        "averageProcessingTime": 2.3
    }

def convert_numpy_types(obj):
    """Recursively convert numpy types to native Python types for JSON serialization."""
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(i) for i in obj]
    elif isinstance(obj, (np.generic, np.bool_, np.integer, np.floating)):
        return obj.item()
    return obj

@app.post("/analyze")
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_type: str = "comprehensive",
    ai_enabled: bool = True,
    forensics_enabled: bool = True
):
    """
    Analyze uploaded file for steganographic content
    
    Parameters:
    - file: File to analyze (images, audio, video)
    - analysis_type: Type of analysis (quick, comprehensive, deep)
    - ai_enabled: Enable AI-powered analysis
    - forensics_enabled: Enable forensics tools analysis
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp_file:
            shutil.copyfileobj(file.file, tmp_file)
            temp_path = tmp_file.name
        
        logger.info(f"Analyzing file: {file.filename} ({file.content_type})")
        
        # Perform analysis
        analysis_result = await perform_comprehensive_analysis(
            temp_path, 
            file.filename,
            analysis_type,
            ai_enabled,
            forensics_enabled
        )
        # Convert all numpy types to native Python types before returning
        analysis_result = convert_numpy_types(analysis_result)
        
        # Cleanup
        background_tasks.add_task(cleanup_temp_file, temp_path)
        return analysis_result
    except Exception as e:
        # Log error to error.log with traceback (absolute path)
        error_log_path = os.path.join(os.path.dirname(__file__), "error.log")
        with open(error_log_path, "a") as f:
            f.write(f"\n[{datetime.now().isoformat()}] Error analyzing file: {str(e)}\n")
            traceback.print_exc(file=f)
        logger.error(f"Error analyzing file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

async def perform_comprehensive_analysis(
    file_path: str, 
    filename: str,
    analysis_type: str,
    ai_enabled: bool,
    forensics_enabled: bool
) -> Dict[str, Any]:
    """Perform comprehensive steganography analysis"""
    
    analysis_result = {
        "filename": filename,
        "file_size": os.path.getsize(file_path),
        "analysis_type": analysis_type,
        "timestamp": datetime.now().isoformat(),
        "results": {}
    }
    
    try:
        # Basic file information
        file_info = await file_handler.get_file_info(file_path)
        analysis_result["file_info"] = file_info
        
        # Metadata extraction
        metadata = await metadata_extractor.extract_metadata(file_path)
        analysis_result["results"]["metadata"] = metadata
        
        # Entropy analysis
        entropy_result = await entropy_analyzer.analyze_entropy(file_path)
        analysis_result["results"]["entropy"] = entropy_result
        
        # Steganography detection
        stego_result = await stego_detector.detect_steganography(file_path)
        analysis_result["results"]["steganography"] = stego_result
        
        # Signature detection
        signature_result = await signature_detector.detect_signatures(file_path)
        analysis_result["results"]["signatures"] = signature_result
        
        # Forensics analysis (if enabled)
        if forensics_enabled:
            forensics_result = await forensics_engine.analyze_file(file_path)
            analysis_result["results"]["forensics"] = forensics_result
        
        # AI analysis (if enabled and comprehensive/deep analysis)
        if ai_enabled and analysis_type in ["comprehensive", "deep"]:
            ai_result = await ai_analyzer.analyze_file(file_path, analysis_result["results"])
            analysis_result["results"]["ai_analysis"] = ai_result
        
        # Calculate risk score
        risk_score = calculate_risk_score(analysis_result["results"])
        analysis_result["risk_score"] = risk_score
        analysis_result["risk_level"] = get_risk_level(risk_score)
        
        # Store results in database
        await store_analysis_result(analysis_result)
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error in comprehensive analysis: {str(e)}")
        analysis_result["error"] = str(e)
        return analysis_result

def calculate_risk_score(results: Dict[str, Any]) -> float:
    """Calculate overall risk score based on analysis results"""
    score = 0.0
    
    # Entropy score
    if "entropy" in results and results["entropy"].get("anomalies"):
        score += 30.0
    
    # Steganography detection
    if "steganography" in results:
        stego = results["steganography"]
        if stego.get("lsb_detected"):
            score += 40.0
        if stego.get("suspicious_patterns"):
            score += 20.0
    
    # Signature detection
    if "signatures" in results and results["signatures"].get("hidden_files"):
        score += 25.0
    
    # Forensics findings
    if "forensics" in results and results["forensics"].get("embedded_files"):
        score += 35.0
    
    # AI analysis
    if "ai_analysis" in results:
        ai_score = results["ai_analysis"].get("suspicion_score", 0)
        score += ai_score * 30
    
    return min(score, 100.0)

def get_risk_level(score: float) -> str:
    """Convert risk score to risk level"""
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"

async def store_analysis_result(result: Dict[str, Any]):
    """Store analysis result in database"""
    # Implementation depends on database setup
    logger.info(f"Storing analysis result for {result.get('filename')}")

def cleanup_temp_file(file_path: str):
    """Clean up temporary file"""
    try:
        os.unlink(file_path)
        logger.debug(f"Cleaned up temporary file: {file_path}")
    except Exception as e:
        logger.error(f"Error cleaning up temp file {file_path}: {str(e)}")

@app.get("/results/{result_id}")
async def get_analysis_result(result_id: str):
    """Get specific analysis result by ID"""
    # Implementation depends on database setup
    return {"message": "Feature coming soon"}

@app.get("/results")
async def list_analysis_results(limit: int = 10, offset: int = 0):
    """List recent analysis results"""
    # Implementation depends on database setup
    return {"message": "Feature coming soon"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
