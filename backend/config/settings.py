# filepath: e:\stegano\backend\config\settings.py
"""
Configuration settings for the Steganography Scanner
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    APP_NAME: str = "Steganography Payload Scanner & Extractor"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database Configuration
    DATABASE_URL: str = "postgresql://stegano:stegano@localhost:5432/stegano"
    
    # File Upload Configuration
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS: List[str] = [
        # Images
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
        # Audio
        ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac",
        # Video
        ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv",
        # Documents
        ".pdf", ".doc", ".docx", ".txt"
    ]
    
    # Analysis Configuration
    ENABLE_AI_ANALYSIS: bool = True
    ENABLE_FORENSICS_TOOLS: bool = True
    DEFAULT_ANALYSIS_TYPE: str = "comprehensive"
    
    # AI API Keys
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    
    # External APIs
    VIRUSTOTAL_API_KEY: Optional[str] = None
    
    # Forensics Tools Configuration
    BINWALK_PATH: str = "binwalk"
    FOREMOST_PATH: str = "foremost"
    EXIFTOOL_PATH: str = "exiftool"
    ZSTEG_PATH: str = "zsteg"
    STEGOVERITAS_PATH: str = "stegoveritas"
    
    # Directories
    TEMP_DIR: Path = Path("temp")
    RESULTS_DIR: Path = Path("results")
    STATIC_DIR: Path = Path("static")
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "steganography_scanner.log"
    
    # Security Configuration
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Analysis Thresholds
    ENTROPY_THRESHOLD: float = 7.5
    LSB_THRESHOLD: float = 0.1
    SUSPICIOUS_PATTERN_THRESHOLD: int = 5
    
    class Config:
        env_file = ".env"
        case_sensitive = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Create directories if they don't exist
        self.TEMP_DIR.mkdir(exist_ok=True)
        self.RESULTS_DIR.mkdir(exist_ok=True)
        self.STATIC_DIR.mkdir(exist_ok=True)

# Global settings instance
settings = Settings()

def get_settings() -> Settings:
    """Get global settings instance"""
    return settings
