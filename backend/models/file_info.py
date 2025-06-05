"""
Database models for file information and metadata.
"""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, 
    JSON, LargeBinary
)
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from .base import Base


class FileInfo(Base):
    """
    File information and basic properties model.
    """
    __tablename__ = "file_info"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Basic file information
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255))
    file_path = Column(Text)
    file_size = Column(Integer, nullable=False)
    
    # File identification
    mime_type = Column(String(100))
    file_extension = Column(String(20))
    magic_bytes = Column(String(100))
    
    # Hashing
    md5_hash = Column(String(32))
    sha1_hash = Column(String(40))
    sha256_hash = Column(String(64))
    ssdeep_hash = Column(Text)  # Fuzzy hashing
    
    # File classification
    file_category = Column(String(50))  # image, audio, video, document, etc.
    is_executable = Column(Boolean, default=False)
    is_archive = Column(Boolean, default=False)
    is_encrypted = Column(Boolean, default=False)
    
    # Security analysis
    virus_scan_clean = Column(Boolean)
    quarantine_status = Column(Boolean, default=False)
    upload_source = Column(String(100))
    
    # Processing status
    metadata_extracted = Column(Boolean, default=False)
    analysis_completed = Column(Boolean, default=False)
    
    # File system information
    creation_time = Column(DateTime)
    modification_time = Column(DateTime)
    access_time = Column(DateTime)


class FileMetadata(Base):
    """
    Comprehensive file metadata model.
    """
    __tablename__ = "file_metadata"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_info_id = Column(String, nullable=False)  # Reference to FileInfo
    created_at = Column(DateTime, default=func.now())
    
    # Metadata source
    extraction_tool = Column(String(100))  # exiftool, mutagen, ffprobe, etc.
    metadata_type = Column(String(50))  # exif, id3, xmp, etc.
    
    # Raw metadata
    raw_metadata = Column(JSON)  # Complete metadata dump
    
    # Image-specific metadata
    image_width = Column(Integer)
    image_height = Column(Integer)
    bit_depth = Column(Integer)
    color_space = Column(String(50))
    compression_type = Column(String(100))
    
    # Camera/device information
    camera_make = Column(String(100))
    camera_model = Column(String(100))
    lens_info = Column(String(200))
    
    # Capture information
    date_taken = Column(DateTime)
    gps_latitude = Column(Float)
    gps_longitude = Column(Float)
    gps_altitude = Column(Float)
    
    # Audio-specific metadata
    audio_duration = Column(Float)
    audio_bitrate = Column(Integer)
    sample_rate = Column(Integer)
    channels = Column(Integer)
    audio_codec = Column(String(50))
    
    # Music metadata
    title = Column(String(200))
    artist = Column(String(200))
    album = Column(String(200))
    year = Column(Integer)
    genre = Column(String(100))
    track_number = Column(Integer)
    
    # Video-specific metadata
    video_duration = Column(Float)
    frame_rate = Column(Float)
    video_codec = Column(String(50))
    video_bitrate = Column(Integer)
    
    # Document metadata
    author = Column(String(200))
    creator = Column(String(200))
    producer = Column(String(200))
    creation_date = Column(DateTime)
    modification_date = Column(DateTime)
    
    # Software information
    software = Column(String(200))
    software_version = Column(String(100))
    operating_system = Column(String(100))
    
    # Digital signatures and certificates
    digital_signature = Column(Boolean, default=False)
    certificate_info = Column(JSON)
    
    # Suspicious indicators
    suspicious_metadata = Column(JSON)  # Unusual or suspicious metadata fields
    metadata_anomalies = Column(JSON)  # Detected anomalies
    hidden_metadata = Column(JSON)  # Potentially hidden information
    
    # Quality and integrity
    metadata_complete = Column(Boolean, default=True)
    parsing_errors = Column(JSON)
    integrity_check = Column(Boolean, default=True)
    
    # Custom fields for steganography analysis
    entropy_analysis = Column(JSON)  # Entropy data for metadata
    frequency_analysis = Column(JSON)  # Character frequency analysis
    pattern_analysis = Column(JSON)  # Pattern detection results
    
    # Thumbnail and preview data
    thumbnail_data = Column(LargeBinary)
    preview_available = Column(Boolean, default=False)
    
    # Processing information
    extraction_time = Column(Float)
    processing_errors = Column(JSON)
