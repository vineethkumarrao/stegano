"""
Database models for analysis sessions, results, and findings.
"""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, 
    ForeignKey, JSON, LargeBinary, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from enum import Enum
import uuid

from .base import Base


class AnalysisStatus(str, Enum):
    """Analysis session status enumeration."""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingType(str, Enum):
    """Type of steganographic finding."""
    LSB_HIDDEN_DATA = "lsb_hidden_data"
    ENTROPY_ANOMALY = "entropy_anomaly"
    STATISTICAL_ANOMALY = "statistical_anomaly"
    VISUAL_ARTIFACT = "visual_artifact"
    METADATA_HIDDEN = "metadata_hidden"
    FORENSIC_TOOL_DETECTION = "forensic_tool_detection"
    AI_DETECTED_PATTERN = "ai_detected_pattern"
    SIGNATURE_MATCH = "signature_match"
    COMPRESSION_ANOMALY = "compression_anomaly"
    FREQUENCY_ANALYSIS = "frequency_analysis"


class SeverityLevel(str, Enum):
    """Severity level for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisSession(Base):
    """
    Analysis session model for tracking complete scans.
    """
    __tablename__ = "analysis_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Session information
    status = Column(SQLEnum(AnalysisStatus), default=AnalysisStatus.PENDING)
    total_files = Column(Integer, default=0)
    processed_files = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    
    # Analysis configuration
    analysis_config = Column(JSON)  # Stores analysis parameters
    user_agent = Column(String(500))
    client_ip = Column(String(45))
    
    # Timing information
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Float)
    
    # Results summary
    has_steganography = Column(Boolean, default=False)
    confidence_score = Column(Float, default=0.0)
    risk_level = Column(SQLEnum(SeverityLevel), default=SeverityLevel.LOW)
    
    # Error handling
    error_message = Column(Text)
    error_details = Column(JSON)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="session", cascade="all, delete-orphan")
    ai_analyses = relationship("AIAnalysis", back_populates="session", cascade="all, delete-orphan")


class ScanResult(Base):
    """
    Individual file scan result model.
    """
    __tablename__ = "scan_results"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("analysis_sessions.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    # File information
    filename = Column(String(255), nullable=False)
    file_path = Column(Text)
    file_size = Column(Integer)
    file_hash = Column(String(64))  # SHA-256 hash
    mime_type = Column(String(100))
    
    # Analysis results
    is_suspicious = Column(Boolean, default=False)
    confidence_score = Column(Float, default=0.0)
    processing_time = Column(Float)
    
    # Technical analysis results
    entropy_score = Column(Float)
    compression_ratio = Column(Float)
    metadata_anomalies = Column(Integer, default=0)
    
    # Analysis details
    analysis_methods = Column(JSON)  # List of methods used
    raw_results = Column(JSON)  # Raw analysis output
    
    # Error handling
    processing_error = Column(Text)
    
    # Relationships
    session = relationship("AnalysisSession", back_populates="scan_results")
    findings = relationship("Finding", back_populates="scan_result", cascade="all, delete-orphan")
    forensics_results = relationship("ForensicsResult", back_populates="scan_result", cascade="all, delete-orphan")


class Finding(Base):
    """
    Individual steganographic finding model.
    """
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String, ForeignKey("scan_results.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    # Finding classification
    finding_type = Column(SQLEnum(FindingType), nullable=False)
    severity = Column(SQLEnum(SeverityLevel), default=SeverityLevel.LOW)
    confidence = Column(Float, nullable=False)
    
    # Finding details
    title = Column(String(200), nullable=False)
    description = Column(Text)
    location = Column(String(500))  # Where in the file
    
    # Technical details
    algorithm_used = Column(String(100))
    parameters = Column(JSON)
    raw_data = Column(LargeBinary)
    
    # Evidence
    evidence_data = Column(JSON)
    extracted_size = Column(Integer)
    pattern_matches = Column(JSON)
    
    # Validation
    is_verified = Column(Boolean, default=False)
    false_positive_likelihood = Column(Float, default=0.0)
    
    # Relationships
    scan_result = relationship("ScanResult", back_populates="findings")
    extracted_payloads = relationship("ExtractedPayload", back_populates="finding", cascade="all, delete-orphan")


class ExtractedPayload(Base):
    """
    Extracted steganographic payload model.
    """
    __tablename__ = "extracted_payloads"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    # Payload information
    payload_type = Column(String(100))  # text, binary, image, etc.
    file_extension = Column(String(10))
    size_bytes = Column(Integer)
    
    # Content analysis
    content_hash = Column(String(64))
    is_encrypted = Column(Boolean, default=False)
    is_compressed = Column(Boolean, default=False)
    
    # Security analysis
    contains_executable = Column(Boolean, default=False)
    contains_urls = Column(Boolean, default=False)
    suspicious_patterns = Column(JSON)
    
    # Storage
    payload_data = Column(LargeBinary)  # Actual extracted data
    preview_text = Column(Text)  # Text preview if applicable
    
    # Metadata
    extraction_method = Column(String(100))
    extraction_parameters = Column(JSON)
    
    # Relationships
    finding = relationship("Finding", back_populates="extracted_payloads")


class AIAnalysis(Base):
    """
    AI-powered analysis results model.
    """
    __tablename__ = "ai_analyses"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("analysis_sessions.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    # AI model information
    model_name = Column(String(100))  # gemini-pro, gpt-4, etc.
    model_version = Column(String(50))
    analysis_type = Column(String(100))  # vision, text, pattern, etc.
    
    # Analysis results
    summary = Column(Text)
    confidence_score = Column(Float)
    risk_assessment = Column(SQLEnum(SeverityLevel))
    
    # Detailed insights
    insights = Column(JSON)  # Structured AI insights
    patterns_detected = Column(JSON)
    recommendations = Column(JSON)
    
    # Technical details
    processing_time = Column(Float)
    token_usage = Column(JSON)  # For LLM usage tracking
    
    # Quality metrics
    analysis_quality = Column(Float)  # Internal quality score
    human_reviewed = Column(Boolean, default=False)
    
    # Relationships
    session = relationship("AnalysisSession", back_populates="ai_analyses")


class ForensicsResult(Base):
    """
    Forensics tools analysis results model.
    """
    __tablename__ = "forensics_results"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String, ForeignKey("scan_results.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    # Tool information
    tool_name = Column(String(100), nullable=False)  # binwalk, foremost, etc.
    tool_version = Column(String(50))
    command_used = Column(Text)
    
    # Results
    exit_code = Column(Integer)
    stdout_output = Column(Text)
    stderr_output = Column(Text)
    execution_time = Column(Float)
    
    # Parsed results
    files_found = Column(Integer, default=0)
    suspicious_patterns = Column(JSON)
    embedded_files = Column(JSON)
    
    # Analysis
    contains_hidden_data = Column(Boolean, default=False)
    threat_indicators = Column(JSON)
    
    # Relationships
    scan_result = relationship("ScanResult", back_populates="forensics_results")
