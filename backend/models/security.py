"""
Database models for security events and scan history.
"""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, 
    JSON, Enum as SQLEnum
)
from sqlalchemy.sql import func
from datetime import datetime
from enum import Enum
import uuid

from .base import Base


class EventType(str, Enum):
    """Security event type enumeration."""
    FILE_UPLOAD = "file_upload"
    ANALYSIS_START = "analysis_start" 
    ANALYSIS_COMPLETE = "analysis_complete"
    SUSPICIOUS_CONTENT = "suspicious_content"
    MALWARE_DETECTED = "malware_detected"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SYSTEM_ERROR = "system_error"
    FORENSIC_EXTRACTION = "forensic_extraction"
    AI_ANALYSIS = "ai_analysis"
    PAYLOAD_EXTRACTED = "payload_extracted"


class ThreatLevel(str, Enum):
    """Threat level enumeration."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(Base):
    """
    Security events and audit log model.
    """
    __tablename__ = "security_events"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Event classification
    event_type = Column(SQLEnum(EventType), nullable=False)
    threat_level = Column(SQLEnum(ThreatLevel), default=ThreatLevel.INFO)
    
    # Event details
    title = Column(String(200), nullable=False)
    description = Column(Text)
    source_component = Column(String(100))  # Which component generated the event
    
    # Context information
    session_id = Column(String(36))  # Associated analysis session
    file_hash = Column(String(64))  # Associated file
    user_agent = Column(String(500))
    client_ip = Column(String(45))
    request_id = Column(String(36))
    
    # Technical details
    event_data = Column(JSON)  # Structured event data
    stack_trace = Column(Text)  # For error events
    request_payload = Column(JSON)  # Request data if relevant
    
    # Response and handling
    response_action = Column(String(100))  # What action was taken
    handled = Column(Boolean, default=False)
    requires_attention = Column(Boolean, default=False)
    
    # Correlation
    correlation_id = Column(String(36))  # For grouping related events
    parent_event_id = Column(String(36))  # For event chains
    
    # Impact assessment
    potential_impact = Column(String(200))
    affected_systems = Column(JSON)
    
    # Resolution
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    resolution_notes = Column(Text)


class ScanHistory(Base):
    """
    Historical scan data and statistics model.
    """
    __tablename__ = "scan_history"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=func.now())
    
    # Time period aggregation
    date_bucket = Column(DateTime, nullable=False)  # Hour/day bucket for aggregation
    aggregation_period = Column(String(20))  # hourly, daily, weekly
    
    # Scan statistics
    total_scans = Column(Integer, default=0)
    completed_scans = Column(Integer, default=0)
    failed_scans = Column(Integer, default=0)
    cancelled_scans = Column(Integer, default=0)
    
    # File statistics
    total_files_scanned = Column(Integer, default=0)
    total_file_size_mb = Column(Float, default=0.0)
    average_file_size_mb = Column(Float, default=0.0)
    
    # Detection statistics
    suspicious_files_found = Column(Integer, default=0)
    confirmed_steganography = Column(Integer, default=0)
    payloads_extracted = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    
    # File type breakdown
    image_files_scanned = Column(Integer, default=0)
    audio_files_scanned = Column(Integer, default=0)
    video_files_scanned = Column(Integer, default=0)
    document_files_scanned = Column(Integer, default=0)
    other_files_scanned = Column(Integer, default=0)
    
    # Performance metrics
    average_scan_time_seconds = Column(Float, default=0.0)
    total_processing_time_seconds = Column(Float, default=0.0)
    peak_memory_usage_mb = Column(Float, default=0.0)
    
    # Detection method effectiveness
    lsb_detections = Column(Integer, default=0)
    entropy_detections = Column(Integer, default=0)
    statistical_detections = Column(Integer, default=0)
    ai_detections = Column(Integer, default=0)
    forensic_detections = Column(Integer, default=0)
    signature_detections = Column(Integer, default=0)
    
    # Quality metrics
    detection_accuracy = Column(Float, default=0.0)
    false_positive_rate = Column(Float, default=0.0)
    confidence_score_average = Column(Float, default=0.0)
    
    # System health
    system_errors = Column(Integer, default=0)
    processing_errors = Column(Integer, default=0)
    resource_warnings = Column(Integer, default=0)
    
    # User behavior
    unique_users = Column(Integer, default=0)
    repeat_users = Column(Integer, default=0)
    average_session_duration = Column(Float, default=0.0)
    
    # Threat landscape
    high_risk_files = Column(Integer, default=0)
    malware_detected = Column(Integer, default=0)
    suspicious_patterns = Column(JSON)  # Common patterns detected
    
    # Geographic data (if IP geolocation is enabled)
    top_countries = Column(JSON)  # Most active countries
    suspicious_locations = Column(JSON)  # Potentially suspicious origins
    
    # Trend analysis
    trend_direction = Column(String(20))  # increasing, decreasing, stable
    anomaly_score = Column(Float, default=0.0)  # Statistical anomaly detection
    
    # Additional metadata
    data_quality_score = Column(Float, default=1.0)
    completeness_percentage = Column(Float, default=100.0)
    notes = Column(Text)


class UserSession(Base):
    """
    User session tracking for analytics and security.
    """
    __tablename__ = "user_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=func.now())
    last_activity = Column(DateTime, default=func.now())
    
    # Session identification
    session_token = Column(String(64), unique=True, nullable=False)
    client_ip = Column(String(45))
    user_agent = Column(String(500))
    fingerprint = Column(String(64))  # Browser fingerprint
    
    # Geographic information
    country = Column(String(100))
    region = Column(String(100))
    city = Column(String(100))
    
    # Session statistics
    files_uploaded = Column(Integer, default=0)
    scans_performed = Column(Integer, default=0)
    total_scan_time = Column(Float, default=0.0)
    
    # Behavior analysis
    suspicious_activity = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    activity_pattern = Column(JSON)
    
    # Session status
    is_active = Column(Boolean, default=True)
    ended_at = Column(DateTime)
    end_reason = Column(String(100))  # timeout, logout, ban, etc.
    
    # Rate limiting
    requests_count = Column(Integer, default=0)
    last_request_time = Column(DateTime)
    rate_limit_exceeded = Column(Boolean, default=False)
