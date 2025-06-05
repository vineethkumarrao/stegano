# filepath: e:\stegano\backend\utils\logger.py
"""
Logging Configuration
Centralized logging setup for the steganography scanner
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json

def setup_logger(name: str, level: str = "INFO", log_dir: Optional[str] = None) -> logging.Logger:
    """
    Set up centralized logging configuration
    
    Args:
        name: Logger name (usually __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory to store log files (optional)
    
    Returns:
        Configured logger instance
    """
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Don't add handlers if already configured
    if logger.handlers:
        return logger
    
    # Set log level
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if log_dir is specified)
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(exist_ok=True)
        
        # Main log file
        log_file = log_path / f"stegano_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
        
        # Error log file
        error_file = log_path / f"stegano_errors_{datetime.now().strftime('%Y%m%d')}.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        logger.addHandler(error_handler)
    
    return logger

class AnalysisLogger:
    """Specialized logger for analysis operations"""
    
    def __init__(self, session_id: str, log_dir: Optional[str] = None):
        self.session_id = session_id
        self.logger = setup_logger(f"analysis.{session_id}", log_dir=log_dir)
        self.analysis_log = []
        
    def log_analysis_start(self, file_path: str, file_info: dict):
        """Log the start of an analysis session"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "analysis_start",
            "session_id": self.session_id,
            "file_path": file_path,
            "file_info": file_info
        }
        
        self.analysis_log.append(log_entry)
        self.logger.info(f"Analysis started for {file_info.get('filename', 'unknown')} (session: {self.session_id})")
    
    def log_module_start(self, module_name: str):
        """Log the start of a specific analysis module"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "module_start",
            "session_id": self.session_id,
            "module": module_name
        }
        
        self.analysis_log.append(log_entry)
        self.logger.info(f"Starting {module_name} analysis")
    
    def log_module_complete(self, module_name: str, results: dict, duration: float):
        """Log the completion of a specific analysis module"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "module_complete",
            "session_id": self.session_id,
            "module": module_name,
            "duration_seconds": duration,
            "success": "error" not in results,
            "results_summary": self._summarize_results(results)
        }
        
        self.analysis_log.append(log_entry)
        
        if "error" not in results:
            self.logger.info(f"Completed {module_name} analysis in {duration:.2f}s")
        else:
            self.logger.error(f"Failed {module_name} analysis: {results.get('error', 'Unknown error')}")
    
    def log_detection(self, detection_type: str, details: dict):
        """Log a detection event"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "detection",
            "session_id": self.session_id,
            "detection_type": detection_type,
            "details": details
        }
        
        self.analysis_log.append(log_entry)
        self.logger.warning(f"Detection: {detection_type} - {details}")
    
    def log_extraction(self, extracted_content: dict):
        """Log content extraction"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "extraction",
            "session_id": self.session_id,
            "extracted_content": extracted_content
        }
        
        self.analysis_log.append(log_entry)
        self.logger.info(f"Extracted content: {extracted_content.get('type', 'unknown')}")
    
    def log_analysis_complete(self, total_duration: float, final_results: dict):
        """Log the completion of analysis"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "analysis_complete",
            "session_id": self.session_id,
            "total_duration_seconds": total_duration,
            "final_results_summary": self._summarize_final_results(final_results)
        }
        
        self.analysis_log.append(log_entry)
        self.logger.info(f"Analysis completed in {total_duration:.2f}s (session: {self.session_id})")
    
    def log_error(self, error_message: str, module: str = None, exception: Exception = None):
        """Log an error during analysis"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "error",
            "session_id": self.session_id,
            "module": module,
            "error_message": error_message,
            "exception_type": type(exception).__name__ if exception else None,
            "exception_details": str(exception) if exception else None
        }
        
        self.analysis_log.append(log_entry)
        
        if exception:
            self.logger.error(f"Error in {module or 'unknown'}: {error_message}", exc_info=exception)
        else:
            self.logger.error(f"Error in {module or 'unknown'}: {error_message}")
    
    def _summarize_results(self, results: dict) -> dict:
        """Create a summary of analysis results for logging"""
        summary = {}
        
        try:
            # Count various metrics
            if isinstance(results, dict):
                summary["has_data"] = len(results) > 0
                summary["error"] = "error" in results
                
                # Steganography detection summary
                if "steganography" in results:
                    stego_data = results["steganography"]
                    if isinstance(stego_data, dict):
                        summary["steganography_detected"] = stego_data.get("confidence_score", 0) > 0.5
                        summary["confidence_score"] = stego_data.get("confidence_score", 0)
                
                # Forensics summary
                if "forensics" in results:
                    forensics_data = results["forensics"]
                    if isinstance(forensics_data, dict):
                        summary["embedded_files"] = forensics_data.get("embedded_file_count", 0)
                        summary["suspicious_indicators"] = len(forensics_data.get("suspicious_indicators", []))
                
                # AI analysis summary
                if "ai_analysis" in results:
                    ai_data = results["ai_analysis"]
                    if isinstance(ai_data, dict):
                        summary["ai_suspicion_score"] = ai_data.get("suspicion_score", 0)
                        summary["anomalies_detected"] = ai_data.get("anomaly_detection", {}).get("anomaly_scores", {}).get("is_anomaly", False)
                
                # Signature detection summary
                if "signatures" in results:
                    sig_data = results["signatures"]
                    if isinstance(sig_data, dict):
                        summary["total_signatures"] = sig_data.get("total_detections", 0)
        
        except Exception:
            summary["summary_error"] = True
        
        return summary
    
    def _summarize_final_results(self, final_results: dict) -> dict:
        """Create a summary of final analysis results"""
        summary = {
            "modules_run": [],
            "total_detections": 0,
            "highest_confidence": 0.0,
            "critical_findings": []
        }
        
        try:
            if isinstance(final_results, dict):
                # Count modules that ran successfully
                for module_name, module_results in final_results.items():
                    if isinstance(module_results, dict) and "error" not in module_results:
                        summary["modules_run"].append(module_name)
                
                # Aggregate detection counts
                detection_fields = [
                    ("steganography", "confidence_score"),
                    ("forensics", "embedded_file_count"),
                    ("signatures", "total_detections"),
                    ("ai_analysis", "suspicion_score")
                ]
                
                for module, field in detection_fields:
                    if module in final_results:
                        module_data = final_results[module]
                        if isinstance(module_data, dict):
                            value = module_data.get(field, 0)
                            if isinstance(value, (int, float)):
                                if field in ["confidence_score", "suspicion_score"]:
                                    summary["highest_confidence"] = max(summary["highest_confidence"], value)
                                else:
                                    summary["total_detections"] += value
                
                # Identify critical findings
                if summary["highest_confidence"] > 0.8:
                    summary["critical_findings"].append("high_confidence_steganography")
                
                if final_results.get("forensics", {}).get("embedded_file_count", 0) > 0:
                    summary["critical_findings"].append("embedded_files_found")
                
                if final_results.get("signatures", {}).get("total_detections", 0) > 5:
                    summary["critical_findings"].append("multiple_signatures_detected")
        
        except Exception:
            summary["summary_error"] = True
        
        return summary
    
    def get_analysis_log(self) -> list:
        """Get the complete analysis log"""
        return self.analysis_log.copy()
    
    def save_analysis_log(self, output_path: str):
        """Save the analysis log to a file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_log, f, indent=2, default=str)
            
            self.logger.info(f"Analysis log saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save analysis log: {str(e)}")

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self, log_dir: Optional[str] = None):
        self.logger = setup_logger("security", log_dir=log_dir)
        
    def log_file_upload(self, filename: str, file_size: int, client_ip: str, session_id: str):
        """Log file upload event"""
        self.logger.info(
            f"File upload: {filename} ({file_size} bytes) from {client_ip} (session: {session_id})"
        )
    
    def log_security_violation(self, violation_type: str, details: dict, client_ip: str):
        """Log security violations"""
        self.logger.warning(
            f"Security violation: {violation_type} from {client_ip} - {details}"
        )
    
    def log_suspicious_file(self, filename: str, reason: str, file_hash: str):
        """Log suspicious file detection"""
        self.logger.warning(
            f"Suspicious file detected: {filename} (hash: {file_hash}) - {reason}"
        )
    
    def log_malware_detection(self, filename: str, detection_details: dict):
        """Log potential malware detection"""
        self.logger.critical(
            f"Potential malware detected: {filename} - {detection_details}"
        )
    
    def log_system_event(self, event_type: str, details: dict):
        """Log system-level security events"""
        self.logger.info(f"System event: {event_type} - {details}")

class PerformanceLogger:
    """Logger for performance monitoring"""
    
    def __init__(self, log_dir: Optional[str] = None):
        self.logger = setup_logger("performance", log_dir=log_dir)
        self.metrics = []
    
    def log_analysis_performance(self, session_id: str, module: str, 
                                duration: float, file_size: int, cpu_usage: float = None):
        """Log analysis performance metrics"""
        metric = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "module": module,
            "duration_seconds": duration,
            "file_size_bytes": file_size,
            "cpu_usage_percent": cpu_usage,
            "throughput_mbps": (file_size / (1024 * 1024)) / duration if duration > 0 else 0
        }
        
        self.metrics.append(metric)
        
        self.logger.info(
            f"Performance: {module} processed {file_size} bytes in {duration:.2f}s "
            f"({metric['throughput_mbps']:.2f} MB/s)"
        )
    
    def log_memory_usage(self, session_id: str, memory_mb: float):
        """Log memory usage"""
        self.logger.info(f"Memory usage: {memory_mb:.2f} MB (session: {session_id})")
    
    def log_disk_usage(self, disk_usage_info: dict):
        """Log disk usage information"""
        self.logger.info(f"Disk usage: {disk_usage_info}")
    
    def get_performance_metrics(self) -> list:
        """Get all performance metrics"""
        return self.metrics.copy()

def configure_logging_for_production(log_dir: str = "logs"):
    """Configure logging for production environment"""
    
    # Create log directory
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    
    # Set up main application logger
    app_logger = setup_logger("stegano", level="INFO", log_dir=log_dir)
    
    # Set up specialized loggers
    security_logger = SecurityLogger(log_dir)
    performance_logger = PerformanceLogger(log_dir)
    
    # Configure third-party library logging
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)
    
    # Suppress noisy loggers
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    
    app_logger.info("Logging configured for production")
    
    return {
        "app_logger": app_logger,
        "security_logger": security_logger,
        "performance_logger": performance_logger
    }
