# filepath: e:\stegano\backend\utils\file_handler.py
"""
File Handling Utilities
Secure file operations for steganography analysis
"""

import os
import shutil
import tempfile
import hashlib
import mimetypes
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import asyncio
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class FileHandler:
    """Secure file handling for uploaded files and analysis results"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.temp_dir = Path(tempfile.gettempdir()) / "stegano_uploads"
        self.results_dir = Path(tempfile.gettempdir()) / "stegano_results"
        
        # Create directories
        self.temp_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        # File size limits (in bytes)
        self.max_file_size = 500 * 1024 * 1024  # 500MB
        self.max_total_size = 1024 * 1024 * 1024  # 1GB
        
        # Allowed file types
        self.allowed_extensions = {
            'images': ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif', '.webp'],
            'audio': ['.wav', '.mp3', '.flac', '.ogg', '.m4a', '.aac', '.wma'],
            'video': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v'],
            'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']
        }
        
        # MIME type mapping
        self.mime_types = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/bmp': '.bmp',
            'image/gif': '.gif',
            'image/tiff': '.tiff',
            'image/webp': '.webp',
            'audio/wav': '.wav',
            'audio/mpeg': '.mp3',
            'audio/flac': '.flac',
            'audio/ogg': '.ogg',
            'video/mp4': '.mp4',
            'video/avi': '.avi',
            'video/quicktime': '.mov',
            'video/x-msvideo': '.avi'
        }
    
    async def save_uploaded_file(self, file_content: bytes, filename: str, 
                               session_id: Optional[str] = None) -> Dict[str, Any]:
        """Securely save uploaded file"""
        try:
            # Generate session ID if not provided
            if not session_id:
                session_id = str(uuid.uuid4())
            
            # Validate file
            validation_result = await self.validate_file(file_content, filename)
            if not validation_result['valid']:
                return validation_result
            
            # Create session directory
            session_dir = self.temp_dir / session_id
            session_dir.mkdir(exist_ok=True)
            
            # Generate safe filename
            safe_filename = self.generate_safe_filename(filename)
            file_path = session_dir / safe_filename
            
            # Save file
            with open(file_path, 'wb') as f:
                f.write(file_content)
            
            # Generate file info
            file_info = await self.get_file_info(file_path)
            file_info.update({
                'session_id': session_id,
                'original_filename': filename,
                'safe_filename': safe_filename,
                'file_path': str(file_path),
                'upload_time': datetime.now().isoformat()
            })
            
            self.logger.info(f"File saved: {safe_filename} (session: {session_id})")
            return {'valid': True, 'file_info': file_info}
            
        except Exception as e:
            self.logger.error(f"Error saving uploaded file: {str(e)}")
            return {'valid': False, 'error': str(e)}
    
    async def validate_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Validate uploaded file"""
        try:
            # Check file size
            if len(file_content) > self.max_file_size:
                return {
                    'valid': False,
                    'error': f'File too large. Maximum size: {self.max_file_size // (1024*1024)}MB'
                }
            
            # Check file extension
            file_ext = Path(filename).suffix.lower()
            if not self.is_allowed_extension(file_ext):
                return {
                    'valid': False,
                    'error': f'File type not allowed: {file_ext}'
                }
            
            # Basic magic number validation
            mime_validation = await self.validate_mime_type(file_content, file_ext)
            if not mime_validation['valid']:
                return mime_validation
            
            # Check for malicious content
            security_check = await self.security_scan(file_content)
            if not security_check['safe']:
                return {
                    'valid': False,
                    'error': f'Security scan failed: {security_check["reason"]}'
                }
            
            return {'valid': True}
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def is_allowed_extension(self, extension: str) -> bool:
        """Check if file extension is allowed"""
        for category, extensions in self.allowed_extensions.items():
            if extension in extensions:
                return True
        return False
    
    async def validate_mime_type(self, file_content: bytes, expected_ext: str) -> Dict[str, Any]:
        """Validate file MIME type against extension"""
        try:
            # Check magic numbers
            magic_checks = {
                '.jpg': [b'\xff\xd8\xff'],
                '.jpeg': [b'\xff\xd8\xff'],
                '.png': [b'\x89PNG\r\n\x1a\n'],
                '.gif': [b'GIF87a', b'GIF89a'],
                '.bmp': [b'BM'],
                '.pdf': [b'%PDF'],
                '.zip': [b'PK\x03\x04', b'PK\x05\x06'],
                '.rar': [b'Rar!\x1a\x07'],
                '.wav': [b'RIFF'],
                '.mp3': [b'ID3', b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'],
                '.mp4': [b'ftyp'],
                '.avi': [b'RIFF']
            }
            
            if expected_ext in magic_checks:
                magic_numbers = magic_checks[expected_ext]
                file_header = file_content[:32]
                
                for magic in magic_numbers:
                    if magic in file_header:
                        return {'valid': True}
                
                # Special case for MP4 - check at offset 4
                if expected_ext == '.mp4' and len(file_content) > 8:
                    if b'ftyp' in file_content[4:12]:
                        return {'valid': True}
                
                return {
                    'valid': False,
                    'error': f'File header does not match expected type {expected_ext}'
                }
            
            # For other types, use basic validation
            return {'valid': True}
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    async def security_scan(self, file_content: bytes) -> Dict[str, Any]:
        """Basic security scanning of file content"""
        try:
            # Check for embedded executables
            dangerous_signatures = [
                b'MZ',  # PE executable
                b'\x7fELF',  # ELF executable
                b'\xfe\xed\xfa\xce',  # Mach-O
                b'#!/bin/sh',  # Shell script
                b'#!/bin/bash',  # Bash script
                b'<script',  # JavaScript
                b'javascript:',  # JavaScript URL
                b'vbscript:',  # VBScript URL
            ]
            
            file_header = file_content[:1024]  # Check first 1KB
            
            for signature in dangerous_signatures:
                if signature in file_header:
                    return {
                        'safe': False,
                        'reason': f'Potentially dangerous content detected: {signature.decode("utf-8", errors="ignore")}'
                    }
            
            # Check for suspicious patterns
            if self.contains_suspicious_patterns(file_content):
                return {
                    'safe': False,
                    'reason': 'Suspicious patterns detected'
                }
            
            return {'safe': True}
            
        except Exception as e:
            return {'safe': False, 'reason': str(e)}
    
    def contains_suspicious_patterns(self, content: bytes) -> bool:
        """Check for suspicious patterns in file content"""
        try:
            # Convert to string for pattern matching (ignore errors)
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            # Suspicious keywords
            suspicious_keywords = [
                'eval(', 'exec(', 'system(', 'shell_exec(',
                'powershell', 'cmd.exe', '/bin/sh',
                'document.write', 'createobject',
                'activexobject', 'wscript.shell'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in content_str:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def generate_safe_filename(self, original_filename: str) -> str:
        """Generate a safe filename"""
        # Get file extension
        file_path = Path(original_filename)
        extension = file_path.suffix.lower()
        
        # Generate unique name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        safe_name = f"upload_{timestamp}_{unique_id}{extension}"
        
        return safe_name
    
    async def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get comprehensive file information"""
        try:
            stat_info = file_path.stat()
            
            # Calculate file hashes
            hashes = await self.calculate_file_hashes(file_path)
            
            # Detect MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            return {
                'filename': file_path.name,
                'size': stat_info.st_size,
                'size_mb': round(stat_info.st_size / (1024 * 1024), 2),
                'extension': file_path.suffix.lower(),
                'mime_type': mime_type,
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'hashes': hashes,
                'file_type': self.classify_file_type(file_path.suffix.lower())
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def calculate_file_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        try:
            # Calculate hashes in chunks to handle large files
            chunk_size = 64 * 1024  # 64KB chunks
            
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            hashes['md5'] = md5_hash.hexdigest()
            hashes['sha1'] = sha1_hash.hexdigest()
            hashes['sha256'] = sha256_hash.hexdigest()
            
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def classify_file_type(self, extension: str) -> str:
        """Classify file type based on extension"""
        for category, extensions in self.allowed_extensions.items():
            if extension in extensions:
                return category
        return 'unknown'
    
    async def create_analysis_workspace(self, session_id: str) -> Path:
        """Create a workspace directory for analysis"""
        workspace_dir = self.results_dir / session_id
        workspace_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (workspace_dir / "extracted").mkdir(exist_ok=True)
        (workspace_dir / "reports").mkdir(exist_ok=True)
        (workspace_dir / "temp").mkdir(exist_ok=True)
        
        return workspace_dir
    
    async def save_analysis_results(self, session_id: str, results: Dict[str, Any], 
                                  filename: str = "analysis_results.json") -> str:
        """Save analysis results to file"""
        try:
            workspace_dir = await self.create_analysis_workspace(session_id)
            results_file = workspace_dir / "reports" / filename
            
            import json
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            
            return str(results_file)
            
        except Exception as e:
            self.logger.error(f"Error saving analysis results: {str(e)}")
            raise
    
    async def save_extracted_content(self, session_id: str, content: bytes, 
                                   original_filename: str, content_type: str = "unknown") -> str:
        """Save extracted content"""
        try:
            workspace_dir = await self.create_analysis_workspace(session_id)
            extracted_dir = workspace_dir / "extracted"
            
            # Generate filename for extracted content
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filename = f"{content_type}_{timestamp}_{original_filename}"
            
            # Remove any path components for security
            safe_filename = Path(safe_filename).name
            
            output_file = extracted_dir / safe_filename
            
            with open(output_file, 'wb') as f:
                f.write(content)
            
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"Error saving extracted content: {str(e)}")
            raise
    
    async def cleanup_session(self, session_id: str) -> bool:
        """Clean up session files"""
        try:
            # Clean up upload directory
            upload_dir = self.temp_dir / session_id
            if upload_dir.exists():
                shutil.rmtree(upload_dir)
            
            # Clean up results directory (optional - keep for analysis history)
            results_dir = self.results_dir / session_id
            if results_dir.exists():
                # Move to archive or delete based on configuration
                # For now, keep results for 24 hours
                pass
            
            self.logger.info(f"Session cleanup completed: {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during session cleanup: {str(e)}")
            return False
    
    async def get_session_files(self, session_id: str) -> List[Dict[str, Any]]:
        """Get list of files in session"""
        files = []
        
        try:
            session_dir = self.temp_dir / session_id
            if session_dir.exists():
                for file_path in session_dir.iterdir():
                    if file_path.is_file():
                        file_info = await self.get_file_info(file_path)
                        file_info['session_path'] = str(file_path)
                        files.append(file_info)
            
        except Exception as e:
            self.logger.error(f"Error getting session files: {str(e)}")
        
        return files
    
    async def check_disk_space(self) -> Dict[str, Any]:
        """Check available disk space"""
        try:
            # Check temp directory space
            temp_usage = shutil.disk_usage(self.temp_dir)
            results_usage = shutil.disk_usage(self.results_dir)
            
            return {
                'temp_dir': {
                    'total': temp_usage.total,
                    'used': temp_usage.used,
                    'free': temp_usage.free,
                    'percent_used': (temp_usage.used / temp_usage.total) * 100
                },
                'results_dir': {
                    'total': results_usage.total,
                    'used': results_usage.used,
                    'free': results_usage.free,
                    'percent_used': (results_usage.used / results_usage.total) * 100
                }
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def cleanup_old_files(self, max_age_hours: int = 24) -> Dict[str, Any]:
        """Clean up old temporary files"""
        cleanup_stats = {
            'files_removed': 0,
            'space_freed': 0,
            'errors': []
        }
        
        try:
            current_time = datetime.now().timestamp()
            max_age_seconds = max_age_hours * 3600
            
            # Clean up temp directory
            for item in self.temp_dir.iterdir():
                try:
                    if item.is_dir():
                        # Check directory age
                        dir_age = current_time - item.stat().st_mtime
                        if dir_age > max_age_seconds:
                            # Calculate size before removal
                            size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                            shutil.rmtree(item)
                            cleanup_stats['files_removed'] += 1
                            cleanup_stats['space_freed'] += size
                    
                except Exception as e:
                    cleanup_stats['errors'].append(f"Error removing {item}: {str(e)}")
            
            # Clean up old results (optional)
            for item in self.results_dir.iterdir():
                try:
                    if item.is_dir():
                        dir_age = current_time - item.stat().st_mtime
                        if dir_age > max_age_seconds * 7:  # Keep results longer
                            size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                            shutil.rmtree(item)
                            cleanup_stats['files_removed'] += 1
                            cleanup_stats['space_freed'] += size
                    
                except Exception as e:
                    cleanup_stats['errors'].append(f"Error removing {item}: {str(e)}")
            
        except Exception as e:
            cleanup_stats['errors'].append(f"General cleanup error: {str(e)}")
        
        return cleanup_stats
