# filepath: e:\stegano\backend\analysis\signature_detector.py
"""
Signature Detection Engine
YARA rules and custom signature detection for steganographic payloads
"""

import os
import asyncio
import logging
import math
from typing import Dict, Any, List, Optional
from pathlib import Path
import hashlib
import re
import binascii

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

logger = logging.getLogger(__name__)

class SignatureDetector:
    """Advanced signature detection using YARA rules and custom patterns"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.yara_rules = None
        self.custom_signatures = self._load_custom_signatures()
        
        # Initialize YARA if available
        if YARA_AVAILABLE:
            self._initialize_yara_rules()
        else:
            self.logger.warning("YARA not available - signature detection will be limited")
    
    def _initialize_yara_rules(self):
        """Initialize YARA rules for steganography detection"""
        try:
            # Define built-in steganography detection rules
            stego_rules = """
            rule Steghide_Signature {
                meta:
                    description = "Detects Steghide embedded data"
                    author = "Stegano Scanner"
                strings:
                    $steghide1 = { 53 74 65 67 68 69 64 65 }  // "Steghide"
                    $steghide2 = "steghide"
                    $steghide3 = "STEGHIDE"
                condition:
                    any of them
            }
            
            rule LSB_Steganography {
                meta:
                    description = "Detects potential LSB steganography patterns"
                    author = "Stegano Scanner"
                strings:
                    $lsb_pattern1 = { 00 01 00 01 00 01 00 01 }
                    $lsb_pattern2 = { FF FE FF FE FF FE FF FE }
                condition:
                    any of them
            }
            
            rule Base64_Hidden_Data {
                meta:
                    description = "Detects suspicious base64 encoded data"
                    author = "Stegano Scanner"                strings:
                    $base64_long = /[A-Za-z0-9+\\/]{100,}={0,2}/
                condition:
                    $base64_long
            }
            
            rule Embedded_Archive {
                meta:
                    description = "Detects embedded archive files"
                    author = "Stegano Scanner"
                strings:
                    $zip_header = { 50 4B 03 04 }
                    $rar_header = { 52 61 72 21 1A 07 00 }
                    $7z_header = { 37 7A BC AF 27 1C }
                    $gzip_header = { 1F 8B }
                condition:
                    any of them
            }
            
            rule Executable_In_Image {
                meta:
                    description = "Detects executable files embedded in images"
                    author = "Stegano Scanner"
                strings:
                    $pe_header = { 4D 5A }  // MZ header
                    $elf_header = { 7F 45 4C 46 }  // ELF header
                condition:
                    any of them
            }
            
            rule Suspicious_Text_Patterns {
                meta:
                    description = "Detects suspicious text patterns in metadata"
                    author = "Stegano Scanner"
                strings:
                    $password = "password" nocase
                    $secret = "secret" nocase
                    $hidden = "hidden" nocase
                    $encrypted = "encrypted" nocase
                    $decode = "decode" nocase
                condition:
                    any of them
            }
            
            rule Cryptographic_Constants {
                meta:
                    description = "Detects cryptographic constants"
                    author = "Stegano Scanner"
                strings:
                    $md5_init = { 67 45 23 01 EF CD AB 89 }
                    $sha1_init = { 67 45 23 01 }
                    $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 }
                condition:
                    any of them
            }
            """
            
            # Compile YARA rules
            self.yara_rules = yara.compile(source=stego_rules)
            self.logger.info("YARA rules compiled successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize YARA rules: {str(e)}")
            self.yara_rules = None
    
    def _load_custom_signatures(self) -> Dict[str, Any]:
        """Load custom signature patterns"""
        return {
            "steganography_tools": {
                "steghide": [b"steghide", b"STEGHIDE", b"Steghide"],
                "openstego": [b"OpenStego", b"openstego"],
                "steganos": [b"Steganos", b"STEGANOS"],
                "hide_seek": [b"hide", b"seek"],
                "jsteg": [b"jsteg", b"JSTEG"],
                "outguess": [b"outguess", b"OutGuess"],
                "stegdetect": [b"stegdetect"],
                "f5": [b"F5 steganography", b"f5stego"]
            },
            "compression_signatures": {
                "zip": [b"PK\x03\x04", b"PK\x05\x06"],
                "rar": [b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01"],
                "7zip": [b"7z\xbc\xaf\x27\x1c"],
                "gzip": [b"\x1f\x8b"],
                "bzip2": [b"BZ"],
                "xz": [b"\xfd7zXZ\x00"]
            },
            "executable_signatures": {
                "pe": [b"MZ"],
                "elf": [b"\x7fELF"],
                "mach_o": [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"],
                "java_class": [b"\xca\xfe\xba\xbe"]
            },
            "crypto_signatures": {
                "pgp": [b"-----BEGIN PGP", b"-----END PGP"],
                "ssh_key": [b"-----BEGIN OPENSSH", b"ssh-rsa", b"ssh-dss"],
                "x509": [b"-----BEGIN CERTIFICATE", b"-----END CERTIFICATE"],
                "pkcs": [b"-----BEGIN PRIVATE KEY", b"-----END PRIVATE KEY"]
            }
        }
    
    async def detect_signatures(self, file_path: str, extracted_content: Optional[bytes] = None) -> Dict[str, Any]:
        """Main signature detection function"""
        results = {
            "yara_matches": [],
            "custom_signatures": {},
            "entropy_signatures": [],
            "statistical_signatures": [],
            "total_detections": 0
        }
        
        try:
            # Read file content
            if extracted_content:
                file_content = extracted_content
            else:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
            
            # YARA rule matching
            if self.yara_rules:
                results["yara_matches"] = await self.run_yara_scan(file_content)
            
            # Custom signature detection
            results["custom_signatures"] = self.detect_custom_signatures(file_content)
            
            # Entropy-based signature detection
            results["entropy_signatures"] = self.detect_entropy_signatures(file_content)
            
            # Statistical signature detection
            results["statistical_signatures"] = self.detect_statistical_signatures(file_content)
            
            # Calculate total detections
            results["total_detections"] = self.count_total_detections(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in signature detection: {str(e)}")
            return {"error": str(e)}
    
    async def run_yara_scan(self, content: bytes) -> List[Dict[str, Any]]:
        """Run YARA rules against content"""
        matches = []
        
        try:
            if self.yara_rules:
                # Run YARA scan in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                yara_matches = await loop.run_in_executor(
                    None, self.yara_rules.match, data=content
                )
                
                for match in yara_matches:
                    match_info = {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                        "strings": []
                    }
                    
                    # Extract string matches
                    for string_match in match.strings:
                        match_info["strings"].append({
                            "identifier": string_match.identifier,
                            "instances": [
                                {
                                    "offset": instance.offset,
                                    "length": instance.length,
                                    "matched_data": instance.matched_data.hex()
                                }
                                for instance in string_match.instances
                            ]
                        })
                    
                    matches.append(match_info)
                    
        except Exception as e:
            self.logger.error(f"YARA scan error: {str(e)}")
            
        return matches
    
    def detect_custom_signatures(self, content: bytes) -> Dict[str, Any]:
        """Detect custom signature patterns"""
        detections = {}
        
        for category, signatures in self.custom_signatures.items():
            category_matches = {}
            
            for sig_name, patterns in signatures.items():
                matches = []
                
                for pattern in patterns:
                    # Find all occurrences of pattern
                    start = 0
                    while True:
                        pos = content.find(pattern, start)
                        if pos == -1:
                            break
                        
                        matches.append({
                            "offset": pos,
                            "pattern": pattern.hex(),
                            "context": content[max(0, pos-10):pos+len(pattern)+10].hex()
                        })
                        
                        start = pos + 1
                
                if matches:
                    category_matches[sig_name] = {
                        "match_count": len(matches),
                        "matches": matches[:10]  # Limit to first 10 matches
                    }
            
            if category_matches:
                detections[category] = category_matches
        
        return detections
    
    def detect_entropy_signatures(self, content: bytes) -> List[Dict[str, Any]]:
        """Detect entropy-based signatures"""
        signatures = []
        
        try:
            # Analyze content in chunks
            chunk_size = 1024
            high_entropy_threshold = 7.5
            low_entropy_threshold = 1.0
            
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i+chunk_size]
                if len(chunk) < 100:  # Skip small chunks
                    continue
                
                entropy = self.calculate_entropy(chunk)
                
                # Detect high entropy regions (potential encryption/compression)
                if entropy > high_entropy_threshold:
                    signatures.append({
                        "type": "high_entropy",
                        "offset": i,
                        "length": len(chunk),
                        "entropy": entropy,
                        "description": "High entropy region - possible encrypted/compressed data"
                    })
                
                # Detect low entropy regions (potential padding/steganographic payload)
                elif entropy < low_entropy_threshold:
                    signatures.append({
                        "type": "low_entropy",
                        "offset": i,
                        "length": len(chunk),
                        "entropy": entropy,
                        "description": "Low entropy region - possible steganographic payload"
                    })
                
                # Detect entropy anomalies
                if i > 0:
                    prev_chunk = content[max(0, i-chunk_size):i]
                    if len(prev_chunk) >= 100:
                        prev_entropy = self.calculate_entropy(prev_chunk)
                        entropy_diff = abs(entropy - prev_entropy)
                        
                        if entropy_diff > 3.0:
                            signatures.append({
                                "type": "entropy_anomaly",
                                "offset": i,
                                "length": len(chunk),
                                "entropy": entropy,
                                "prev_entropy": prev_entropy,
                                "entropy_diff": entropy_diff,
                                "description": "Sudden entropy change - possible data boundary"
                            })
            
        except Exception as e:
            self.logger.error(f"Entropy signature detection error: {str(e)}")
        
        return signatures
    
    def detect_statistical_signatures(self, content: bytes) -> List[Dict[str, Any]]:
        """Detect statistical anomalies that might indicate steganography"""
        signatures = []
        
        try:
            # Byte frequency analysis
            byte_freq = self.analyze_byte_frequency(content)
            signatures.extend(self.detect_frequency_anomalies(byte_freq))
            
            # Pattern analysis
            pattern_sigs = self.detect_pattern_anomalies(content)
            signatures.extend(pattern_sigs)
            
            # Correlation analysis
            correlation_sigs = self.detect_correlation_anomalies(content)
            signatures.extend(correlation_sigs)
            
        except Exception as e:
            self.logger.error(f"Statistical signature detection error: {str(e)}")
        
        return signatures
    
    def analyze_byte_frequency(self, content: bytes) -> Dict[int, int]:
        """Analyze byte frequency distribution"""
        frequency = {}
        
        for byte in content:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        return frequency
    
    def detect_frequency_anomalies(self, byte_freq: Dict[int, int]) -> List[Dict[str, Any]]:
        """Detect frequency-based anomalies"""
        anomalies = []
        
        try:
            total_bytes = sum(byte_freq.values())
            
            # Calculate expected frequency (uniform distribution)
            expected_freq = total_bytes / 256
            
            # Detect unusual frequency patterns
            high_freq_bytes = []
            low_freq_bytes = []
            
            for byte_val, freq in byte_freq.items():
                deviation = abs(freq - expected_freq) / expected_freq
                
                if deviation > 2.0:  # More than 200% deviation
                    if freq > expected_freq:
                        high_freq_bytes.append((byte_val, freq, deviation))
                    else:
                        low_freq_bytes.append((byte_val, freq, deviation))
            
            if high_freq_bytes:
                anomalies.append({
                    "type": "high_frequency_bytes",
                    "description": "Bytes with unusually high frequency",
                    "bytes": high_freq_bytes[:10],  # Top 10
                    "count": len(high_freq_bytes)
                })
            
            if low_freq_bytes:
                anomalies.append({
                    "type": "low_frequency_bytes", 
                    "description": "Bytes with unusually low frequency",
                    "bytes": low_freq_bytes[:10],  # Top 10
                    "count": len(low_freq_bytes)
                })
            
            # Check for ASCII bias (common in text-based steganography)
            ascii_count = sum(freq for byte_val, freq in byte_freq.items() if 32 <= byte_val <= 126)
            ascii_ratio = ascii_count / total_bytes
            
            if ascii_ratio > 0.8:
                anomalies.append({
                    "type": "ascii_bias",
                    "description": "High concentration of ASCII characters",
                    "ascii_ratio": ascii_ratio
                })
            
        except Exception as e:
            self.logger.error(f"Frequency anomaly detection error: {str(e)}")
        
        return anomalies
    
    def detect_pattern_anomalies(self, content: bytes) -> List[Dict[str, Any]]:
        """Detect pattern-based anomalies"""
        anomalies = []
        
        try:
            # Detect repeating patterns
            pattern_length = 4
            patterns = {}
            
            for i in range(len(content) - pattern_length + 1):
                pattern = content[i:i+pattern_length]
                pattern_hex = pattern.hex()
                patterns[pattern_hex] = patterns.get(pattern_hex, 0) + 1
            
            # Find most common patterns
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            
            # Detect unusual repetition
            total_patterns = len(content) - pattern_length + 1
            for pattern, count in sorted_patterns[:5]:
                frequency = count / total_patterns
                if frequency > 0.01:  # More than 1% of all patterns
                    anomalies.append({
                        "type": "repeating_pattern",
                        "description": f"Pattern {pattern} repeats {count} times",
                        "pattern": pattern,
                        "count": count,
                        "frequency": frequency
                    })
            
            # Detect null byte sequences
            null_sequences = self.find_null_sequences(content)
            if null_sequences:
                anomalies.append({
                    "type": "null_sequences",
                    "description": "Sequences of null bytes found",
                    "sequences": null_sequences[:10]
                })
            
        except Exception as e:
            self.logger.error(f"Pattern anomaly detection error: {str(e)}")
        
        return anomalies
    
    def find_null_sequences(self, content: bytes) -> List[Dict[str, Any]]:
        """Find sequences of null bytes"""
        sequences = []
        in_sequence = False
        sequence_start = 0
        sequence_length = 0
        
        for i, byte in enumerate(content):
            if byte == 0:
                if not in_sequence:
                    in_sequence = True
                    sequence_start = i
                    sequence_length = 1
                else:
                    sequence_length += 1
            else:
                if in_sequence and sequence_length >= 10:  # Significant null sequence
                    sequences.append({
                        "offset": sequence_start,
                        "length": sequence_length
                    })
                in_sequence = False
                sequence_length = 0
        
        # Check final sequence
        if in_sequence and sequence_length >= 10:
            sequences.append({
                "offset": sequence_start,
                "length": sequence_length
            })
        
        return sequences
    
    def detect_correlation_anomalies(self, content: bytes) -> List[Dict[str, Any]]:
        """Detect correlation-based anomalies"""
        anomalies = []
        
        try:
            # Analyze byte pairs (bigrams)
            bigrams = {}
            for i in range(len(content) - 1):
                bigram = (content[i], content[i+1])
                bigrams[bigram] = bigrams.get(bigram, 0) + 1
            
            total_bigrams = len(content) - 1
            
            # Find unusual bigram patterns
            sorted_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)
            
            for bigram, count in sorted_bigrams[:10]:
                frequency = count / total_bigrams
                if frequency > 0.005:  # More than 0.5% of all bigrams
                    anomalies.append({
                        "type": "frequent_bigram",
                        "description": f"Bigram {bigram[0]:02x}{bigram[1]:02x} appears {count} times",
                        "bigram": [bigram[0], bigram[1]],
                        "count": count,
                        "frequency": frequency
                    })
            
        except Exception as e:
            self.logger.error(f"Correlation anomaly detection error: {str(e)}")
        
        return anomalies
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
          for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def count_total_detections(self, results: Dict[str, Any]) -> int:
        """Count total number of detections across all methods"""
        total = 0
        
        # Count YARA matches
        total += len(results.get("yara_matches", []))
        
        # Count custom signatures
        custom_sigs = results.get("custom_signatures", {})
        for category in custom_sigs.values():
            for sig_matches in category.values():
                total += sig_matches.get("match_count", 0)
        
        # Count entropy signatures
        total += len(results.get("entropy_signatures", []))
        
        # Count statistical signatures
        total += len(results.get("statistical_signatures", []))
        
        return total
    
    async def scan_extracted_content(self, extracted_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan extracted content for signatures"""
        scan_results = {
            "total_files_scanned": 0,
            "files_with_detections": 0,
            "file_results": []
        }
        
        try:
            for file_info in extracted_files:
                file_path = file_info.get("path")
                if not file_path or not os.path.exists(file_path):
                    continue
                
                # Scan individual file
                file_result = await self.detect_signatures(file_path)
                file_result["file_info"] = file_info
                
                scan_results["file_results"].append(file_result)
                scan_results["total_files_scanned"] += 1
                
                if file_result.get("total_detections", 0) > 0:
                    scan_results["files_with_detections"] += 1
            
        except Exception as e:
            scan_results["error"] = str(e)
        
        return scan_results
