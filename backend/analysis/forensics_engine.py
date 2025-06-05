# filepath: e:\stegano\backend\analysis\forensics_engine.py
"""
Forensics Engine - Integration with cybersecurity tools
Binwalk, Foremost, ExifTool, Zsteg, Stegoveritas integration
"""

import subprocess
import asyncio
import tempfile
import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import shlex
import re

logger = logging.getLogger(__name__)

class ForensicsEngine:
    """Integration with forensics and steganography tools"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.temp_dir = Path(tempfile.gettempdir()) / "stegano_forensics"
        self.temp_dir.mkdir(exist_ok=True)
        
        # Tool paths - update these based on your installation
        self.tools = {
            "binwalk": "binwalk",
            "foremost": "foremost", 
            "exiftool": "exiftool",
            "zsteg": "zsteg",
            "stegoveritas": "stegoveritas",
            "strings": "strings",
            "file": "file",
            "hexdump": "hexdump"
        }
        
    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Run comprehensive forensics analysis"""
        results = {
            "file_info": {},
            "embedded_files": {},
            "metadata": {},
            "strings_analysis": {},
            "steganography_tools": {},
            "suspicious_indicators": [],
            "embedded_file_count": 0
        }
        
        try:
            # Basic file information
            results["file_info"] = await self.get_file_info(file_path)
            
            # Binwalk analysis for embedded files
            results["embedded_files"] = await self.run_binwalk(file_path)
            
            # Foremost file carving
            foremost_results = await self.run_foremost(file_path)
            if foremost_results:
                results["embedded_files"]["foremost"] = foremost_results
            
            # ExifTool metadata extraction
            results["metadata"] = await self.run_exiftool(file_path)
            
            # Strings analysis
            results["strings_analysis"] = await self.run_strings_analysis(file_path)
            
            # Steganography-specific tools
            results["steganography_tools"] = await self.run_stego_tools(file_path)
            
            # Count embedded files
            results["embedded_file_count"] = self.count_embedded_files(results)
            
            # Generate suspicious indicators
            results["suspicious_indicators"] = self.analyze_suspicious_indicators(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in forensics analysis: {str(e)}")
            results["error"] = str(e)
            return results
    
    async def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information using 'file' command"""
        try:
            # Run file command
            cmd = [self.tools["file"], "-b", file_path]
            result = await self.run_command(cmd, timeout=30)
            
            if result["success"]:
                file_type = result["stdout"].strip()
            else:
                file_type = "Unknown"
            
            # Get file size and basic info
            file_stat = os.stat(file_path)
            
            return {
                "file_type": file_type,
                "size_bytes": file_stat.st_size,
                "size_mb": round(file_stat.st_size / (1024*1024), 2),
                "extension": Path(file_path).suffix.lower(),
                "filename": Path(file_path).name
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def run_binwalk(self, file_path: str) -> Dict[str, Any]:
        """Run binwalk analysis to find embedded files"""
        try:
            results = {
                "embedded_files": [],
                "entropy_analysis": {},
                "signatures": [],
                "extraction_attempted": False
            }
            
            # Check if binwalk is available
            if not await self.check_tool_availability("binwalk"):
                return {"error": "binwalk not available", "available": False}
            
            # Run binwalk signature scan
            cmd = [self.tools["binwalk"], "-B", file_path]
            result = await self.run_command(cmd, timeout=60)
            
            if result["success"]:
                results["signatures"] = self.parse_binwalk_output(result["stdout"])
            
            # Run binwalk entropy analysis
            cmd = [self.tools["binwalk"], "-E", file_path]
            entropy_result = await self.run_command(cmd, timeout=60)
            
            if entropy_result["success"]:
                results["entropy_analysis"] = self.parse_binwalk_entropy(entropy_result["stdout"])
            
            # Attempt extraction if signatures found
            if results["signatures"]:
                extract_dir = self.temp_dir / f"binwalk_extract_{os.getpid()}"
                extract_dir.mkdir(exist_ok=True)
                
                cmd = [self.tools["binwalk"], "-e", "-C", str(extract_dir), file_path]
                extract_result = await self.run_command(cmd, timeout=120)
                
                if extract_result["success"]:
                    results["extraction_attempted"] = True
                    results["extracted_files"] = self.list_extracted_files(extract_dir)
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def parse_binwalk_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse binwalk signature output"""
        signatures = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if line.strip() and not line.startswith('DECIMAL'):
                # Parse binwalk output format: DECIMAL HEXADECIMAL DESCRIPTION
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        decimal_offset = int(parts[0])
                        hex_offset = parts[1]
                        description = parts[2]
                        
                        signatures.append({
                            "offset_decimal": decimal_offset,
                            "offset_hex": hex_offset,
                            "description": description,
                            "type": self.classify_signature(description)
                        })
                    except ValueError:
                        continue
        
        return signatures
    
    def classify_signature(self, description: str) -> str:
        """Classify binwalk signature type"""
        description_lower = description.lower()
        
        if any(x in description_lower for x in ['zip', 'archive', 'compressed']):
            return "archive"
        elif any(x in description_lower for x in ['jpeg', 'png', 'gif', 'image']):
            return "image"
        elif any(x in description_lower for x in ['audio', 'mp3', 'wav']):
            return "audio"
        elif any(x in description_lower for x in ['video', 'mp4', 'avi']):
            return "video"
        elif any(x in description_lower for x in ['executable', 'elf', 'pe32']):
            return "executable"
        elif any(x in description_lower for x in ['certificate', 'key', 'crypto']):
            return "cryptographic"
        else:
            return "other"
    
    def parse_binwalk_entropy(self, output: str) -> Dict[str, Any]:
        """Parse binwalk entropy analysis output"""
        # This is a simplified parser - full implementation would parse the entropy plot data
        entropy_info = {
            "high_entropy_regions": [],
            "low_entropy_regions": [],
            "average_entropy": 0.0
        }
        
        lines = output.strip().split('\n')
        for line in lines:
            if "entropy" in line.lower():
                # Extract entropy information (simplified)
                entropy_info["analysis_performed"] = True
                break
        
        return entropy_info
    
    def list_extracted_files(self, extract_dir: Path) -> List[Dict[str, Any]]:
        """List files extracted by binwalk"""
        extracted_files = []
        
        if extract_dir.exists():
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path = Path(root) / file
                    try:
                        stat_info = file_path.stat()
                        extracted_files.append({
                            "filename": file,
                            "path": str(file_path),
                            "size": stat_info.st_size,
                            "relative_path": str(file_path.relative_to(extract_dir))
                        })
                    except Exception:
                        continue
        
        return extracted_files
    
    async def run_foremost(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Run foremost file carving"""
        try:
            if not await self.check_tool_availability("foremost"):
                return {"error": "foremost not available", "available": False}
            
            # Create output directory
            output_dir = self.temp_dir / f"foremost_output_{os.getpid()}"
            output_dir.mkdir(exist_ok=True)
            
            # Run foremost
            cmd = [self.tools["foremost"], "-o", str(output_dir), "-t", "all", file_path]
            result = await self.run_command(cmd, timeout=120)
            
            if result["success"]:
                # Parse foremost results
                audit_file = output_dir / "audit.txt"
                carved_files = []
                
                if audit_file.exists():
                    with open(audit_file, 'r', encoding='utf-8', errors='ignore') as f:
                        audit_content = f.read()
                    
                    # List carved files
                    for root, dirs, files in os.walk(output_dir):
                        for file in files:
                            if file != "audit.txt":
                                file_path = Path(root) / file
                                try:
                                    stat_info = file_path.stat()
                                    carved_files.append({
                                        "filename": file,
                                        "type": Path(root).name,
                                        "size": stat_info.st_size,
                                        "path": str(file_path)
                                    })
                                except Exception:
                                    continue
                
                return {
                    "carved_files": carved_files,
                    "total_files": len(carved_files),
                    "audit_content": audit_content if 'audit_content' in locals() else ""
                }
            else:
                return {"error": result["stderr"]}
                
        except Exception as e:
            return {"error": str(e)}
    
    async def run_exiftool(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata using ExifTool"""
        try:
            if not await self.check_tool_availability("exiftool"):
                return {"error": "exiftool not available", "available": False}
            
            # Run exiftool with JSON output
            cmd = [self.tools["exiftool"], "-json", "-all", file_path]
            result = await self.run_command(cmd, timeout=60)
            
            if result["success"]:
                try:
                    metadata = json.loads(result["stdout"])
                    if isinstance(metadata, list) and len(metadata) > 0:
                        return {
                            "metadata": metadata[0],
                            "suspicious_tags": self.analyze_suspicious_metadata(metadata[0])
                        }
                    else:
                        return {"metadata": {}, "suspicious_tags": []}
                except json.JSONDecodeError:
                    return {"error": "Failed to parse exiftool output"}
            else:
                return {"error": result["stderr"]}
                
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_suspicious_metadata(self, metadata: Dict[str, Any]) -> List[str]:
        """Analyze metadata for suspicious indicators"""
        suspicious = []
        
        # Check for unusual metadata
        suspicious_fields = ['Comment', 'UserComment', 'ImageDescription', 'XPComment']
        
        for field in suspicious_fields:
            if field in metadata:
                value = str(metadata[field])
                # Check for base64-like strings
                if len(value) > 20 and self.is_base64_like(value):
                    suspicious.append(f"suspicious_{field.lower()}")
                # Check for unusual characters
                if any(ord(c) > 127 for c in value):
                    suspicious.append(f"non_ascii_{field.lower()}")
        
        # Check for unusual software/tools
        if 'Software' in metadata:
            software = str(metadata['Software']).lower()
            suspicious_software = ['steghide', 'openstego', 'steganos', 'hide']
            if any(tool in software for tool in suspicious_software):
                suspicious.append("suspicious_software")
        
        return suspicious
    
    def is_base64_like(self, text: str) -> bool:
        """Check if text looks like base64 encoding"""
        import re
        # Simple base64 pattern check
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        return bool(base64_pattern.match(text.strip()))
    
    async def run_strings_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run strings analysis to find readable text"""
        try:
            if not await self.check_tool_availability("strings"):
                # Fallback to Python implementation
                return await self.python_strings_analysis(file_path)
            
            # Run strings command
            cmd = [self.tools["strings"], "-n", "4", file_path]
            result = await self.run_command(cmd, timeout=60)
            
            if result["success"]:
                strings_list = result["stdout"].strip().split('\n')
                
                return {
                    "total_strings": len(strings_list),
                    "suspicious_strings": self.find_suspicious_strings(strings_list),
                    "url_patterns": self.find_url_patterns(strings_list),
                    "email_patterns": self.find_email_patterns(strings_list),
                    "base64_patterns": self.find_base64_patterns(strings_list)
                }
            else:
                return {"error": result["stderr"]}
                
        except Exception as e:
            return {"error": str(e)}
    
    async def python_strings_analysis(self, file_path: str) -> Dict[str, Any]:
        """Python fallback for strings analysis"""
        try:
            strings_list = []
            
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Extract strings (printable ASCII sequences of length 4+)
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings_list.append(current_string)
                    current_string = ""
            
            if len(current_string) >= 4:
                strings_list.append(current_string)
            
            return {
                "total_strings": len(strings_list),
                "suspicious_strings": self.find_suspicious_strings(strings_list),
                "url_patterns": self.find_url_patterns(strings_list),
                "email_patterns": self.find_email_patterns(strings_list),
                "base64_patterns": self.find_base64_patterns(strings_list)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def find_suspicious_strings(self, strings_list: List[str]) -> List[str]:
        """Find suspicious strings that might indicate steganography"""
        suspicious = []
        suspicious_keywords = [
            'password', 'secret', 'hidden', 'steganography', 'stego',
            'encrypted', 'payload', 'backdoor', 'malware', 'exploit'
        ]
        
        for string in strings_list:
            string_lower = string.lower()
            if any(keyword in string_lower for keyword in suspicious_keywords):
                suspicious.append(string)
        
        return suspicious[:20]  # Limit to first 20
    
    def find_url_patterns(self, strings_list: List[str]) -> List[str]:
        """Find URL patterns in strings"""
        import re
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        urls = []
        
        for string in strings_list:
            matches = url_pattern.findall(string)
            urls.extend(matches)
        
        return list(set(urls))[:10]  # Unique URLs, limit to 10
    
    def find_email_patterns(self, strings_list: List[str]) -> List[str]:
        """Find email patterns in strings"""
        import re
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = []
        
        for string in strings_list:
            matches = email_pattern.findall(string)
            emails.extend(matches)
        
        return list(set(emails))[:10]  # Unique emails, limit to 10
    
    def find_base64_patterns(self, strings_list: List[str]) -> List[str]:
        """Find potential base64 encoded strings"""
        base64_like = []
        
        for string in strings_list:
            if len(string) >= 20 and self.is_base64_like(string):
                base64_like.append(string)
        
        return base64_like[:10]  # Limit to 10
    
    async def run_stego_tools(self, file_path: str) -> Dict[str, Any]:
        """Run steganography-specific detection tools"""
        results = {}
        
        # Run zsteg for images (if available)
        if Path(file_path).suffix.lower() in ['.png', '.bmp']:
            results["zsteg"] = await self.run_zsteg(file_path)
        
        # Run stegoveritas (if available)
        results["stegoveritas"] = await self.run_stegoveritas(file_path)
        
        return results
    
    async def run_zsteg(self, file_path: str) -> Dict[str, Any]:
        """Run zsteg analysis for PNG/BMP files"""
        try:
            if not await self.check_tool_availability("zsteg"):
                return {"error": "zsteg not available", "available": False}
            
            cmd = [self.tools["zsteg"], "-a", file_path]
            result = await self.run_command(cmd, timeout=120)
            
            if result["success"]:
                return {
                    "output": result["stdout"],
                    "found_data": len(result["stdout"].strip()) > 0,
                    "analysis": self.parse_zsteg_output(result["stdout"])
                }
            else:
                return {"error": result["stderr"]}
                
        except Exception as e:
            return {"error": str(e)}
    
    def parse_zsteg_output(self, output: str) -> Dict[str, Any]:
        """Parse zsteg output for meaningful information"""
        lines = output.strip().split('\n')
        findings = []
        
        for line in lines:
            if line.strip() and not line.startswith('b'):
                # zsteg output format analysis
                if 'text' in line.lower() or 'ascii' in line.lower():
                    findings.append({
                        "type": "text",
                        "description": line.strip()
                    })
                elif 'file' in line.lower():
                    findings.append({
                        "type": "file",
                        "description": line.strip()
                    })
        
        return {
            "total_findings": len(findings),
            "findings": findings
        }
    
    async def run_stegoveritas(self, file_path: str) -> Dict[str, Any]:
        """Run stegoveritas analysis"""
        try:
            if not await self.check_tool_availability("stegoveritas"):
                return {"error": "stegoveritas not available", "available": False}
            
            # Create output directory
            output_dir = self.temp_dir / f"stegoveritas_output_{os.getpid()}"
            output_dir.mkdir(exist_ok=True)
            
            cmd = [self.tools["stegoveritas"], "-out", str(output_dir), file_path]
            result = await self.run_command(cmd, timeout=180)
            
            if result["success"]:
                # Analyze stegoveritas output
                return {
                    "output_directory": str(output_dir),
                    "analysis_completed": True,
                    "output_files": self.list_stegoveritas_output(output_dir)
                }
            else:
                return {"error": result["stderr"]}
                
        except Exception as e:
            return {"error": str(e)}
    
    def list_stegoveritas_output(self, output_dir: Path) -> List[Dict[str, Any]]:
        """List and analyze stegoveritas output files"""
        output_files = []
        
        if output_dir.exists():
            for file_path in output_dir.rglob('*'):
                if file_path.is_file():
                    try:
                        stat_info = file_path.stat()
                        output_files.append({
                            "filename": file_path.name,
                            "size": stat_info.st_size,
                            "type": self.guess_file_type(file_path),
                            "path": str(file_path)
                        })
                    except Exception:
                        continue
        
        return output_files
    
    def guess_file_type(self, file_path: Path) -> str:
        """Guess file type based on extension and content"""
        suffix = file_path.suffix.lower()
        
        type_map = {
            '.txt': 'text',
            '.png': 'image',
            '.jpg': 'image',
            '.jpeg': 'image',
            '.html': 'html',
            '.json': 'json'
        }
        
        return type_map.get(suffix, 'unknown')
    
    def count_embedded_files(self, results: Dict[str, Any]) -> int:
        """Count total embedded files found"""
        count = 0
        
        # Count binwalk signatures
        if "embedded_files" in results and "signatures" in results["embedded_files"]:
            count += len(results["embedded_files"]["signatures"])
        
        # Count foremost carved files
        if "embedded_files" in results and "foremost" in results["embedded_files"]:
            count += results["embedded_files"]["foremost"].get("total_files", 0)
        
        return count
    
    def analyze_suspicious_indicators(self, results: Dict[str, Any]) -> List[str]:
        """Analyze all results for suspicious indicators"""
        indicators = []
        
        # Check embedded files
        if results.get("embedded_file_count", 0) > 0:
            indicators.append(f"embedded_files_detected_{results['embedded_file_count']}")
        
        # Check metadata
        metadata = results.get("metadata", {})
        if metadata.get("suspicious_tags"):
            indicators.extend(metadata["suspicious_tags"])
        
        # Check strings analysis
        strings_analysis = results.get("strings_analysis", {})
        if strings_analysis.get("suspicious_strings"):
            indicators.append("suspicious_strings_found")
        if strings_analysis.get("base64_patterns"):
            indicators.append("base64_patterns_found")
        
        # Check steganography tools results
        stego_tools = results.get("steganography_tools", {})
        if stego_tools.get("zsteg", {}).get("found_data"):
            indicators.append("zsteg_data_found")
        
        return indicators
    
    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a forensics tool is available"""
        try:
            cmd = [self.tools[tool_name], "--version"]
            result = await self.run_command(cmd, timeout=10)
            return result["success"]
        except Exception:
            return False
    
    async def run_command(self, cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Run a command with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return {
                "success": process.returncode == 0,
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore')
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Command timed out",
                "stdout": "",
                "stderr": f"Timeout after {timeout} seconds"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": str(e)
            }
