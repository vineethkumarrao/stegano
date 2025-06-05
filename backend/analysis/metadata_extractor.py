# filepath: e:\stegano\backend\analysis\metadata_extractor.py
"""
Metadata Extraction Engine
Advanced metadata analysis for steganography detection
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import hashlib
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import mutagen
from mutagen.id3 import ID3NoHeaderError
import subprocess

logger = logging.getLogger(__name__)

class MetadataExtractor:
    """Advanced metadata extraction and analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    async def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Main metadata extraction function"""
        try:
            file_ext = Path(file_path).suffix.lower()
            metadata = {
                "file_info": await self.get_basic_file_info(file_path),
                "image_metadata": {},
                "audio_metadata": {},
                "video_metadata": {},
                "suspicious_indicators": [],
                "hash_analysis": await self.analyze_file_hashes(file_path)
            }
            
            # Extract based on file type
            if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.gif']:
                metadata["image_metadata"] = await self.extract_image_metadata(file_path)
            elif file_ext in ['.wav', '.mp3', '.flac', '.ogg', '.m4a']:
                metadata["audio_metadata"] = await self.extract_audio_metadata(file_path)
            elif file_ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv']:
                metadata["video_metadata"] = await self.extract_video_metadata(file_path)
            
            # Analyze for suspicious indicators
            metadata["suspicious_indicators"] = self.analyze_suspicious_patterns(metadata)
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {str(e)}")
            return {"error": str(e)}
    
    async def get_basic_file_info(self, file_path: str) -> Dict[str, Any]:
        """Extract basic file information"""
        try:
            stat_info = os.stat(file_path)
            file_path_obj = Path(file_path)
            
            return {
                "filename": file_path_obj.name,
                "file_size": stat_info.st_size,
                "file_extension": file_path_obj.suffix.lower(),
                "creation_time": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "modification_time": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "access_time": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                "permissions": oct(stat_info.st_mode)[-3:]
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def extract_image_metadata(self, image_path: str) -> Dict[str, Any]:
        """Extract comprehensive image metadata"""
        metadata = {
            "exif_data": {},
            "image_properties": {},
            "color_analysis": {},
            "compression_info": {}
        }
        
        try:
            # Extract EXIF data using PIL
            with Image.open(image_path) as img:
                # Basic image properties
                metadata["image_properties"] = {
                    "format": img.format,
                    "mode": img.mode,
                    "size": img.size,
                    "width": img.width,
                    "height": img.height,
                    "has_transparency": img.mode in ('RGBA', 'LA') or 'transparency' in img.info
                }
                
                # EXIF data
                exifdata = img.getexif()
                if exifdata is not None:
                    for tag_id in exifdata:
                        tag = TAGS.get(tag_id, tag_id)
                        data = exifdata.get(tag_id)
                        
                        # Handle GPS data separately
                        if tag == "GPSInfo":
                            gps_data = {}
                            for gps_tag_id in data:
                                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                                gps_data[gps_tag] = data[gps_tag_id]
                            metadata["exif_data"]["GPSInfo"] = gps_data
                        else:
                            # Convert bytes to string for JSON serialization
                            if isinstance(data, bytes):
                                try:
                                    data = data.decode('utf-8', errors='ignore')
                                except:
                                    data = str(data)
                            metadata["exif_data"][tag] = data
                
                # Color analysis
                metadata["color_analysis"] = await self.analyze_image_colors(img)
                
                # Compression analysis
                metadata["compression_info"] = self.analyze_image_compression(img)
                
        except Exception as e:
            metadata["error"] = str(e)
            
        return metadata
    
    async def analyze_image_colors(self, img: Image.Image) -> Dict[str, Any]:
        """Analyze image color properties"""
        try:
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img_rgb = img.convert('RGB')
            else:
                img_rgb = img
            
            # Get dominant colors
            colors = img_rgb.getcolors(maxcolors=256*256*256)
            if colors:
                # Sort by frequency
                colors.sort(reverse=True)
                dominant_colors = [{"count": count, "rgb": rgb} for count, rgb in colors[:5]]
            else:
                dominant_colors = []
            
            # Color statistics
            from PIL import ImageStat
            stat = ImageStat.Stat(img_rgb)
            
            return {
                "dominant_colors": dominant_colors,
                "mean_rgb": stat.mean,
                "median_rgb": stat.median,
                "stddev_rgb": stat.stddev,
                "color_count": len(colors) if colors else 0
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_image_compression(self, img: Image.Image) -> Dict[str, Any]:
        """Analyze image compression characteristics"""
        compression_info = {
            "format": img.format,
            "quality_estimate": None,
            "compression_artifacts": []
        }
        
        try:
            # JPEG quality estimation
            if img.format == 'JPEG':
                # Estimate quality based on quantization tables (simplified)
                if hasattr(img, 'quantization'):
                    q_tables = img.quantization
                    if q_tables:
                        # Simple quality estimation
                        avg_quant = sum(sum(table) for table in q_tables.values()) / sum(len(table) for table in q_tables.values())
                        quality_estimate = max(1, min(100, int(100 - (avg_quant - 1) * 2)))
                        compression_info["quality_estimate"] = quality_estimate
            
            # Check for recompression artifacts
            if img.format in ['JPEG', 'WEBP']:
                compression_info["compression_artifacts"].append("lossy_compression")
            
        except Exception as e:
            compression_info["error"] = str(e)
            
        return compression_info
    
    async def extract_audio_metadata(self, audio_path: str) -> Dict[str, Any]:
        """Extract comprehensive audio metadata"""
        metadata = {
            "basic_info": {},
            "tags": {},
            "technical_info": {},
            "stream_info": []
        }
        
        try:
            # Use mutagen for audio metadata
            audiofile = mutagen.File(audio_path)
            if audiofile is not None:
                # Basic info
                if hasattr(audiofile, 'info'):
                    info = audiofile.info
                    metadata["basic_info"] = {
                        "length": getattr(info, 'length', 0),
                        "bitrate": getattr(info, 'bitrate', 0),
                        "sample_rate": getattr(info, 'sample_rate', 0),
                        "channels": getattr(info, 'channels', 0),
                        "format": getattr(info, 'format', 'unknown')
                    }
                
                # Tags/metadata
                if audiofile.tags:
                    for key, value in audiofile.tags.items():
                        # Convert list values to strings
                        if isinstance(value, list):
                            value = ', '.join(str(v) for v in value)
                        metadata["tags"][key] = str(value)
                
                # Stream analysis using ffprobe if available
                metadata["stream_info"] = await self.analyze_audio_streams(audio_path)
                
        except ID3NoHeaderError:
            metadata["error"] = "No ID3 header found"
        except Exception as e:
            metadata["error"] = str(e)
            
        return metadata
    
    async def analyze_audio_streams(self, audio_path: str) -> List[Dict[str, Any]]:
        """Analyze audio streams using ffprobe"""
        try:
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_streams', audio_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                return data.get('streams', [])
            else:
                return [{"error": stderr.decode()}]
                
        except Exception as e:
            return [{"error": str(e)}]
    
    async def extract_video_metadata(self, video_path: str) -> Dict[str, Any]:
        """Extract comprehensive video metadata"""
        metadata = {
            "container_info": {},
            "video_streams": [],
            "audio_streams": [],
            "subtitle_streams": [],
            "chapters": [],
            "technical_analysis": {}
        }
        
        try:
            # Use ffprobe for comprehensive video analysis
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_format', '-show_streams', '-show_chapters', video_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                
                # Container/format info
                if 'format' in data:
                    format_info = data['format']
                    metadata["container_info"] = {
                        "filename": format_info.get('filename', ''),
                        "format_name": format_info.get('format_name', ''),
                        "format_long_name": format_info.get('format_long_name', ''),
                        "duration": float(format_info.get('duration', 0)),
                        "size": int(format_info.get('size', 0)),
                        "bit_rate": int(format_info.get('bit_rate', 0)),
                        "tags": format_info.get('tags', {})
                    }
                
                # Stream analysis
                if 'streams' in data:
                    for stream in data['streams']:
                        stream_type = stream.get('codec_type', 'unknown')
                        
                        if stream_type == 'video':
                            metadata["video_streams"].append(self.parse_video_stream(stream))
                        elif stream_type == 'audio':
                            metadata["audio_streams"].append(self.parse_audio_stream(stream))
                        elif stream_type == 'subtitle':
                            metadata["subtitle_streams"].append(self.parse_subtitle_stream(stream))
                
                # Chapters
                metadata["chapters"] = data.get('chapters', [])
                
                # Technical analysis
                metadata["technical_analysis"] = await self.analyze_video_technical(video_path)
                
            else:
                metadata["error"] = stderr.decode()
                
        except Exception as e:
            metadata["error"] = str(e)
            
        return metadata
    
    def parse_video_stream(self, stream: Dict[str, Any]) -> Dict[str, Any]:
        """Parse video stream information"""
        return {
            "index": stream.get('index', 0),
            "codec_name": stream.get('codec_name', ''),
            "codec_long_name": stream.get('codec_long_name', ''),
            "width": stream.get('width', 0),
            "height": stream.get('height', 0),
            "aspect_ratio": stream.get('display_aspect_ratio', ''),
            "pixel_format": stream.get('pix_fmt', ''),
            "frame_rate": stream.get('r_frame_rate', ''),
            "bit_rate": int(stream.get('bit_rate', 0)) if stream.get('bit_rate') else 0,
            "duration": float(stream.get('duration', 0)) if stream.get('duration') else 0,
            "tags": stream.get('tags', {})
        }
    
    def parse_audio_stream(self, stream: Dict[str, Any]) -> Dict[str, Any]:
        """Parse audio stream information"""
        return {
            "index": stream.get('index', 0),
            "codec_name": stream.get('codec_name', ''),
            "codec_long_name": stream.get('codec_long_name', ''),
            "sample_rate": int(stream.get('sample_rate', 0)) if stream.get('sample_rate') else 0,
            "channels": stream.get('channels', 0),
            "channel_layout": stream.get('channel_layout', ''),
            "bit_rate": int(stream.get('bit_rate', 0)) if stream.get('bit_rate') else 0,
            "duration": float(stream.get('duration', 0)) if stream.get('duration') else 0,
            "tags": stream.get('tags', {})
        }
    
    def parse_subtitle_stream(self, stream: Dict[str, Any]) -> Dict[str, Any]:
        """Parse subtitle stream information"""
        return {
            "index": stream.get('index', 0),
            "codec_name": stream.get('codec_name', ''),
            "codec_long_name": stream.get('codec_long_name', ''),
            "language": stream.get('tags', {}).get('language', ''),
            "title": stream.get('tags', {}).get('title', ''),
            "tags": stream.get('tags', {})
        }
    
    async def analyze_video_technical(self, video_path: str) -> Dict[str, Any]:
        """Perform technical analysis of video file"""
        analysis = {
            "frame_analysis": {},
            "compression_analysis": {},
            "container_analysis": {}
        }
        
        try:
            # Analyze frame patterns
            analysis["frame_analysis"] = await self.analyze_frame_patterns(video_path)
            
            # Compression analysis
            analysis["compression_analysis"] = await self.analyze_video_compression(video_path)
            
        except Exception as e:
            analysis["error"] = str(e)
            
        return analysis
    
    async def analyze_frame_patterns(self, video_path: str) -> Dict[str, Any]:
        """Analyze video frame patterns for anomalies"""
        try:
            # Use ffprobe to get frame information (first 100 frames)
            cmd = [
                'ffprobe', '-v', 'quiet', '-select_streams', 'v:0',
                '-show_frames', '-read_intervals', '%+#100',
                '-print_format', 'json', video_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                frames = data.get('frames', [])
                
                if frames:
                    frame_sizes = [int(frame.get('pkt_size', 0)) for frame in frames]
                    
                    return {
                        "total_frames_analyzed": len(frames),
                        "avg_frame_size": sum(frame_sizes) / len(frame_sizes) if frame_sizes else 0,
                        "min_frame_size": min(frame_sizes) if frame_sizes else 0,
                        "max_frame_size": max(frame_sizes) if frame_sizes else 0,
                        "frame_size_variance": self.calculate_variance(frame_sizes)
                    }
            
            return {"error": "Could not analyze frames"}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def analyze_video_compression(self, video_path: str) -> Dict[str, Any]:
        """Analyze video compression characteristics"""
        try:
            # Get detailed codec information
            cmd = [
                'ffprobe', '-v', 'quiet', '-select_streams', 'v:0',
                '-show_streams', '-print_format', 'json', video_path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                streams = data.get('streams', [])
                
                if streams:
                    video_stream = streams[0]
                    
                    return {
                        "compression_level": self.estimate_compression_level(video_stream),
                        "profile": video_stream.get('profile', ''),
                        "level": video_stream.get('level', ''),
                        "encoder": video_stream.get('tags', {}).get('encoder', ''),
                        "compression_artifacts": self.detect_compression_artifacts(video_stream)
                    }
            
            return {"error": "Could not analyze compression"}
            
        except Exception as e:
            return {"error": str(e)}
    
    def estimate_compression_level(self, stream: Dict[str, Any]) -> str:
        """Estimate compression level based on bitrate and resolution"""
        try:
            bit_rate = int(stream.get('bit_rate', 0))
            width = stream.get('width', 0)
            height = stream.get('height', 0)
            
            if not (bit_rate and width and height):
                return "unknown"
            
            # Calculate bits per pixel
            pixels = width * height
            bpp = bit_rate / (pixels * 30)  # Assuming 30 fps
            
            if bpp > 0.5:
                return "low_compression"
            elif bpp > 0.1:
                return "medium_compression"
            else:
                return "high_compression"
                
        except:
            return "unknown"
    
    def detect_compression_artifacts(self, stream: Dict[str, Any]) -> List[str]:
        """Detect potential compression artifacts"""
        artifacts = []
        
        # Check for multiple encoding
        encoder = stream.get('tags', {}).get('encoder', '').lower()
        if 'x264' in encoder or 'x265' in encoder:
            artifacts.append("h264_h265_encoding")
        
        # Check for unusual profiles
        profile = stream.get('profile', '').lower()
        if 'baseline' in profile:
            artifacts.append("baseline_profile")
        elif 'high' in profile:
            artifacts.append("high_profile")
        
        return artifacts
    
    async def analyze_file_hashes(self, file_path: str) -> Dict[str, Any]:
        """Calculate and analyze file hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Calculate multiple hashes
            hashes['md5'] = hashlib.md5(file_content).hexdigest()
            hashes['sha1'] = hashlib.sha1(file_content).hexdigest()
            hashes['sha256'] = hashlib.sha256(file_content).hexdigest()
            
            # Analyze hash patterns
            hashes['hash_analysis'] = self.analyze_hash_patterns(hashes)
            
        except Exception as e:
            hashes['error'] = str(e)
            
        return hashes
    
    def analyze_hash_patterns(self, hashes: Dict[str, str]) -> Dict[str, Any]:
        """Analyze hash patterns for anomalies"""
        analysis = {
            "entropy_estimate": 0.0,
            "patterns_detected": []
        }
        
        try:
            # Simple entropy estimation from SHA256
            sha256 = hashes.get('sha256', '')
            if sha256:
                # Count unique characters
                unique_chars = len(set(sha256))
                analysis['entropy_estimate'] = unique_chars / 16.0  # Normalized
                
                # Check for patterns
                if len(set(sha256[::2])) < 8:  # Even positions
                    analysis['patterns_detected'].append("even_position_pattern")
                if len(set(sha256[1::2])) < 8:  # Odd positions
                    analysis['patterns_detected'].append("odd_position_pattern")
                    
        except Exception:
            pass
            
        return analysis
    
    def analyze_suspicious_patterns(self, metadata: Dict[str, Any]) -> List[str]:
        """Analyze metadata for suspicious patterns"""
        indicators = []
        
        try:
            # Check image metadata
            image_metadata = metadata.get("image_metadata", {})
            if image_metadata:
                exif_data = image_metadata.get("exif_data", {})
                
                # Suspicious EXIF tags
                suspicious_tags = ['UserComment', 'ImageDescription', 'Software', 'Copyright']
                for tag in suspicious_tags:
                    if tag in exif_data:
                        value = str(exif_data[tag])
                        if self.is_suspicious_text(value):
                            indicators.append(f"suspicious_{tag.lower()}")
                
                # Check for steganography tools in software tag
                software = exif_data.get('Software', '').lower()
                stego_tools = ['steghide', 'openstego', 'steganos', 'hide', 'secrethide']
                if any(tool in software for tool in stego_tools):
                    indicators.append("steganography_tool_detected")
            
            # Check audio metadata
            audio_metadata = metadata.get("audio_metadata", {})
            if audio_metadata:
                tags = audio_metadata.get("tags", {})
                
                # Suspicious audio tags
                for tag, value in tags.items():
                    if self.is_suspicious_text(str(value)):
                        indicators.append("suspicious_audio_tag")
                        break
            
            # Check video metadata
            video_metadata = metadata.get("video_metadata", {})
            if video_metadata:
                container_info = video_metadata.get("container_info", {})
                tags = container_info.get("tags", {})
                
                # Suspicious video tags
                for tag, value in tags.items():
                    if self.is_suspicious_text(str(value)):
                        indicators.append("suspicious_video_tag")
                        break
                
                # Check for unusual encoders
                for stream in video_metadata.get("video_streams", []):
                    encoder = stream.get("tags", {}).get("encoder", "").lower()
                    if any(tool in encoder for tool in stego_tools):
                        indicators.append("suspicious_video_encoder")
            
        except Exception as e:
            self.logger.error(f"Error analyzing suspicious patterns: {str(e)}")
        
        return indicators
    
    def is_suspicious_text(self, text: str) -> bool:
        """Check if text contains suspicious patterns"""
        if not text or len(text) < 10:
            return False
        
        # Check for base64-like patterns
        if self.looks_like_base64(text):
            return True
        
        # Check for unusual character patterns
        non_ascii_ratio = sum(1 for c in text if ord(c) > 127) / len(text)
        if non_ascii_ratio > 0.3:
            return True
        
        # Check for hex-like patterns
        if self.looks_like_hex(text):
            return True
        
        return False
    
    def looks_like_base64(self, text: str) -> bool:
        """Check if text looks like base64"""
        if len(text) < 20:
            return False
        
        # Base64 characters
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        text_chars = set(text)
        
        # At least 90% should be base64 characters
        valid_ratio = len(text_chars.intersection(base64_chars)) / len(text_chars)
        return valid_ratio > 0.9 and len(text) % 4 == 0
    
    def looks_like_hex(self, text: str) -> bool:
        """Check if text looks like hexadecimal"""
        if len(text) < 20:
            return False
        
        hex_chars = set('0123456789abcdefABCDEF')
        text_chars = set(text)
        
        valid_ratio = len(text_chars.intersection(hex_chars)) / len(text_chars)
        return valid_ratio > 0.9 and len(text) % 2 == 0
    
    def calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        if not values:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
