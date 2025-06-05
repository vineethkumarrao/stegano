# filepath: e:\stegano\backend\analysis\stego_detector.py
"""
Advanced Steganography Detection Engine
Implements multiple algorithms for detecting steganographic content
"""

import numpy as np
import cv2
from PIL import Image, ImageStat
import asyncio
import logging
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import librosa
import wave
import struct
from scipy import stats
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import io
import base64

logger = logging.getLogger(__name__)

class SteganographyDetector:
    """Advanced steganography detection using multiple algorithms"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    async def detect_steganography(self, file_path: str) -> Dict[str, Any]:
        """Main detection function - routes to appropriate analyzer"""
        try:
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.gif']:
                return await self.analyze_image(file_path)
            elif file_ext in ['.wav', '.mp3', '.flac', '.ogg']:
                return await self.analyze_audio(file_path)
            elif file_ext in ['.mp4', '.avi', '.mkv', '.mov']:
                return await self.analyze_video(file_path)
            else:
                return {"error": f"Unsupported file type: {file_ext}"}
                
        except Exception as e:
            self.logger.error(f"Error in steganography detection: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """Comprehensive image steganography analysis"""
        results = {
            "file_type": "image",
            "lsb_analysis": {},
            "statistical_analysis": {},
            "visual_analysis": {},
            "chi_square_test": {},
            "histogram_analysis": {},
            "compression_analysis": {},
            "suspicious_patterns": [],
            "lsb_detected": False,
            "confidence_score": 0.0
        }
        
        try:
            # Load image
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # LSB Analysis
            results["lsb_analysis"] = await self.lsb_analysis(img_array)
            
            # Statistical Analysis
            results["statistical_analysis"] = await self.statistical_analysis(img_array)
            
            # Chi-Square Test
            results["chi_square_test"] = await self.chi_square_test(img_array)
            
            # Histogram Analysis
            results["histogram_analysis"] = await self.histogram_analysis(img_array)
            
            # Visual Attack Analysis
            results["visual_analysis"] = await self.visual_attack_analysis(img_array)
            
            # Compression Analysis (for JPEG)
            if image_path.lower().endswith(('.jpg', '.jpeg')):
                results["compression_analysis"] = await self.jpeg_compression_analysis(image_path)
            
            # Calculate overall confidence
            results["confidence_score"] = self.calculate_confidence_score(results)
            results["lsb_detected"] = results["confidence_score"] > 0.7
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing image: {str(e)}")
            results["error"] = str(e)
            return results
    
    async def lsb_analysis(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Least Significant Bit analysis"""
        try:
            if len(image_array.shape) == 3:
                # Color image - analyze each channel
                channels = ['red', 'green', 'blue']
                results = {}
                
                for i, channel in enumerate(channels):
                    channel_data = image_array[:, :, i]
                    results[channel] = self.analyze_lsb_channel(channel_data)
                
                # Overall LSB analysis
                results["overall"] = {
                    "avg_lsb_entropy": np.mean([results[ch]["lsb_entropy"] for ch in channels]),
                    "suspicious_patterns": sum([len(results[ch]["patterns"]) for ch in channels]),
                    "lsb_uniformity": np.mean([results[ch]["uniformity"] for ch in channels])
                }
                
            else:
                # Grayscale image
                results = {"grayscale": self.analyze_lsb_channel(image_array)}
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_lsb_channel(self, channel_data: np.ndarray) -> Dict[str, Any]:
        """Analyze LSB for a single channel"""
        # Extract LSBs
        lsb_plane = channel_data & 1
        
        # Calculate entropy of LSB plane
        unique, counts = np.unique(lsb_plane, return_counts=True)
        probabilities = counts / counts.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        
        # Check for patterns
        patterns = self.detect_lsb_patterns(lsb_plane)
        
        # Calculate uniformity (should be ~0.5 for random data)
        uniformity = np.mean(lsb_plane)
        
        # Chi-square test on LSBs
        expected = len(lsb_plane.flatten()) / 2
        observed = [np.sum(lsb_plane == 0), np.sum(lsb_plane == 1)]
        chi_stat = sum((obs - expected) ** 2 / expected for obs in observed)
        
        return {
            "lsb_entropy": entropy,
            "uniformity": uniformity,
            "patterns": patterns,
            "chi_square": chi_stat,
            "suspicious": entropy > 0.9 or abs(uniformity - 0.5) > 0.1
        }
    
    def detect_lsb_patterns(self, lsb_plane: np.ndarray) -> List[str]:
        """Detect suspicious patterns in LSB plane"""
        patterns = []
        flat_lsb = lsb_plane.flatten()
        
        # Check for repeated sequences
        for seq_len in [8, 16, 32]:
            for i in range(0, len(flat_lsb) - seq_len, seq_len):
                sequence = flat_lsb[i:i+seq_len]
                if np.all(sequence == sequence[0]):
                    patterns.append(f"repeated_{seq_len}_bit_sequence")
                    break
        
        # Check for alternating patterns
        alternating = all(flat_lsb[i] != flat_lsb[i+1] for i in range(min(100, len(flat_lsb)-1)))
        if alternating:
            patterns.append("alternating_pattern")
        
        return patterns
    
    async def statistical_analysis(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Statistical analysis for steganography detection"""
        try:
            results = {}
            
            if len(image_array.shape) == 3:
                # Color image
                for i, channel in enumerate(['red', 'green', 'blue']):
                    channel_data = image_array[:, :, i]
                    results[channel] = self.channel_statistics(channel_data)
            else:
                # Grayscale
                results["grayscale"] = self.channel_statistics(image_array)
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def channel_statistics(self, channel_data: np.ndarray) -> Dict[str, Any]:
        """Calculate statistical properties of a channel"""
        flat_data = channel_data.flatten()
        
        return {
            "mean": float(np.mean(flat_data)),
            "std": float(np.std(flat_data)),
            "skewness": float(stats.skew(flat_data)),
            "kurtosis": float(stats.kurtosis(flat_data)),
            "entropy": self.calculate_entropy(flat_data),
            "variance": float(np.var(flat_data))
        }
    
    def calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy"""
        unique, counts = np.unique(data, return_counts=True)
        probabilities = counts / counts.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return float(entropy)
    
    async def chi_square_test(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Chi-square test for randomness in LSB planes"""
        try:
            results = {}
            
            if len(image_array.shape) == 3:
                for i, channel in enumerate(['red', 'green', 'blue']):
                    channel_data = image_array[:, :, i]
                    lsb_plane = channel_data & 1
                    
                    # Perform chi-square test
                    observed_0 = np.sum(lsb_plane == 0)
                    observed_1 = np.sum(lsb_plane == 1)
                    expected = len(lsb_plane.flatten()) / 2
                    
                    chi_stat = ((observed_0 - expected) ** 2 + (observed_1 - expected) ** 2) / expected
                    p_value = 1 - stats.chi2.cdf(chi_stat, df=1)
                    
                    results[channel] = {
                        "chi_square": float(chi_stat),
                        "p_value": float(p_value),
                        "suspicious": p_value < 0.05
                    }
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    async def histogram_analysis(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Analyze histogram properties for steganography detection"""
        try:
            results = {}
            
            if len(image_array.shape) == 3:
                for i, channel in enumerate(['red', 'green', 'blue']):
                    channel_data = image_array[:, :, i]
                    results[channel] = self.analyze_histogram(channel_data)
            else:
                results["grayscale"] = self.analyze_histogram(image_array)
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_histogram(self, channel_data: np.ndarray) -> Dict[str, Any]:
        """Analyze histogram of a single channel"""
        hist, bins = np.histogram(channel_data.flatten(), bins=256, range=(0, 256))
        
        # Calculate histogram statistics
        hist_mean = float(np.mean(hist))
        hist_std = float(np.std(hist))
        hist_entropy = self.calculate_entropy(hist)
        
        # Check for suspicious patterns
        suspicious_patterns = []
        
        # Check for unusual spikes
        if np.max(hist) > hist_mean + 3 * hist_std:
            suspicious_patterns.append("unusual_spikes")
        
        # Check for flat regions
        flat_regions = np.sum(hist == 0)
        if flat_regions > 50:  # More than 50 empty bins
            suspicious_patterns.append("flat_regions")
        
        return {
            "mean": hist_mean,
            "std": hist_std,
            "entropy": hist_entropy,
            "max_value": int(np.max(hist)),
            "min_value": int(np.min(hist)),
            "suspicious_patterns": suspicious_patterns
        }
    
    async def visual_attack_analysis(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Visual attack analysis - examine LSB planes visually"""
        try:
            results = {"lsb_planes": {}}
            
            if len(image_array.shape) == 3:
                for i, channel in enumerate(['red', 'green', 'blue']):
                    channel_data = image_array[:, :, i]
                    lsb_plane = (channel_data & 1) * 255  # Amplify LSB
                    
                    # Calculate visual properties
                    results["lsb_planes"][channel] = {
                        "visible_patterns": self.detect_visual_patterns(lsb_plane),
                        "texture_complexity": float(np.std(lsb_plane)),
                        "edge_density": self.calculate_edge_density(lsb_plane)
                    }
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def detect_visual_patterns(self, lsb_plane: np.ndarray) -> List[str]:
        """Detect visual patterns in LSB plane"""
        patterns = []
        
        # Check for text-like patterns (high edge density in specific regions)
        edges = cv2.Canny(lsb_plane.astype(np.uint8), 50, 150)
        edge_density = np.sum(edges) / (edges.shape[0] * edges.shape[1])
        
        if edge_density > 0.1:
            patterns.append("text_like_pattern")
        
        # Check for geometric patterns
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if len(contours) > 10:
            patterns.append("geometric_patterns")
        
        return patterns
    
    def calculate_edge_density(self, image: np.ndarray) -> float:
        """Calculate edge density using Canny edge detector"""
        edges = cv2.Canny(image.astype(np.uint8), 50, 150)
        return float(np.sum(edges) / (edges.shape[0] * edges.shape[1]))
    
    async def jpeg_compression_analysis(self, image_path: str) -> Dict[str, Any]:
        """Analyze JPEG compression artifacts for steganography"""
        try:
            # This is a simplified analysis - full implementation would require DCT analysis
            img = Image.open(image_path)
            
            # Check EXIF data for quality information
            exif_data = img._getexif() if hasattr(img, '_getexif') and img._getexif() else {}
            
            # Basic compression analysis
            results = {
                "quality_estimate": "unknown",
                "compression_artifacts": [],
                "suspicious_regions": []
            }
            
            # Convert to array for analysis
            img_array = np.array(img)
            
            # Look for blocking artifacts (8x8 blocks)
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Simple block artifact detection
            block_variance = []
            for i in range(0, gray.shape[0] - 8, 8):
                for j in range(0, gray.shape[1] - 8, 8):
                    block = gray[i:i+8, j:j+8]
                    block_variance.append(np.var(block))
            
            avg_variance = np.mean(block_variance)
            results["avg_block_variance"] = float(avg_variance)
            
            # Low variance might indicate steganography
            if avg_variance < 100:
                results["compression_artifacts"].append("low_block_variance")
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    async def analyze_audio(self, audio_path: str) -> Dict[str, Any]:
        """Analyze audio files for steganography"""
        results = {
            "file_type": "audio",
            "lsb_analysis": {},
            "spectral_analysis": {},
            "echo_hiding_analysis": {},
            "suspicious_patterns": [],
            "confidence_score": 0.0
        }
        
        try:
            # Load audio file
            y, sr = librosa.load(audio_path, sr=None)
            
            # LSB Analysis for audio
            results["lsb_analysis"] = await self.audio_lsb_analysis(y, sr)
            
            # Spectral Analysis
            results["spectral_analysis"] = await self.audio_spectral_analysis(y, sr)
            
            # Echo Hiding Detection
            results["echo_hiding_analysis"] = await self.echo_hiding_analysis(y, sr)
            
            # Calculate confidence
            results["confidence_score"] = self.calculate_audio_confidence(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing audio: {str(e)}")
            results["error"] = str(e)
            return results
    
    async def audio_lsb_analysis(self, audio_data: np.ndarray, sample_rate: int) -> Dict[str, Any]:
        """LSB analysis for audio files"""
        try:
            # Convert to 16-bit integers for LSB analysis
            audio_16bit = (audio_data * 32767).astype(np.int16)
            
            # Extract LSBs
            lsb_data = audio_16bit & 1
            
            # Calculate entropy of LSB stream
            entropy = self.calculate_entropy(lsb_data)
            
            # Check for patterns
            patterns = []
            if entropy > 0.9:
                patterns.append("high_entropy_lsb")
            
            # Statistical tests
            mean_lsb = np.mean(lsb_data)
            if abs(mean_lsb - 0.5) > 0.1:
                patterns.append("non_uniform_lsb")
            
            return {
                "lsb_entropy": float(entropy),
                "lsb_mean": float(mean_lsb),
                "patterns": patterns,
                "suspicious": len(patterns) > 0
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def audio_spectral_analysis(self, audio_data: np.ndarray, sample_rate: int) -> Dict[str, Any]:
        """Spectral analysis for audio steganography"""
        try:
            # Compute spectrogram
            stft = librosa.stft(audio_data)
            magnitude = np.abs(stft)
            
            # Analyze high frequency content
            high_freq_energy = np.mean(magnitude[magnitude.shape[0]//2:, :])
            total_energy = np.mean(magnitude)
            high_freq_ratio = high_freq_energy / total_energy
            
            # Look for unusual spectral patterns
            patterns = []
            if high_freq_ratio > 0.3:
                patterns.append("high_frequency_content")
            
            # Analyze spectral entropy
            spectral_entropy = []
            for frame in magnitude.T:
                frame_entropy = self.calculate_entropy(frame)
                spectral_entropy.append(frame_entropy)
            
            avg_spectral_entropy = np.mean(spectral_entropy)
            
            return {
                "high_freq_ratio": float(high_freq_ratio),
                "avg_spectral_entropy": float(avg_spectral_entropy),
                "patterns": patterns,
                "suspicious": len(patterns) > 0
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def echo_hiding_analysis(self, audio_data: np.ndarray, sample_rate: int) -> Dict[str, Any]:
        """Analyze for echo hiding steganography"""
        try:
            # Simple echo detection using autocorrelation
            autocorr = np.correlate(audio_data, audio_data, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            
            # Look for peaks that might indicate echoes
            peaks = []
            threshold = np.max(autocorr) * 0.1
            
            for i in range(1, min(1000, len(autocorr))):  # Check first 1000 samples
                if autocorr[i] > threshold and autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1]:
                    peaks.append(i)
            
            # Analyze peak patterns
            patterns = []
            if len(peaks) > 5:
                patterns.append("multiple_echo_peaks")
            
            return {
                "echo_peaks": len(peaks),
                "patterns": patterns,
                "suspicious": len(patterns) > 0
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_audio_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate confidence score for audio analysis"""
        score = 0.0
        
        # LSB analysis
        if results.get("lsb_analysis", {}).get("suspicious"):
            score += 0.4
        
        # Spectral analysis
        if results.get("spectral_analysis", {}).get("suspicious"):
            score += 0.3
        
        # Echo hiding
        if results.get("echo_hiding_analysis", {}).get("suspicious"):
            score += 0.3
        
        return min(score, 1.0)
    
    async def analyze_video(self, video_path: str) -> Dict[str, Any]:
        """Analyze video files for steganography"""
        results = {
            "file_type": "video",
            "frame_analysis": {},
            "motion_vector_analysis": {},
            "suspicious_patterns": [],
            "confidence_score": 0.0
        }
        
        try:
            # Open video file
            cap = cv2.VideoCapture(video_path)
            
            if not cap.isOpened():
                return {"error": "Could not open video file"}
            
            # Analyze sample frames
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            sample_frames = min(10, frame_count)
            
            frame_results = []
            for i in range(0, frame_count, frame_count // sample_frames):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                ret, frame = cap.read()
                if ret:
                    # Analyze frame as image
                    frame_result = await self.analyze_image_array(frame)
                    frame_results.append(frame_result)
            
            cap.release()
            
            # Aggregate frame analysis
            results["frame_analysis"] = {
                "total_frames": frame_count,
                "analyzed_frames": len(frame_results),
                "avg_confidence": np.mean([r.get("confidence_score", 0) for r in frame_results]),
                "suspicious_frames": sum(1 for r in frame_results if r.get("confidence_score", 0) > 0.7)
            }
            
            results["confidence_score"] = results["frame_analysis"]["avg_confidence"]
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing video: {str(e)}")
            results["error"] = str(e)
            return results
    
    async def analyze_image_array(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Analyze image array (used for video frames)"""
        try:
            # Simplified image analysis for video frames
            lsb_analysis = await self.lsb_analysis(image_array)
            statistical_analysis = await self.statistical_analysis(image_array)
            
            confidence = 0.0
            if any(ch.get("suspicious", False) for ch in lsb_analysis.values() if isinstance(ch, dict)):
                confidence += 0.5
            
            return {
                "lsb_analysis": lsb_analysis,
                "statistical_analysis": statistical_analysis,
                "confidence_score": confidence
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_confidence_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall confidence score for image analysis"""
        score = 0.0
        
        # LSB analysis
        lsb_analysis = results.get("lsb_analysis", {})
        if isinstance(lsb_analysis, dict):
            for channel_name, channel_data in lsb_analysis.items():
                if isinstance(channel_data, dict) and channel_data.get("suspicious"):
                    score += 0.2
        
        # Chi-square test
        chi_square = results.get("chi_square_test", {})
        if isinstance(chi_square, dict):
            for channel_name, channel_data in chi_square.items():
                if isinstance(channel_data, dict) and channel_data.get("suspicious"):
                    score += 0.15
        
        # Visual analysis
        visual_analysis = results.get("visual_analysis", {})
        if isinstance(visual_analysis, dict):
            lsb_planes = visual_analysis.get("lsb_planes", {})
            for channel_name, channel_data in lsb_planes.items():
                if isinstance(channel_data, dict) and channel_data.get("visible_patterns"):
                    score += 0.1 * len(channel_data["visible_patterns"])
        
        # Histogram analysis
        histogram = results.get("histogram_analysis", {})
        if isinstance(histogram, dict):
            for channel_name, channel_data in histogram.items():
                if isinstance(channel_data, dict) and channel_data.get("suspicious_patterns"):
                    score += 0.05 * len(channel_data["suspicious_patterns"])
        
        return min(score, 1.0)
