# filepath: e:\stegano\backend\analysis\entropy_analyzer.py
"""
Entropy Analysis Module
Analyzes entropy patterns to detect steganographic content
"""

import numpy as np
import asyncio
import logging
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import io
import base64
from PIL import Image
import cv2

logger = logging.getLogger(__name__)

class EntropyAnalyzer:
    """Advanced entropy analysis for steganography detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.block_sizes = [8, 16, 32, 64, 128]  # Different block sizes for analysis
        
    async def analyze_entropy(self, file_path: str) -> Dict[str, Any]:
        """Main entropy analysis function"""
        try:
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.gif']:
                return await self.analyze_image_entropy(file_path)
            elif file_ext in ['.wav', '.mp3', '.flac', '.ogg']:
                return await self.analyze_audio_entropy(file_path)
            elif file_ext in ['.mp4', '.avi', '.mkv', '.mov']:
                return await self.analyze_video_entropy(file_path)
            else:
                return await self.analyze_binary_entropy(file_path)
                
        except Exception as e:
            self.logger.error(f"Error in entropy analysis: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_image_entropy(self, image_path: str) -> Dict[str, Any]:
        """Comprehensive entropy analysis for images"""
        results = {
            "file_type": "image",
            "overall_entropy": {},
            "block_entropy": {},
            "channel_entropy": {},
            "entropy_distribution": {},
            "anomalies": [],
            "entropy_map": None,
            "suspicious_regions": []
        }
        
        try:
            # Load image
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Overall entropy
            results["overall_entropy"] = self.calculate_overall_entropy(img_array)
            
            # Block-based entropy analysis
            results["block_entropy"] = await self.analyze_block_entropy(img_array)
            
            # Channel-wise entropy (for color images)
            if len(img_array.shape) == 3:
                results["channel_entropy"] = self.analyze_channel_entropy(img_array)
            
            # Entropy distribution analysis
            results["entropy_distribution"] = self.analyze_entropy_distribution(img_array)
            
            # Generate entropy map visualization
            results["entropy_map"] = await self.generate_entropy_map(img_array)
            
            # Detect anomalies
            results["anomalies"] = self.detect_entropy_anomalies(results)
            
            # Find suspicious regions
            results["suspicious_regions"] = await self.find_suspicious_regions(img_array)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing image entropy: {str(e)}")
            results["error"] = str(e)
            return results
    
    def calculate_overall_entropy(self, data: np.ndarray) -> Dict[str, Any]:
        """Calculate overall entropy of the data"""
        try:
            if len(data.shape) == 3:
                # For color images, calculate entropy for each channel and overall
                entropies = {}
                
                for i, channel in enumerate(['red', 'green', 'blue']):
                    channel_data = data[:, :, i].flatten()
                    entropies[channel] = self.shannon_entropy(channel_data)
                
                # Overall entropy (all channels combined)
                combined_data = data.flatten()
                entropies["combined"] = self.shannon_entropy(combined_data)
                
                # Calculate average and variance
                channel_entropies = [entropies['red'], entropies['green'], entropies['blue']]
                entropies["mean_entropy"] = float(np.mean(channel_entropies))
                entropies["entropy_variance"] = float(np.var(channel_entropies))
                
                return entropies
                
            else:
                # Grayscale image
                flat_data = data.flatten()
                entropy = self.shannon_entropy(flat_data)
                
                return {
                    "grayscale": entropy,
                    "mean_entropy": entropy,
                    "entropy_variance": 0.0
                }
                
        except Exception as e:
            return {"error": str(e)}
    
    def shannon_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy"""
        try:
            # Get unique values and their counts
            unique, counts = np.unique(data, return_counts=True)
            
            # Calculate probabilities
            probabilities = counts / counts.sum()
            
            # Calculate entropy
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            
            return float(entropy)
            
        except Exception as e:
            return 0.0
    
    async def analyze_block_entropy(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Analyze entropy in blocks of different sizes"""
        block_results = {}
        
        try:
            for block_size in self.block_sizes:
                if block_size > min(image_array.shape[:2]):
                    continue
                    
                block_entropies = []
                block_positions = []
                
                # Slide through the image
                for i in range(0, image_array.shape[0] - block_size + 1, block_size // 2):
                    for j in range(0, image_array.shape[1] - block_size + 1, block_size // 2):
                        # Extract block
                        if len(image_array.shape) == 3:
                            block = image_array[i:i+block_size, j:j+block_size, :]
                            block_entropy = self.shannon_entropy(block.flatten())
                        else:
                            block = image_array[i:i+block_size, j:j+block_size]
                            block_entropy = self.shannon_entropy(block.flatten())
                        
                        block_entropies.append(block_entropy)
                        block_positions.append((i, j))
                
                if block_entropies:
                    block_results[f"block_size_{block_size}"] = {
                        "mean_entropy": float(np.mean(block_entropies)),
                        "std_entropy": float(np.std(block_entropies)),
                        "min_entropy": float(np.min(block_entropies)),
                        "max_entropy": float(np.max(block_entropies)),
                        "entropy_range": float(np.max(block_entropies) - np.min(block_entropies)),
                        "total_blocks": len(block_entropies),
                        "high_entropy_blocks": sum(1 for e in block_entropies if e > 7.0),
                        "low_entropy_blocks": sum(1 for e in block_entropies if e < 2.0)
                    }
            
            return block_results
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_channel_entropy(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Analyze entropy for each color channel"""
        try:
            channel_results = {}
            
            if len(image_array.shape) != 3:
                return {"error": "Not a color image"}
            
            channels = ['red', 'green', 'blue']
            
            for i, channel_name in enumerate(channels):
                channel_data = image_array[:, :, i]
                
                # Overall channel entropy
                channel_entropy = self.shannon_entropy(channel_data.flatten())
                
                # Local entropy (block-based for this channel)
                local_entropies = []
                block_size = 32
                
                for row in range(0, channel_data.shape[0] - block_size + 1, block_size):
                    for col in range(0, channel_data.shape[1] - block_size + 1, block_size):
                        block = channel_data[row:row+block_size, col:col+block_size]
                        local_entropy = self.shannon_entropy(block.flatten())
                        local_entropies.append(local_entropy)
                
                channel_results[channel_name] = {
                    "overall_entropy": float(channel_entropy),
                    "local_entropy_mean": float(np.mean(local_entropies)) if local_entropies else 0.0,
                    "local_entropy_std": float(np.std(local_entropies)) if local_entropies else 0.0,
                    "entropy_variation": float(np.std(local_entropies)) if local_entropies else 0.0
                }
            
            # Inter-channel analysis
            channel_entropies = [channel_results[ch]["overall_entropy"] for ch in channels]
            channel_results["inter_channel"] = {
                "entropy_correlation": self.calculate_channel_correlation(image_array),
                "entropy_balance": float(np.std(channel_entropies)),
                "dominant_channel": channels[np.argmax(channel_entropies)]
            }
            
            return channel_results
            
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_channel_correlation(self, image_array: np.ndarray) -> Dict[str, float]:
        """Calculate correlation between color channels"""
        try:
            if len(image_array.shape) != 3:
                return {}
            
            red = image_array[:, :, 0].flatten()
            green = image_array[:, :, 1].flatten()
            blue = image_array[:, :, 2].flatten()
            
            correlations = {
                "red_green": float(np.corrcoef(red, green)[0, 1]),
                "red_blue": float(np.corrcoef(red, blue)[0, 1]),
                "green_blue": float(np.corrcoef(green, blue)[0, 1])
            }
            
            return correlations
            
        except Exception as e:
            return {}
    
    def analyze_entropy_distribution(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Analyze the distribution of entropy values"""
        try:
            # Calculate local entropy for small blocks
            block_size = 16
            local_entropies = []
            
            for i in range(0, image_array.shape[0] - block_size + 1, block_size // 2):
                for j in range(0, image_array.shape[1] - block_size + 1, block_size // 2):
                    if len(image_array.shape) == 3:
                        block = image_array[i:i+block_size, j:j+block_size, :]
                    else:
                        block = image_array[i:i+block_size, j:j+block_size]
                    
                    local_entropy = self.shannon_entropy(block.flatten())
                    local_entropies.append(local_entropy)
            
            if not local_entropies:
                return {"error": "No entropy values calculated"}
            
            # Statistical analysis of entropy distribution
            entropy_array = np.array(local_entropies)
            
            # Calculate percentiles
            percentiles = [10, 25, 50, 75, 90, 95, 99]
            entropy_percentiles = {}
            for p in percentiles:
                entropy_percentiles[f"p{p}"] = float(np.percentile(entropy_array, p))
            
            # Distribution characteristics
            distribution_stats = {
                "mean": float(np.mean(entropy_array)),
                "median": float(np.median(entropy_array)),
                "std": float(np.std(entropy_array)),
                "skewness": float(self.calculate_skewness(entropy_array)),
                "kurtosis": float(self.calculate_kurtosis(entropy_array)),
                "range": float(np.max(entropy_array) - np.min(entropy_array))
            }
            
            # Identify unusual patterns
            unusual_patterns = []
            
            # Check for bimodal distribution
            if self.is_bimodal(entropy_array):
                unusual_patterns.append("bimodal_distribution")
            
            # Check for unusual spread
            if distribution_stats["std"] > 2.0:
                unusual_patterns.append("high_entropy_variance")
            elif distribution_stats["std"] < 0.5:
                unusual_patterns.append("low_entropy_variance")
            
            # Check for extreme skewness
            if abs(distribution_stats["skewness"]) > 1.5:
                unusual_patterns.append("highly_skewed_distribution")
            
            return {
                "total_blocks": len(local_entropies),
                "distribution_stats": distribution_stats,
                "percentiles": entropy_percentiles,
                "unusual_patterns": unusual_patterns,
                "entropy_histogram": self.create_entropy_histogram(entropy_array)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_skewness(self, data: np.ndarray) -> float:
        """Calculate skewness of data"""
        try:
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0.0
            skew = np.mean(((data - mean) / std) ** 3)
            return float(skew)
        except:
            return 0.0
    
    def calculate_kurtosis(self, data: np.ndarray) -> float:
        """Calculate kurtosis of data"""
        try:
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0.0
            kurt = np.mean(((data - mean) / std) ** 4) - 3
            return float(kurt)
        except:
            return 0.0
    
    def is_bimodal(self, data: np.ndarray) -> bool:
        """Check if distribution is bimodal"""
        try:
            hist, _ = np.histogram(data, bins=20)
            
            # Find peaks
            peaks = []
            for i in range(1, len(hist) - 1):
                if hist[i] > hist[i-1] and hist[i] > hist[i+1]:
                    peaks.append(i)
            
            # Consider bimodal if there are 2 significant peaks
            if len(peaks) >= 2:
                # Check if peaks are significant
                max_hist = np.max(hist)
                significant_peaks = [p for p in peaks if hist[p] > max_hist * 0.3]
                return len(significant_peaks) >= 2
            
            return False
            
        except:
            return False
    
    def create_entropy_histogram(self, entropy_array: np.ndarray) -> Dict[str, Any]:
        """Create entropy histogram data"""
        try:
            hist, bin_edges = np.histogram(entropy_array, bins=20)
            
            return {
                "bin_counts": hist.tolist(),
                "bin_edges": bin_edges.tolist(),
                "total_bins": len(hist),
                "most_common_range": int(np.argmax(hist))
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def generate_entropy_map(self, image_array: np.ndarray) -> Optional[str]:
        """Generate visual entropy map"""
        try:
            block_size = 16
            
            # Calculate entropy for each block
            entropy_map = np.zeros((
                (image_array.shape[0] // block_size) + 1,
                (image_array.shape[1] // block_size) + 1
            ))
            
            for i in range(0, image_array.shape[0], block_size):
                for j in range(0, image_array.shape[1], block_size):
                    # Extract block
                    end_i = min(i + block_size, image_array.shape[0])
                    end_j = min(j + block_size, image_array.shape[1])
                    
                    if len(image_array.shape) == 3:
                        block = image_array[i:end_i, j:end_j, :]
                    else:
                        block = image_array[i:end_i, j:end_j]
                    
                    # Calculate entropy
                    block_entropy = self.shannon_entropy(block.flatten())
                    entropy_map[i // block_size, j // block_size] = block_entropy
            
            # Create visualization
            plt.figure(figsize=(10, 8))
            plt.imshow(entropy_map, cmap='hot', interpolation='nearest')
            plt.colorbar(label='Entropy')
            plt.title('Entropy Map')
            plt.xlabel('Block X')
            plt.ylabel('Block Y')
            
            # Save to base64 string
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
            buffer.seek(0)
            
            # Convert to base64
            entropy_map_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            plt.close()
            buffer.close()
            
            return entropy_map_b64
            
        except Exception as e:
            self.logger.error(f"Error generating entropy map: {str(e)}")
            return None
    
    async def find_suspicious_regions(self, image_array: np.ndarray) -> List[Dict[str, Any]]:
        """Find regions with suspicious entropy patterns"""
        suspicious_regions = []
        
        try:
            block_size = 32
            threshold_high = 7.5  # High entropy threshold
            threshold_low = 1.5   # Low entropy threshold
            
            for i in range(0, image_array.shape[0] - block_size + 1, block_size // 2):
                for j in range(0, image_array.shape[1] - block_size + 1, block_size // 2):
                    # Extract block
                    if len(image_array.shape) == 3:
                        block = image_array[i:i+block_size, j:j+block_size, :]
                    else:
                        block = image_array[i:i+block_size, j:j+block_size]
                    
                    block_entropy = self.shannon_entropy(block.flatten())
                    
                    # Check for suspicious entropy
                    if block_entropy > threshold_high:
                        suspicious_regions.append({
                            "type": "high_entropy",
                            "position": (i, j),
                            "size": block_size,
                            "entropy": float(block_entropy),
                            "description": f"High entropy region ({block_entropy:.2f})"
                        })
                    elif block_entropy < threshold_low:
                        suspicious_regions.append({
                            "type": "low_entropy",
                            "position": (i, j),
                            "size": block_size,
                            "entropy": float(block_entropy),
                            "description": f"Low entropy region ({block_entropy:.2f})"
                        })
            
            # Limit results
            return suspicious_regions[:20]
            
        except Exception as e:
            return []
    
    def detect_entropy_anomalies(self, results: Dict[str, Any]) -> List[str]:
        """Detect entropy-based anomalies that might indicate steganography"""
        anomalies = []
        
        try:
            # Check overall entropy
            overall_entropy = results.get("overall_entropy", {})
            mean_entropy = overall_entropy.get("mean_entropy", 0)
            
            if mean_entropy > 7.5:
                anomalies.append("high_overall_entropy")
            elif mean_entropy < 2.0:
                anomalies.append("low_overall_entropy")
            
            # Check entropy variance between channels
            entropy_variance = overall_entropy.get("entropy_variance", 0)
            if entropy_variance > 1.0:
                anomalies.append("high_channel_entropy_variance")
            
            # Check block entropy patterns
            block_entropy = results.get("block_entropy", {})
            for block_size, stats in block_entropy.items():
                if isinstance(stats, dict):
                    entropy_range = stats.get("entropy_range", 0)
                    high_entropy_blocks = stats.get("high_entropy_blocks", 0)
                    total_blocks = stats.get("total_blocks", 1)
                    
                    if entropy_range > 6.0:
                        anomalies.append(f"high_entropy_range_{block_size}")
                    
                    if high_entropy_blocks / total_blocks > 0.2:
                        anomalies.append(f"many_high_entropy_blocks_{block_size}")
            
            # Check entropy distribution
            entropy_distribution = results.get("entropy_distribution", {})
            unusual_patterns = entropy_distribution.get("unusual_patterns", [])
            anomalies.extend(unusual_patterns)
            
            # Check suspicious regions
            suspicious_regions = results.get("suspicious_regions", [])
            if len(suspicious_regions) > 10:
                anomalies.append("many_suspicious_entropy_regions")
            
            return anomalies
            
        except Exception as e:
            return []
    
    async def analyze_audio_entropy(self, audio_path: str) -> Dict[str, Any]:
        """Analyze entropy in audio files"""
        results = {
            "file_type": "audio",
            "overall_entropy": {},
            "temporal_entropy": {},
            "spectral_entropy": {},
            "anomalies": []
        }
        
        try:
            import librosa
            
            # Load audio
            y, sr = librosa.load(audio_path, sr=None)
            
            # Overall entropy
            results["overall_entropy"] = {
                "temporal_entropy": self.shannon_entropy((y * 32767).astype(np.int16)),
                "amplitude_entropy": self.shannon_entropy(np.abs(y) * 255)
            }
            
            # Temporal entropy analysis (frame-based)
            frame_length = 2048
            hop_length = 512
            frame_entropies = []
            
            for i in range(0, len(y) - frame_length + 1, hop_length):
                frame = y[i:i+frame_length]
                frame_entropy = self.shannon_entropy((frame * 32767).astype(np.int16))
                frame_entropies.append(frame_entropy)
            
            if frame_entropies:
                results["temporal_entropy"] = {
                    "mean_entropy": float(np.mean(frame_entropies)),
                    "std_entropy": float(np.std(frame_entropies)),
                    "max_entropy": float(np.max(frame_entropies)),
                    "min_entropy": float(np.min(frame_entropies))
                }
            
            # Spectral entropy
            stft = librosa.stft(y)
            magnitude = np.abs(stft)
            
            spectral_entropies = []
            for frame in magnitude.T:
                spectral_entropy = self.shannon_entropy(frame)
                spectral_entropies.append(spectral_entropy)
            
            if spectral_entropies:
                results["spectral_entropy"] = {
                    "mean_entropy": float(np.mean(spectral_entropies)),
                    "std_entropy": float(np.std(spectral_entropies)),
                    "max_entropy": float(np.max(spectral_entropies)),
                    "min_entropy": float(np.min(spectral_entropies))
                }
            
            # Detect anomalies
            results["anomalies"] = self.detect_audio_entropy_anomalies(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing audio entropy: {str(e)}")
            results["error"] = str(e)
            return results
    
    def detect_audio_entropy_anomalies(self, results: Dict[str, Any]) -> List[str]:
        """Detect entropy anomalies in audio"""
        anomalies = []
        
        try:
            # Check overall entropy
            overall_entropy = results.get("overall_entropy", {})
            temporal_entropy = overall_entropy.get("temporal_entropy", 0)
            
            if temporal_entropy > 15.0:  # High for 16-bit audio
                anomalies.append("high_temporal_entropy")
            
            # Check temporal entropy variation
            temporal_stats = results.get("temporal_entropy", {})
            if temporal_stats.get("std_entropy", 0) > 2.0:
                anomalies.append("high_temporal_entropy_variation")
            
            # Check spectral entropy
            spectral_stats = results.get("spectral_entropy", {})
            if spectral_stats.get("mean_entropy", 0) > 10.0:
                anomalies.append("high_spectral_entropy")
            
            return anomalies
            
        except Exception:
            return []
    
    async def analyze_video_entropy(self, video_path: str) -> Dict[str, Any]:
        """Analyze entropy in video files"""
        results = {
            "file_type": "video",
            "frame_entropy": {},
            "temporal_entropy": {},
            "anomalies": []
        }
        
        try:
            # Open video
            cap = cv2.VideoCapture(video_path)
            
            if not cap.isOpened():
                return {"error": "Could not open video file"}
            
            frame_entropies = []
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            sample_frames = min(50, frame_count)  # Sample up to 50 frames
            
            for i in range(0, frame_count, max(1, frame_count // sample_frames)):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                ret, frame = cap.read()
                
                if ret:
                    frame_entropy = self.shannon_entropy(frame.flatten())
                    frame_entropies.append(frame_entropy)
            
            cap.release()
            
            if frame_entropies:
                results["frame_entropy"] = {
                    "mean_entropy": float(np.mean(frame_entropies)),
                    "std_entropy": float(np.std(frame_entropies)),
                    "max_entropy": float(np.max(frame_entropies)),
                    "min_entropy": float(np.min(frame_entropies)),
                    "analyzed_frames": len(frame_entropies)
                }
                
                # Temporal entropy changes
                if len(frame_entropies) > 1:
                    entropy_changes = np.diff(frame_entropies)
                    results["temporal_entropy"] = {
                        "mean_change": float(np.mean(entropy_changes)),
                        "std_change": float(np.std(entropy_changes)),
                        "max_change": float(np.max(entropy_changes)),
                        "abrupt_changes": sum(1 for change in entropy_changes if abs(change) > 1.0)
                    }
            
            # Detect anomalies
            results["anomalies"] = self.detect_video_entropy_anomalies(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing video entropy: {str(e)}")
            results["error"] = str(e)
            return results
    
    def detect_video_entropy_anomalies(self, results: Dict[str, Any]) -> List[str]:
        """Detect entropy anomalies in video"""
        anomalies = []
        
        try:
            # Check frame entropy
            frame_entropy = results.get("frame_entropy", {})
            mean_entropy = frame_entropy.get("mean_entropy", 0)
            
            if mean_entropy > 20.0:
                anomalies.append("high_frame_entropy")
            
            # Check temporal changes
            temporal_entropy = results.get("temporal_entropy", {})
            abrupt_changes = temporal_entropy.get("abrupt_changes", 0)
            analyzed_frames = frame_entropy.get("analyzed_frames", 1)
            
            if abrupt_changes / analyzed_frames > 0.3:
                anomalies.append("many_abrupt_entropy_changes")
            
            return anomalies
            
        except Exception:
            return []
    
    async def analyze_binary_entropy(self, file_path: str) -> Dict[str, Any]:
        """Analyze entropy for binary files"""
        results = {
            "file_type": "binary",
            "overall_entropy": {},
            "block_entropy": {},
            "byte_distribution": {},
            "anomalies": []
        }
        
        try:
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Overall entropy
            results["overall_entropy"] = {
                "entropy": self.shannon_entropy(np.frombuffer(data, dtype=np.uint8)),
                "file_size": len(data)
            }
            
            # Block-based entropy
            block_size = 1024
            block_entropies = []
            
            for i in range(0, len(data), block_size):
                block = data[i:i+block_size]
                if len(block) >= 64:  # Minimum block size
                    block_entropy = self.shannon_entropy(np.frombuffer(block, dtype=np.uint8))
                    block_entropies.append(block_entropy)
            
            if block_entropies:
                results["block_entropy"] = {
                    "mean_entropy": float(np.mean(block_entropies)),
                    "std_entropy": float(np.std(block_entropies)),
                    "max_entropy": float(np.max(block_entropies)),
                    "min_entropy": float(np.min(block_entropies)),
                    "total_blocks": len(block_entropies)
                }
            
            # Byte distribution
            byte_array = np.frombuffer(data, dtype=np.uint8)
            unique, counts = np.unique(byte_array, return_counts=True)
            
            results["byte_distribution"] = {
                "unique_bytes": len(unique),
                "most_common_byte": int(unique[np.argmax(counts)]),
                "most_common_count": int(np.max(counts)),
                "distribution_entropy": self.shannon_entropy(counts)
            }
            
            # Detect anomalies
            results["anomalies"] = self.detect_binary_entropy_anomalies(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing binary entropy: {str(e)}")
            results["error"] = str(e)
            return results
    
    def detect_binary_entropy_anomalies(self, results: Dict[str, Any]) -> List[str]:
        """Detect entropy anomalies in binary files"""
        anomalies = []
        
        try:
            # Check overall entropy
            overall_entropy = results.get("overall_entropy", {}).get("entropy", 0)
            
            if overall_entropy > 7.8:
                anomalies.append("very_high_entropy")
            elif overall_entropy < 1.0:
                anomalies.append("very_low_entropy")
            
            # Check block entropy variation
            block_entropy = results.get("block_entropy", {})
            std_entropy = block_entropy.get("std_entropy", 0)
            
            if std_entropy > 2.0:
                anomalies.append("high_entropy_variation")
            
            # Check byte distribution
            byte_dist = results.get("byte_distribution", {})
            unique_bytes = byte_dist.get("unique_bytes", 0)
            
            if unique_bytes < 10:
                anomalies.append("limited_byte_diversity")
            elif unique_bytes == 256:
                anomalies.append("full_byte_spectrum")
            
            return anomalies
            
        except Exception:
            return []
    
    def entropy_signature_detection(self, entropy_values):
        """Detect suspicious entropy signatures (fixes float.bit_length bug)"""
        import math
        try:
            # Example: check for high entropy spikes using log2 instead of bit_length
            spikes = []
            for val in entropy_values:
                # Use math.log2 for float, not bit_length
                if isinstance(val, float) and val > 0:
                    log_val = math.log2(val)
                    if log_val > 2.5:  # Arbitrary threshold for spike
                        spikes.append(val)
            return {
                "spike_count": len(spikes),
                "spikes": spikes
            }
        except Exception as e:
            return {"error": str(e)}
