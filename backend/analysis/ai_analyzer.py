# filepath: e:\stegano\backend\analysis\ai_analyzer.py
"""
AI-Powered Analysis Engine
Integrates with Gemini AI and other ML models for advanced analysis
"""

import asyncio
import logging
import base64
import io
import json
import os
from typing import Dict, Any, List, Optional
from pathlib import Path
import numpy as np
from PIL import Image
try:
    import google.generativeai as genai
except ImportError:
    genai = None
try:
    import openai
except ImportError:
    openai = None
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    IsolationForest = None
    StandardScaler = None
import cv2

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """AI-powered steganography analysis using machine learning and LLMs"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.gemini_model = None
        self.openai_client = None
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        
        # Initialize AI models
        self._initialize_ai_models()
    
    def _initialize_ai_models(self):
        """Initialize AI models with API keys"""
        try:
            # Initialize Gemini
            gemini_api_key = os.getenv('GEMINI_API_KEY')
            if gemini_api_key:
                genai.configure(api_key=gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-pro-vision')
                self.logger.info("Gemini AI model initialized")
            else:
                self.logger.warning("Gemini API key not found")
            
            # Initialize OpenAI
            openai_api_key = os.getenv('OPENAI_API_KEY')
            if openai_api_key:
                self.openai_client = openai.OpenAI(api_key=openai_api_key)
                self.logger.info("OpenAI client initialized")
            else:
                self.logger.warning("OpenAI API key not found")
                
        except Exception as e:
            self.logger.error(f"Error initializing AI models: {str(e)}")
    
    async def analyze_file(self, file_path: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Main AI analysis function"""
        ai_results = {
            "ai_enabled": True,
            "models_used": [],
            "anomaly_detection": {},
            "llm_analysis": {},
            "pattern_recognition": {},
            "suspicion_score": 0.0,
            "ai_recommendations": []
        }
        
        try:
            file_ext = Path(file_path).suffix.lower()
            
            # Machine Learning Anomaly Detection
            ai_results["anomaly_detection"] = await self.ml_anomaly_detection(file_path, analysis_results)
            
            # LLM Analysis (if available)
            if self.gemini_model or self.openai_client:
                ai_results["llm_analysis"] = await self.llm_analysis(file_path, analysis_results)
            
            # Pattern Recognition
            ai_results["pattern_recognition"] = await self.advanced_pattern_recognition(file_path)
            
            # Calculate AI suspicion score
            ai_results["suspicion_score"] = self.calculate_ai_suspicion_score(ai_results)
            
            # Generate recommendations
            ai_results["ai_recommendations"] = self.generate_recommendations(ai_results, analysis_results)
            
            return ai_results
            
        except Exception as e:
            self.logger.error(f"Error in AI analysis: {str(e)}")
            ai_results["error"] = str(e)
            return ai_results
    
    async def ml_anomaly_detection(self, file_path: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Machine learning-based anomaly detection"""
        try:
            results = {
                "features_extracted": {},
                "anomaly_scores": {},
                "outliers_detected": [],
                "feature_importance": {}
            }
            
            # Extract features for ML analysis
            features = await self.extract_ml_features(file_path, analysis_results)
            results["features_extracted"] = features
            
            if not features:
                return {"error": "No features extracted for ML analysis"}
            
            # Prepare feature vector
            feature_vector = self.prepare_feature_vector(features)
            
            if len(feature_vector) > 0:
                # Anomaly detection using Isolation Forest
                feature_array = np.array(feature_vector).reshape(1, -1)
                
                # Fit and predict (in production, you'd train on a dataset)
                anomaly_score = self.isolation_forest.fit_predict(feature_array)[0]
                decision_function = self.isolation_forest.decision_function(feature_array)[0]
                
                results["anomaly_scores"] = {
                    "isolation_forest_score": float(anomaly_score),
                    "decision_function": float(decision_function),
                    "is_anomaly": anomaly_score == -1
                }
                
                # Detect specific outliers
                results["outliers_detected"] = self.detect_feature_outliers(features)
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    async def extract_ml_features(self, file_path: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for machine learning analysis"""
        features = {}
        
        try:
            file_ext = Path(file_path).suffix.lower()
            
            # File-based features
            file_size = os.path.getsize(file_path)
            features["file_size"] = file_size
            features["file_size_log"] = np.log10(file_size + 1)
            
            # Extract features from previous analysis results
            if "entropy" in analysis_results:
                entropy_data = analysis_results["entropy"]
                if isinstance(entropy_data, dict):
                    features["entropy_mean"] = entropy_data.get("mean_entropy", 0)
                    features["entropy_variance"] = entropy_data.get("entropy_variance", 0)
            
            if "steganography" in analysis_results:
                stego_data = analysis_results["steganography"]
                if isinstance(stego_data, dict):
                    # LSB features
                    lsb_analysis = stego_data.get("lsb_analysis", {})
                    if isinstance(lsb_analysis, dict):
                        features["lsb_entropy"] = self.extract_nested_value(lsb_analysis, "overall.avg_lsb_entropy", 0)
                        features["lsb_uniformity"] = self.extract_nested_value(lsb_analysis, "overall.lsb_uniformity", 0.5)
                    
                    # Statistical features
                    features["confidence_score"] = stego_data.get("confidence_score", 0)
            
            # Forensics features
            if "forensics" in analysis_results:
                forensics_data = analysis_results["forensics"]
                if isinstance(forensics_data, dict):
                    features["embedded_file_count"] = forensics_data.get("embedded_file_count", 0)
                    features["suspicious_indicators_count"] = len(forensics_data.get("suspicious_indicators", []))
            
            # Image-specific features
            if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
                image_features = await self.extract_image_features(file_path)
                features.update(image_features)
            
            # Audio-specific features
            elif file_ext in ['.wav', '.mp3', '.flac', '.ogg']:
                audio_features = await self.extract_audio_features(file_path)
                features.update(audio_features)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting ML features: {str(e)}")
            return {}
    
    def extract_nested_value(self, data: Dict, path: str, default):
        """Extract nested dictionary value using dot notation"""
        try:
            keys = path.split('.')
            current = data
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default
    
    async def extract_image_features(self, image_path: str) -> Dict[str, Any]:
        """Extract image-specific features for ML"""
        features = {}
        
        try:
            # Load image
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Basic image properties
            features["image_width"] = img.width
            features["image_height"] = img.height
            features["image_channels"] = len(img_array.shape)
            features["image_area"] = img.width * img.height
            features["aspect_ratio"] = img.width / img.height
            
            # Color statistics
            if len(img_array.shape) == 3:
                for i, channel in enumerate(['red', 'green', 'blue']):
                    channel_data = img_array[:, :, i].flatten()
                    features[f"{channel}_mean"] = float(np.mean(channel_data))
                    features[f"{channel}_std"] = float(np.std(channel_data))
                    features[f"{channel}_skew"] = float(self.calculate_skewness(channel_data))
            else:
                # Grayscale
                features["gray_mean"] = float(np.mean(img_array))
                features["gray_std"] = float(np.std(img_array))
            
            # Texture features using OpenCV
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Edge density
            edges = cv2.Canny(gray, 50, 150)
            features["edge_density"] = float(np.sum(edges) / (gray.shape[0] * gray.shape[1]))
            
            # Local Binary Pattern energy
            features["texture_energy"] = float(np.var(gray))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting image features: {str(e)}")
            return {}
    
    async def extract_audio_features(self, audio_path: str) -> Dict[str, Any]:
        """Extract audio-specific features for ML"""
        features = {}
        
        try:
            import librosa
            
            # Load audio
            y, sr = librosa.load(audio_path, sr=None)
            
            # Basic audio properties
            features["audio_length"] = len(y)
            features["sample_rate"] = sr
            features["duration"] = len(y) / sr
            
            # Statistical features
            features["audio_mean"] = float(np.mean(y))
            features["audio_std"] = float(np.std(y))
            features["audio_rms"] = float(np.sqrt(np.mean(y**2)))
            
            # Spectral features
            stft = librosa.stft(y)
            magnitude = np.abs(stft)
            
            features["spectral_centroid"] = float(np.mean(librosa.feature.spectral_centroid(y=y, sr=sr)))
            features["spectral_bandwidth"] = float(np.mean(librosa.feature.spectral_bandwidth(y=y, sr=sr)))
            features["spectral_rolloff"] = float(np.mean(librosa.feature.spectral_rolloff(y=y, sr=sr)))
            
            # Zero crossing rate
            features["zero_crossing_rate"] = float(np.mean(librosa.feature.zero_crossing_rate(y)))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting audio features: {str(e)}")
            return {}
    
    def calculate_skewness(self, data: np.ndarray) -> float:
        """Calculate skewness of data"""
        try:
            from scipy import stats
            return float(stats.skew(data))
        except:
            # Fallback calculation
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0.0
            skew = np.mean(((data - mean) / std) ** 3)
            return float(skew)
    
    def prepare_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Prepare feature vector for ML algorithms"""
        try:
            feature_vector = []
            
            # Select numerical features
            numerical_features = [
                'file_size_log', 'entropy_mean', 'entropy_variance',
                'lsb_entropy', 'lsb_uniformity', 'confidence_score',
                'embedded_file_count', 'suspicious_indicators_count',
                'edge_density', 'texture_energy'
            ]
            
            for feature_name in numerical_features:
                if feature_name in features:
                    value = features[feature_name]
                    if isinstance(value, (int, float)) and not np.isnan(value):
                        feature_vector.append(float(value))
                    else:
                        feature_vector.append(0.0)
                else:
                    feature_vector.append(0.0)
            
            return feature_vector
            
        except Exception as e:
            self.logger.error(f"Error preparing feature vector: {str(e)}")
            return []
    
    def detect_feature_outliers(self, features: Dict[str, Any]) -> List[str]:
        """Detect outlier features that might indicate steganography"""
        outliers = []
        
        try:
            # Check for unusual file size
            if 'file_size' in features:
                size_mb = features['file_size'] / (1024 * 1024)
                if size_mb > 50:  # Large file
                    outliers.append("large_file_size")
            
            # Check for unusual entropy
            if 'entropy_mean' in features:
                if features['entropy_mean'] > 7.5:
                    outliers.append("high_entropy")
                elif features['entropy_mean'] < 1.0:
                    outliers.append("low_entropy")
            
            # Check for suspicious LSB patterns
            if 'lsb_uniformity' in features:
                uniformity = features['lsb_uniformity']
                if abs(uniformity - 0.5) > 0.2:
                    outliers.append("non_uniform_lsb")
            
            # Check for high confidence from other analyses
            if 'confidence_score' in features:
                if features['confidence_score'] > 0.8:
                    outliers.append("high_steganography_confidence")
            
            return outliers
            
        except Exception as e:
            return []
    
    async def llm_analysis(self, file_path: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Large Language Model analysis using Gemini or OpenAI"""
        llm_results = {
            "gemini_analysis": {},
            "openai_analysis": {},
            "combined_assessment": {}
        }
        
        try:
            # Prepare analysis summary for LLM
            analysis_summary = self.prepare_analysis_summary(analysis_results)
            
            # Gemini Analysis
            if self.gemini_model:
                llm_results["gemini_analysis"] = await self.gemini_analysis(file_path, analysis_summary)
            
            # OpenAI Analysis
            if self.openai_client:
                llm_results["openai_analysis"] = await self.openai_analysis(analysis_summary)
            
            # Combine assessments
            llm_results["combined_assessment"] = self.combine_llm_assessments(llm_results)
            
            return llm_results
            
        except Exception as e:
            return {"error": str(e)}
    
    def prepare_analysis_summary(self, analysis_results: Dict[str, Any]) -> str:
        """Prepare a summary of analysis results for LLM"""
        summary_parts = []
        
        # File information
        if "file_info" in analysis_results:
            file_info = analysis_results["file_info"]
            summary_parts.append(f"File type: {file_info.get('file_type', 'unknown')}")
            summary_parts.append(f"File size: {file_info.get('size_mb', 0):.2f} MB")
        
        # Steganography analysis
        if "steganography" in analysis_results:
            stego = analysis_results["steganography"]
            confidence = stego.get("confidence_score", 0)
            summary_parts.append(f"Steganography confidence: {confidence:.2f}")
            if stego.get("lsb_detected"):
                summary_parts.append("LSB steganography detected")
        
        # Forensics findings
        if "forensics" in analysis_results:
            forensics = analysis_results["forensics"]
            embedded_count = forensics.get("embedded_file_count", 0)
            if embedded_count > 0:
                summary_parts.append(f"Embedded files found: {embedded_count}")
            
            indicators = forensics.get("suspicious_indicators", [])
            if indicators:
                summary_parts.append(f"Suspicious indicators: {', '.join(indicators[:3])}")
        
        # Entropy analysis
        if "entropy" in analysis_results:
            entropy = analysis_results["entropy"]
            if isinstance(entropy, dict):
                avg_entropy = entropy.get("mean_entropy", 0)
                summary_parts.append(f"Average entropy: {avg_entropy:.2f}")
        
        return ". ".join(summary_parts)
    
    async def gemini_analysis(self, file_path: str, analysis_summary: str) -> Dict[str, Any]:
        """Analyze using Google Gemini"""
        try:
            file_ext = Path(file_path).suffix.lower()
            
            # Prepare prompt
            prompt = f"""
            Analyze this file for potential steganography based on the following technical analysis:
            
            {analysis_summary}
            
            Please provide:
            1. Assessment of steganography likelihood (0-1 scale)
            2. Key indicators that suggest hidden content
            3. Recommended next steps for investigation
            4. Confidence level in your assessment
            
            Focus on cybersecurity implications and potential threats.
            """
            
            # For images, include visual analysis
            if file_ext in ['.jpg', '.jpeg', '.png', '.bmp']:
                # Convert image to base64 for Gemini
                with open(file_path, 'rb') as f:
                    image_data = f.read()
                
                image = Image.open(io.BytesIO(image_data))
                
                response = await asyncio.get_event_loop().run_in_executor(
                    None, self._call_gemini_vision, prompt, image
                )
            else:
                response = await asyncio.get_event_loop().run_in_executor(
                    None, self._call_gemini_text, prompt
                )
            
            if response:
                return {
                    "raw_response": response,
                    "assessment": self.parse_gemini_response(response)
                }
            else:
                return {"error": "No response from Gemini"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def _call_gemini_vision(self, prompt: str, image: Image.Image) -> str:
        """Call Gemini Vision API (synchronous)"""
        try:
            response = self.gemini_model.generate_content([prompt, image])
            return response.text
        except Exception as e:
            self.logger.error(f"Gemini Vision API error: {str(e)}")
            return ""
    
    def _call_gemini_text(self, prompt: str) -> str:
        """Call Gemini Text API (synchronous)"""
        try:
            response = self.gemini_model.generate_content(prompt)
            return response.text
        except Exception as e:
            self.logger.error(f"Gemini Text API error: {str(e)}")
            return ""
    
    def parse_gemini_response(self, response: str) -> Dict[str, Any]:
        """Parse Gemini response for structured data"""
        assessment = {
            "likelihood_score": 0.0,
            "key_indicators": [],
            "recommendations": [],
            "confidence": 0.0
        }
        
        try:
            # Extract likelihood score (simple regex approach)
            import re
            
            likelihood_match = re.search(r'likelihood[:\s]+([0-9.]+)', response.lower())
            if likelihood_match:
                assessment["likelihood_score"] = float(likelihood_match.group(1))
            
            confidence_match = re.search(r'confidence[:\s]+([0-9.]+)', response.lower())
            if confidence_match:
                assessment["confidence"] = float(confidence_match.group(1))
            
            # Extract indicators and recommendations (simplified)
            lines = response.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                if 'indicator' in line.lower():
                    current_section = 'indicators'
                elif 'recommendation' in line.lower() or 'next step' in line.lower():
                    current_section = 'recommendations'
                elif line.startswith('-') or line.startswith('•'):
                    if current_section == 'indicators':
                        assessment["key_indicators"].append(line[1:].strip())
                    elif current_section == 'recommendations':
                        assessment["recommendations"].append(line[1:].strip())
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error parsing Gemini response: {str(e)}")
            return assessment
    
    async def openai_analysis(self, analysis_summary: str) -> Dict[str, Any]:
        """Analyze using OpenAI GPT"""
        try:
            prompt = f"""
            As a cybersecurity expert specializing in steganography detection, analyze the following technical findings:
            
            {analysis_summary}
            
            Provide a structured assessment in JSON format:
            {{
                "likelihood_score": <0-1 decimal>,
                "threat_level": "<low/medium/high>",
                "key_findings": ["finding1", "finding2"],
                "investigation_steps": ["step1", "step2"],
                "confidence": <0-1 decimal>
            }}
            """
            
            response = await asyncio.get_event_loop().run_in_executor(
                None, self._call_openai, prompt
            )
            
            if response:
                return {
                    "raw_response": response,
                    "assessment": self.parse_openai_response(response)
                }
            else:
                return {"error": "No response from OpenAI"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API (synchronous)"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in steganography detection."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content
        except Exception as e:
            self.logger.error(f"OpenAI API error: {str(e)}")
            return ""
    
    def parse_openai_response(self, response: str) -> Dict[str, Any]:
        """Parse OpenAI response"""
        try:
            # Try to parse as JSON first
            import json
            return json.loads(response)
        except:
            # Fallback to simple parsing
            return {"raw_analysis": response}
    
    def combine_llm_assessments(self, llm_results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine assessments from multiple LLMs"""
        combined = {
            "average_likelihood": 0.0,
            "consensus_indicators": [],
            "consensus_recommendations": [],
            "agreement_level": 0.0
        }
        
        try:
            likelihood_scores = []
            all_indicators = []
            all_recommendations = []
            
            # Extract from Gemini
            gemini_assessment = llm_results.get("gemini_analysis", {}).get("assessment", {})
            if gemini_assessment.get("likelihood_score"):
                likelihood_scores.append(gemini_assessment["likelihood_score"])
            all_indicators.extend(gemini_assessment.get("key_indicators", []))
            all_recommendations.extend(gemini_assessment.get("recommendations", []))
            
            # Extract from OpenAI
            openai_assessment = llm_results.get("openai_analysis", {}).get("assessment", {})
            if openai_assessment.get("likelihood_score"):
                likelihood_scores.append(openai_assessment["likelihood_score"])
            all_indicators.extend(openai_assessment.get("key_findings", []))
            all_recommendations.extend(openai_assessment.get("investigation_steps", []))
            
            # Calculate averages
            if likelihood_scores:
                combined["average_likelihood"] = sum(likelihood_scores) / len(likelihood_scores)
            
            # Find consensus (simplified)
            combined["consensus_indicators"] = list(set(all_indicators))[:5]
            combined["consensus_recommendations"] = list(set(all_recommendations))[:5]
            
            # Agreement level
            if len(likelihood_scores) > 1:
                score_variance = np.var(likelihood_scores)
                combined["agreement_level"] = max(0, 1 - score_variance)
            
            return combined
            
        except Exception as e:
            return {"error": str(e)}
    
    async def advanced_pattern_recognition(self, file_path: str) -> Dict[str, Any]:
        """Advanced pattern recognition using custom algorithms"""
        results = {
            "frequency_analysis": {},
            "compression_patterns": {},
            "byte_distribution": {},
            "suspicious_sequences": []
        }
        
        try:
            # Read file as bytes
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Frequency analysis
            results["frequency_analysis"] = self.analyze_byte_frequency(file_data)
            
            # Compression patterns
            results["compression_patterns"] = self.analyze_compression_patterns(file_data)
            
            # Byte distribution analysis
            results["byte_distribution"] = self.analyze_byte_distribution(file_data)
            
            # Look for suspicious sequences
            results["suspicious_sequences"] = self.find_suspicious_sequences(file_data)
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_byte_frequency(self, data: bytes) -> Dict[str, Any]:
        """Analyze byte frequency distribution"""
        try:
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            total_bytes = len(data)
            frequencies = [count / total_bytes for count in byte_counts]
            
            # Calculate entropy
            entropy = -sum(f * np.log2(f + 1e-10) for f in frequencies if f > 0)
            
            # Find most and least common bytes
            max_freq_byte = frequencies.index(max(frequencies))
            min_freq_byte = frequencies.index(min(frequencies))
            
            return {
                "entropy": float(entropy),
                "max_frequency": float(max(frequencies)),
                "min_frequency": float(min(frequencies)),
                "most_common_byte": hex(max_freq_byte),
                "least_common_byte": hex(min_freq_byte),
                "uniformity_score": 1.0 - np.std(frequencies)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_compression_patterns(self, data: bytes) -> Dict[str, Any]:
        """Analyze compression-related patterns"""
        try:
            # Simple compression analysis
            import zlib
            
            compressed = zlib.compress(data)
            compression_ratio = len(compressed) / len(data)
            
            # Look for repeated sequences
            repeated_sequences = 0
            for i in range(len(data) - 16):
                sequence = data[i:i+16]
                if data.count(sequence) > 1:
                    repeated_sequences += 1
            
            return {
                "compression_ratio": float(compression_ratio),
                "repeated_sequences": repeated_sequences,
                "high_entropy_regions": compression_ratio > 0.9,
                "suspicious_compression": compression_ratio < 0.1 or compression_ratio > 0.95
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_byte_distribution(self, data: bytes) -> Dict[str, Any]:
        """Analyze distribution of bytes"""
        try:
            # Calculate chi-square goodness of fit
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            expected = len(data) / 256
            chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
            
            # Kolmogorov-Smirnov test approximation
            from scipy import stats
            uniform_data = np.random.uniform(0, 255, len(data))
            ks_statistic, ks_p_value = stats.kstest(list(data), lambda x: x/255)
            
            return {
                "chi_square": float(chi_square),
                "ks_statistic": float(ks_statistic),
                "ks_p_value": float(ks_p_value),
                "distribution_uniformity": ks_p_value > 0.05
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def find_suspicious_sequences(self, data: bytes) -> List[Dict[str, Any]]:
        """Find suspicious byte sequences"""
        suspicious = []
        
        try:
            # Look for null byte sequences
            null_sequence_length = 0
            max_null_sequence = 0
            
            for byte in data:
                if byte == 0:
                    null_sequence_length += 1
                    max_null_sequence = max(max_null_sequence, null_sequence_length)
                else:
                    null_sequence_length = 0
            
            if max_null_sequence > 100:
                suspicious.append({
                    "type": "long_null_sequence",
                    "length": max_null_sequence,
                    "description": f"Long sequence of null bytes ({max_null_sequence})"
                })
            
            # Look for repeating patterns
            for pattern_length in [4, 8, 16]:
                for i in range(0, min(1000, len(data) - pattern_length)):
                    pattern = data[i:i+pattern_length]
                    count = data.count(pattern)
                    if count > 10:  # Pattern repeats more than 10 times
                        suspicious.append({
                            "type": "repeating_pattern",
                            "pattern": pattern.hex(),
                            "count": count,
                            "description": f"Pattern {pattern.hex()} repeats {count} times"
                        })
                        break
            
            # Look for high-entropy regions
            chunk_size = 1024
            for i in range(0, len(data) - chunk_size, chunk_size):
                chunk = data[i:i+chunk_size]
                chunk_entropy = self.calculate_chunk_entropy(chunk)
                if chunk_entropy > 7.5:  # High entropy
                    suspicious.append({
                        "type": "high_entropy_region",
                        "offset": i,
                        "entropy": chunk_entropy,
                        "description": f"High entropy region at offset {i}"
                    })
            
            return suspicious[:10]  # Limit to first 10
            
        except Exception as e:
            return []
    
    def calculate_chunk_entropy(self, chunk: bytes) -> float:
        """Calculate entropy of a byte chunk"""
        try:
            byte_counts = [0] * 256
            for byte in chunk:
                byte_counts[byte] += 1
            
            total = len(chunk)
            frequencies = [count / total for count in byte_counts if count > 0]
            
            entropy = -sum(f * np.log2(f) for f in frequencies)
            return float(entropy)
            
        except Exception:
            return 0.0
    
    def calculate_ai_suspicion_score(self, ai_results: Dict[str, Any]) -> float:
        """Calculate overall AI suspicion score"""
        score = 0.0
        
        try:
            # ML anomaly detection
            anomaly_detection = ai_results.get("anomaly_detection", {})
            if anomaly_detection.get("anomaly_scores", {}).get("is_anomaly"):
                score += 0.3
            
            outliers_count = len(anomaly_detection.get("outliers_detected", []))
            score += min(outliers_count * 0.1, 0.2)
            
            # LLM analysis
            llm_analysis = ai_results.get("llm_analysis", {})
            combined_assessment = llm_analysis.get("combined_assessment", {})
            avg_likelihood = combined_assessment.get("average_likelihood", 0)
            score += avg_likelihood * 0.4
            
            # Pattern recognition
            pattern_recognition = ai_results.get("pattern_recognition", {})
            suspicious_sequences = len(pattern_recognition.get("suspicious_sequences", []))
            score += min(suspicious_sequences * 0.05, 0.1)
            
            return min(score, 1.0)
            
        except Exception:
            return 0.0
    
    def generate_recommendations(self, ai_results: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[str]:
        """Generate AI-powered recommendations"""
        recommendations = []
        
        try:
            suspicion_score = ai_results.get("suspicion_score", 0)
            
            if suspicion_score > 0.7:
                recommendations.append("HIGH PRIORITY: Strong indicators of steganographic content detected")
                recommendations.append("Immediate manual investigation recommended")
                recommendations.append("Consider deep forensic analysis with specialized tools")
            elif suspicion_score > 0.4:
                recommendations.append("MEDIUM PRIORITY: Suspicious patterns detected")
                recommendations.append("Additional analysis with steganography-specific tools recommended")
                recommendations.append("Monitor for similar files from same source")
            elif suspicion_score > 0.2:
                recommendations.append("LOW PRIORITY: Some anomalies detected")
                recommendations.append("Consider batch analysis if multiple similar files")
            else:
                recommendations.append("No significant steganographic indicators detected")
                recommendations.append("File appears to be clean")
            
            # Specific recommendations based on findings
            if ai_results.get("anomaly_detection", {}).get("outliers_detected"):
                recommendations.append("Investigate flagged anomalies in detail")
            
            llm_recommendations = ai_results.get("llm_analysis", {}).get("combined_assessment", {}).get("consensus_recommendations", [])
            recommendations.extend(llm_recommendations[:3])
            
            return recommendations[:8]  # Limit to 8 recommendations
            
        except Exception:
            return ["Error generating recommendations"]
