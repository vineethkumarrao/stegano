#!/usr/bin/env python3
"""
Test backend startup and basic functionality
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def test_imports():
    """Test if all imports work"""
    print("Testing imports...")
    
    try:
        from analysis.stego_detector import SteganographyDetector
        print("✅ SteganographyDetector imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import SteganographyDetector: {e}")
        return False
        
    try:
        from analysis.forensics_engine import ForensicsEngine
        print("✅ ForensicsEngine imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import ForensicsEngine: {e}")
        return False
        
    try:
        from analysis.ai_analyzer import AIAnalyzer
        print("✅ AIAnalyzer imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import AIAnalyzer: {e}")
        return False
        
    try:
        from analysis.entropy_analyzer import EntropyAnalyzer
        print("✅ EntropyAnalyzer imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import EntropyAnalyzer: {e}")
        return False
        
    try:
        from analysis.metadata_extractor import MetadataExtractor
        print("✅ MetadataExtractor imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import MetadataExtractor: {e}")
        return False
        
    try:
        from analysis.signature_detector import SignatureDetector
        print("✅ SignatureDetector imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import SignatureDetector: {e}")
        return False
        
    try:
        from utils.file_handler import FileHandler
        print("✅ FileHandler imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import FileHandler: {e}")
        return False
        
    print("✅ All imports successful!")
    return True

def test_basic_functionality():
    """Test basic functionality of analysis engines"""
    print("\nTesting basic functionality...")
    
    try:
        from analysis.stego_detector import SteganographyDetector
        detector = SteganographyDetector()
        print("✅ SteganographyDetector initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize SteganographyDetector: {e}")
        return False
        
    try:
        from analysis.entropy_analyzer import EntropyAnalyzer
        analyzer = EntropyAnalyzer()
        print("✅ EntropyAnalyzer initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize EntropyAnalyzer: {e}")
        return False
        
    print("✅ Basic functionality test passed!")
    return True

if __name__ == "__main__":
    print("🔍 Testing Backend Components...")
    
    imports_ok = test_imports()
    if not imports_ok:
        print("❌ Import tests failed")
        sys.exit(1)
        
    functionality_ok = test_basic_functionality()
    if not functionality_ok:
        print("❌ Functionality tests failed")
        sys.exit(1)
        
    print("\n✅ All backend tests passed! Backend should be ready.")
