#!/usr/bin/env python3
"""
Quick test script to verify the steganography scanner setup
"""

import sys
import subprocess
import importlib.util
from pathlib import Path

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        if package_name:
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                return False, f"{package_name} not installed"
        else:
            importlib.import_module(module_name)
        return True, "OK"
    except ImportError as e:
        return False, str(e)

def test_command(command):
    """Test if a command exists"""
    try:
        result = subprocess.run([command, "--version"], 
                              capture_output=True, text=True, timeout=5)
        return True, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        return False, "Not found"

def main():
    print("🧪 Steganography Scanner - Setup Verification")
    print("=" * 50)
    
    # Test Python dependencies
    print("\n🐍 Python Dependencies:")
    python_deps = [
        ("fastapi", "FastAPI"),
        ("sqlalchemy", "SQLAlchemy"), 
        ("uvicorn", "Uvicorn"),
        ("pydantic", "Pydantic"),
        ("pillow", "Pillow (PIL)"),
        ("numpy", "NumPy"),
        ("requests", "Requests"),
    ]
    
    python_ok = 0
    for module, name in python_deps:
        success, msg = test_import(module, name)
        status = "✅" if success else "❌"
        print(f"  {status} {name}: {msg}")
        if success:
            python_ok += 1
    
    # Test external tools
    print("\n🔧 External Tools:")
    tools = [
        ("binwalk", "Binwalk"),
        ("foremost", "Foremost"), 
        ("exiftool", "ExifTool"),
    ]
    
    tools_ok = 0
    for command, name in tools:
        success, msg = test_command(command)
        status = "✅" if success else "⚠️"
        print(f"  {status} {name}: {msg}")
        if success:
            tools_ok += 1
    
    # Test project structure
    print("\n📁 Project Structure:")
    required_files = [
        "backend/main.py",
        "backend/requirements.txt",
        "frontend/package.json",
        "backend/config/settings.py",
        "backend/models/base.py",
    ]
    
    structure_ok = 0
    for file_path in required_files:
        exists = Path(file_path).exists()
        status = "✅" if exists else "❌"
        print(f"  {status} {file_path}")
        if exists:
            structure_ok += 1
    
    # Summary
    print("\n📊 Summary:")
    print(f"  Python Dependencies: {python_ok}/{len(python_deps)}")
    print(f"  External Tools: {tools_ok}/{len(tools)} (optional)")
    print(f"  Project Structure: {structure_ok}/{len(required_files)}")
    
    if python_ok == len(python_deps) and structure_ok == len(required_files):
        print("\n🎉 SUCCESS: Ready to run!")
        print("\n🚀 Next steps:")
        print("  1. cd backend && python main.py")
        print("  2. cd frontend && npm start")
        print("  3. Open http://localhost:3000")
    else:
        print("\n⚠️  Issues found - check missing dependencies above")
        if python_ok < len(python_deps):
            print("  💡 Run: pip install -r backend/requirements.txt")
        if structure_ok < len(required_files):
            print("  💡 Ensure you're in the correct project directory")
    
    if tools_ok == 0:
        print("\n💡 External tools are optional but enhance functionality")

if __name__ == "__main__":
    main()
