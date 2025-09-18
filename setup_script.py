#!/usr/bin/env python3
"""
Setup script for Phishing URL Detection System
This script sets up everything you need to run the complete solution.
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def print_banner():
    print("🛡️" + "="*60)
    print("  PHISHING URL DETECTION SYSTEM - SETUP")
    print("="*62)
    print("This script will set up your complete phishing detection system")
    print("="*62 + "\n")

def check_python_version():
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 7):
        print("❌ ERROR: Python 3.7 or higher is required")
        print(f"   Your version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} is compatible\n")

def install_requirements():
    print("📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All dependencies installed successfully\n")
    except subprocess.CalledProcessError:
        print("❌ ERROR: Failed to install dependencies")
        print("   Please run: pip install -r requirements.txt")
        return False
    return True

def create_extension_folder():
    print("📁 Creating Chrome extension folder...")
    
    extension_dir = Path("extension")
    extension_dir.mkdir(exist_ok=True)
    
    icons_dir = extension_dir / "icons"
    icons_dir.mkdir(exist_ok=True)
    
    # Create manifest.json
    manifest = {
        "manifest_version": 3,
        "name": "Phishing URL Detector",
        "version": "1.0.0",
        "description": "Real-time phishing URL detection using machine learning",
        
        "permissions": [
            "activeTab",
            "storage", 
            "tabs",
            "webNavigation",
            "declarativeNetRequest"
        ],
        
        "host_permissions": [
            "http://*/*",
            "https://*/*"
        ],
        
        "background": {
            "service_worker": "background.js"
        },
        
        "content_scripts": [
            {
                "matches": ["<all_urls>"],
                "js": ["content.js"],
                "run_at": "document_start"
            }
        ],
        
        "action": {
            "default_popup": "popup.html",
            "default_title": "Phishing URL Detector",
            "default_icon": {
                "16": "icons/icon16.png",
                "48": "icons/icon48.png", 
                "128": "icons/icon128.png"
            }
        },
        
        "icons": {
            "16": "icons/icon16.png",
            "48": "icons/icon48.png",
            "128": "icons/icon128.png"
        },
        
        "web_accessible_resources": [
            {
                "resources": ["warning.html"],
                "matches": ["<all_urls>"]
            }
        ]
    }
    
    with open(extension_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    
    print("✅ Extension folder structure created")
    print("   📁 extension/")
    print("   ├── manifest.json ✅")
    print("   └── icons/ ✅")
    print("   ⚠️  You still need to add the JS/HTML files from the artifacts\n")

def create_project_structure():
    print("🏗️  Creating project structure...")
    
    folders = ["data", "models", "logs"]
    for folder in folders:
        Path(folder).mkdir(exist_ok=True)
    
    print("✅ Project folders created:")
    print("   📁 data/ - for datasets")
    print("   📁 models/ - for trained models") 
    print("   📁 logs/ - for log files\n")

def run_quick_test():
    print("🧪 Running quick system test...")
    
    try:
        # Test imports
        import pandas as pd
        import numpy as np
        import sklearn
        from flask import Flask
        print("✅ All core libraries can be imported")
        
        # Test basic functionality
        from urllib.parse import urlparse
        test_url = "https://www.google.com"
        parsed = urlparse(test_url)
        print("✅ URL parsing works")
        
        print("✅ System test passed!\n")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def display_next_steps():
    print("🚀 SETUP COMPLETE! Next steps:")
    print("="*50)
    print("1. 📊 Train your model:")
    print("   python complete_phishing_solution.py")
    print()
    print("2. 🚀 Start the API server:")
    print("   python app.py")
    print()
    print("3. 🔧 Complete the Chrome extension:")
    print("   - Copy JS/HTML files from the artifacts to extension/ folder")
    print("   - Add icon files (16x16, 48x48, 128x128 PNG)")
    print("   - Load extension in Chrome developer mode")
    print()
    print("4. 🧪 Test everything:")
    print("   - Visit http://127.0.0.1:5000/test to test the API")
    print("   - Try the extension on various websites")
    print()
    print("📚 Files you need to create:")
    print("   - extension/background.js")
    print("   - extension/content.js") 
    print("   - extension/popup.html")
    print("   - extension/popup.js")
    print("   - extension/icons/*.png")
    print()
    print("💡 All code is provided in the artifacts above!")
    print("="*50)

def main():
    print_banner()
    
    # Step 1: Check Python version
    check_python_version()
    
    # Step 2: Check if requirements.txt exists
    if not Path("requirements.txt").exists():
        print("❌ requirements.txt not found!")
        print("   Please make sure requirements.txt is in the current directory")
        return
    
    # Step 3: Install dependencies
    if not install_requirements():
        return
    
    # Step 4: Create project structure
    create_project_structure()
    create_extension_folder()
    
    # Step 5: Run tests
    if not run_quick_test():
        print("⚠️  Setup completed but tests failed. Check your installation.")
        return
    
    # Step 6: Display next steps
    display_next_steps()

if __name__ == "__main__":
    main()
