#!/usr/bin/env python3

# Advanced Web Vulnerability Scanner - Python Installation Script
# This script installs all required dependencies for the Python vulnerability scanner

import subprocess
import sys
import os
import json
from pathlib import Path

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║          Advanced Web Vulnerability Scanner - Python Installation            ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def check_python():
    print("[*] Checking Python installation...")
    try:
        version = sys.version_info
        if version.major == 3 and version.minor >= 6:
            print(f"[+] Python {version.major}.{version.minor}.{version.micro} found")
            return True
        else:
            print(f"[!] Python 3.6+ required, found {version.major}.{version.minor}.{version.micro}")
            return False
    except Exception as e:
        print(f"[!] Error checking Python: {e}")
        return False

def check_pip():
    print("[*] Checking pip installation...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] pip found")
        return True
    except subprocess.CalledProcessError:
        print("[!] pip not found")
        return False

def install_requirements():
    print("[*] Installing required Python packages...")
    
    requirements = [
        "requests>=2.25.0",
        "urllib3>=1.26.0"
    ]
    
    for requirement in requirements:
        print(f"    Installing {requirement}...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", requirement
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"    [+] {requirement} installed successfully")
        except subprocess.CalledProcessError:
            print(f"    [!] Failed to install {requirement}")
            return False
    
    return True

def check_files():
    print("[*] Checking scanner files...")
    
    required_files = [
        "web_scanner.py",
        "requirements.txt",
        "README.md"
    ]
    
    missing_files = []
    for file in required_files:
        if os.path.exists(file):
            print(f"    [+] Found: {file}")
        else:
            print(f"    [!] Missing: {file}")
            missing_files.append(file)
    
    return len(missing_files) == 0, missing_files

def create_wrapper():
    print("[*] Creating wrapper script...")
    
    wrapper_content = '''#!/usr/bin/env python3
# Wrapper script for the Python vulnerability scanner

import subprocess
import sys
import os

# Get the directory where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Run the scanner
scanner_path = os.path.join(script_dir, "web_scanner.py")
subprocess.call([sys.executable, scanner_path] + sys.argv[1:])
'''
    
    try:
        with open("vuln_scanner", "w") as f:
            f.write(wrapper_content)
        
        # Make executable on Unix systems
        if os.name != 'nt':
            os.chmod("vuln_scanner", 0o755)
        
        print("[+] Wrapper script created: vuln_scanner")
        return True
    except Exception as e:
        print(f"[!] Failed to create wrapper: {e}")
        return False

def test_installation():
    print("[*] Testing installation...")
    
    try:
        import requests
        import urllib3
        print("[+] All dependencies loaded successfully")
        return True
    except ImportError as e:
        print(f"[!] Import error: {e}")
        return False

def main():
    print_banner()
    
    # Check Python
    if not check_python():
        print("[!] Installation aborted.")
        sys.exit(1)
    
    # Check pip
    if not check_pip():
        print("[!] Please install pip first.")
        print("[!] Installation aborted.")
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("[!] Failed to install some requirements.")
        print("[!] Installation aborted.")
        sys.exit(1)
    
    # Check files
    files_ok, missing_files = check_files()
    if not files_ok:
        print("\n[!] Warning: The following files are missing:")
        for file in missing_files:
            print(f"    - {file}")
        print("[!] Please ensure all files are in the current directory.")
    
    # Create wrapper
    if not create_wrapper():
        print("[!] Failed to create wrapper script.")
    
    # Test installation
    if not test_installation():
        print("[!] Installation test failed.")
        print("[!] You may need to manually configure your Python environment.")
    
    print("\n" + "="*70)
    print("                    Installation Complete!")
    print("="*70)
    print()
    print("The Advanced Web Vulnerability Scanner has been installed successfully!")
    print()
    print("Quick start:")
    print("  python web_scanner.py https://example.com")
    print("  python web_scanner.py -v -o report.json https://example.com")
    print()
    print("Alternative (if wrapper script works on your system):")
    print("  vuln_scanner https://example.com")
    print()
    print("For help:")
    print("  python web_scanner.py --help")
    print()
    print("⚠️  Remember: Only use this tool on systems you own or have permission to test!")
    print()

if __name__ == "__main__":
    main()