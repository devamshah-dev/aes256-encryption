#!/usr/bin/env python3
import os
import sys
import subprocess
import webbrowser
import time
from pathlib import Path

def check_python_version():
    if sys.version_info < (3, 7):
        print("Python 3.7 or higher!")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_and_install_requirements():
    required_packages = [
        'flask',
        'flask-cors', 
        'cryptography'
    ]
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"{package} is installed")
        except ImportError:
            print(f"{package} is missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                *missing_packages
            ])
            print("✅ All packages installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install packages: {e}")
            print("Please execute --> pip install flask flask-cors cryptography")
            return False
    return True

def create_directory_structure():
    print("\nCreating directory structure...")
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    print(f"Verified: {templates_dir}")
    static_dir = Path("static")
    static_dir.mkdir(exist_ok=True)
    print(f"✅ Created/verified: {static_dir}")
    return True

def check_files_exist():
    print("\nChecking required files...")
    
    required_files = [
        "app.py",
        "templates/index.html",
        "templates/style.css",
        "crypto_utils.py"
    ]
    missing_files = []
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"Found: {file_path}")
        else:
            print(f"Missing: {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\nMissing files: {', '.join(missing_files)}")
        print("Please make sure all files are in the correct location.")
        return False
    return True

def start_server():
    print("\nStarting Flask server...")
    print("Server will be available at: http://localhost:5000")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    try:
        from app import app
        def open_browser():
            time.sleep(1.5)
            try:
                webbrowser.open('http://localhost:5000')
                print("🌐 Opening browser...")
            except Exception as e:
                print(f"Could not open browser automatically: {e}")
                print("Please open http://localhost:5000 manually!")
        
        import threading
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        app.run(
            debug=True,
            host='localhost',
            port=5000,
            use_reloader=False  # I am disabling this reloader; was opening 2 browser window.
        )
        
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
        print("Thank you for using the AES-256 Encryption Project!")
    except Exception as e:
        print(f"\nError starting server: {e}")

def main():
    print("Secure AES-256 Encryption <-- Group 18 Project")
    print("=" * 60)
    if not check_python_version():
        input("Press Enter to exit...")
        return
    if not check_and_install_requirements():
        input("Press Enter to exit...")
        return
    if not create_directory_structure():
        input("Press Enter to exit...")
        return
    if not check_files_exist():
        input("Press Enter to exit...")
        return
    print("\nReady to start server.")
    input("Click Enter to start the Flask server...")
    start_server()

if __name__ == "__main__":
    main()