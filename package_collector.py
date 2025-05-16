#!/usr/bin/env python3
"""
TechStackLens Collection Tool Packager

This script packages the TechStackLens collection tool into a ZIP file
for easy distribution to client systems.
"""

import os
import sys
import zipfile
import shutil
from pathlib import Path

def create_readme():
    """Create a README file for the package."""
    readme_content = """TechStackLens Collection Tool
==========================

This tool collects information about your Windows-IIS environment and network
to be uploaded to the TechStackLens application for analysis.

Requirements:
- Windows system with IIS installed (for IIS scanning)
- Python 3.6+ installed
- Administrator privileges (for accessing IIS configuration files)
- Nmap installed (optional, for better network scanning)

Usage:
1. Extract this zip file to a directory on your Windows system
2. Open a command prompt with Administrator privileges
3. Navigate to the extracted directory
4. Run one of the following commands:

   # Scan local IIS configuration:
   python collection_script.py --scan-local

   # Scan network:
   python collection_script.py --scan-network --network-range 192.168.1.0/24

   # Scan both IIS and network:
   python collection_script.py --scan-local --scan-network

5. After the scan completes, find the results in the 'techstacklens_data' directory
6. Upload the 'combined_scan_results.json' file to the TechStackLens web application

Common Options:
  --output-dir DIR     Directory to save results (default: techstacklens_data)
  --verbose, -v        Enable verbose output for debugging
  --help, -h           Show help message

For support, contact the TechStackLens team.
"""
    with open("README.txt", "w") as f:
        f.write(readme_content)
    return "README.txt"

def create_batch_script():
    """Create a batch script to make running the tool easier."""
    batch_content = """@echo off
echo TechStackLens Collection Tool
echo ===========================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: This script is not running with Administrator privileges.
    echo          Some features may not work correctly.
    echo          Right-click the batch file and select "Run as administrator".
    echo.
    pause
)

echo Choose a scan type:
echo 1. Scan local IIS configuration
echo 2. Scan network
echo 3. Scan both IIS and network
echo 4. Exit
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    python collection_script.py --scan-local --verbose
) else if "%choice%"=="2" (
    set /p network="Enter network range to scan (e.g. 192.168.1.0/24): "
    python collection_script.py --scan-network --network-range %network% --verbose
) else if "%choice%"=="3" (
    set /p network="Enter network range to scan (e.g. 192.168.1.0/24): "
    python collection_script.py --scan-local --scan-network --network-range %network% --verbose
) else if "%choice%"=="4" (
    exit /b
) else (
    echo Invalid choice!
    exit /b
)

echo.
echo Scan complete! Results are stored in the 'techstacklens_data' directory.
echo Please upload the 'combined_scan_results.json' file to the TechStackLens web application.
echo.
pause
"""
    with open("run_collector.bat", "w") as f:
        f.write(batch_content)
    return "run_collector.bat"

def package_collector():
    """Package the collection tool into a zip file."""
    print("Creating TechStackLens collection tool package...")
    
    # Create output directory if it doesn't exist
    Path("dist").mkdir(exist_ok=True)
    
    # Create README and batch file
    readme_file = create_readme()
    batch_file = create_batch_script()
    
    # Define package name
    package_name = "dist/techstacklens_collector.zip"
    
    # Create ZIP file
    with zipfile.ZipFile(package_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add collection script
        zipf.write("collection_script.py")
        
        # Add README and batch file
        zipf.write(readme_file)
        zipf.write(batch_file)
    
    # Clean up temporary files
    os.remove(readme_file)
    os.remove(batch_file)
    
    print(f"Package created successfully: {package_name}")
    print(f"Size: {os.path.getsize(package_name) / 1024:.1f} KB")
    print("\nDistribute this ZIP file to client systems for data collection.")
    print("Users can run the 'run_collector.bat' script for an interactive experience.")

if __name__ == "__main__":
    package_collector()