#!/usr/bin/env python3
"""
TechStackLens Scanner Package Creator

This script packages all the TechStackLens scanner tools into separately
distributable ZIP files for easy deployment to client systems with
different technology stacks.
"""

import os
import sys
import zipfile
import shutil
from pathlib import Path

# List of scanners to package
SCANNERS = {
    "windows-iis": {
        "name": "Windows IIS Scanner",
        "script": "collection_script.py",
        "batch_file": "run_windows_scanner.bat",
        "description": "Collects information about Windows IIS environments and network infrastructure."
    },
    "xampp": {
        "name": "XAMPP Stack Scanner",
        "script": "xampp_scanner.py",
        "shell_file": "run_xampp_scanner.sh",
        "batch_file": "run_xampp_scanner.bat",
        "description": "Collects information about XAMPP environments (Apache, MySQL, PHP, Perl) on Windows or Linux systems with ELT component detection."
    },
    "cloud": {
        "name": "Cloud Infrastructure Scanner",
        "script": "cloud_scanner.py",
        "shell_file": "run_cloud_scanner.sh",
        "batch_file": "run_cloud_scanner.bat",
        "description": "Collects information about AWS, Azure, and GCP environments."
    }
}

def create_readme(scanner_type):
    """Create a README file for a specific scanner package."""
    scanner = SCANNERS[scanner_type]
    
    # Create scanner-specific readme
    if scanner_type == "windows-iis":
        readme_content = f"""TechStackLens {scanner['name']}
============================

This tool collects information about your Windows-IIS environment and network
to be uploaded to the TechStackLens application for analysis.

Requirements:
- Windows system with IIS installed (for IIS scanning)
- Python 3.6+ installed

Steps:
1. Run the batch file {scanner['batch_file']}
2. Follow the on-screen instructions
3. Upload the resulting JSON files to the TechStackLens web application

For support, contact the TechStackLens team.
"""
    elif scanner_type == "xampp":
        readme_content = f"""TechStackLens {scanner['name']}
============================

This tool collects information about your XAMPP environment (Apache, MySQL, PHP, Perl)
on either Windows or Linux systems, including detection of ELT/ETL components.

Requirements:
- Windows or Linux system with XAMPP installed
- Python 3.6+ installed

Steps:
1. For Windows users: Run the batch file {scanner['batch_file']}
   For Linux/macOS users: Run the shell script {scanner['shell_file']}
2. Follow the on-screen instructions
3. Upload the resulting JSON files to the TechStackLens web application

For support, contact the TechStackLens team.
"""
    elif scanner_type == "cloud":
        readme_content = f"""TechStackLens {scanner['name']}
============================

This tool collects information about your cloud infrastructure (AWS, Azure, GCP)
to be uploaded to the TechStackLens application for analysis.

Requirements:
- Python 3.6+ installed
- Appropriate cloud CLI tools configured:
  - AWS CLI for scanning AWS
  - Azure CLI for scanning Azure
  - Google Cloud SDK for scanning GCP

Steps:
1. Ensure you have authenticated with your cloud provider(s)
2. For Windows users: Run the batch file {scanner['batch_file']}
   For Linux/macOS users: Run the shell script {scanner['shell_file']}
3. Follow the on-screen instructions
4. Upload the resulting JSON files to the TechStackLens web application

For support, contact the TechStackLens team.
"""

    # Write readme to file
    with open(f"README_{scanner_type}.txt", "w") as f:
        f.write(readme_content)
    return f"README_{scanner_type}.txt"

def create_batch_script(scanner_type):
    """Create a batch script for Windows scanners."""
    scanner = SCANNERS[scanner_type]
    script_file = scanner['script']
    
    # Use existing batch file if it exists
    batch_file = scanner.get('batch_file')
    if batch_file and os.path.exists(batch_file):
        return batch_file
    
    # Create a default batch file for Windows
    if scanner_type == "windows-iis":
        batch_content = """@echo off
echo TechStackLens Windows IIS Scanner
echo =================================
echo.

REM Check for Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in the PATH.
    echo Please install Python 3.6 or higher and try again.
    echo.
    pause
    exit /b 1
)

echo Running IIS and network scan...
echo This may take a few minutes depending on your environment.
echo.

REM Run the scanner with default options
python collection_script.py --scan-local --scan-network

echo.
echo Scan complete!
echo Results are saved in the techstacklens_data directory.
echo Please upload these JSON files to the TechStackLens web application.
echo.
pause
"""
    elif scanner_type == "cloud":
        batch_content = """@echo off
echo TechStackLens Cloud Infrastructure Scanner
echo =========================================
echo.

REM Check for Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in the PATH.
    echo Please install Python 3.6 or higher and try again.
    echo.
    pause
    exit /b 1
)

echo Which cloud provider(s) would you like to scan?
echo 1. AWS
echo 2. Azure
echo 3. GCP
echo 4. All available providers
echo.
set /p CHOICE="Enter your choice (1-4): "

if "%CHOICE%"=="1" (
    python cloud_scanner.py --scan-aws
) else if "%CHOICE%"=="2" (
    python cloud_scanner.py --scan-azure
) else if "%CHOICE%"=="3" (
    python cloud_scanner.py --scan-gcp
) else if "%CHOICE%"=="4" (
    python cloud_scanner.py --scan-aws --scan-azure --scan-gcp
) else (
    echo Invalid choice. Running scan for all providers...
    python cloud_scanner.py --scan-aws --scan-azure --scan-gcp
)

echo.
echo Scan complete!
echo Results are saved in the techstacklens_data directory.
echo Please upload these JSON files to the TechStackLens web application.
echo.
pause
"""
    else:
        batch_content = f"""@echo off
echo TechStackLens {scanner['name']}
echo =================================
echo.

REM Check for Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in the PATH.
    echo Please install Python 3.6 or higher and try again.
    echo.
    pause
    exit /b 1
)

echo Running scan...
echo This may take a few minutes depending on your environment.
echo.

REM Run the scanner with default options
python {script_file} --scan-local --scan-network

echo.
echo Scan complete!
echo Results are saved in the techstacklens_data directory.
echo Please upload these JSON files to the TechStackLens web application.
echo.
pause
"""

    # Write batch file
    batch_file = f"run_{scanner_type}_scanner.bat"
    with open(batch_file, "w") as f:
        f.write(batch_content)
    return batch_file

def create_shell_script(scanner_type):
    """Create a shell script for Linux/macOS scanners."""
    scanner = SCANNERS[scanner_type]
    script_file = scanner['script']
    
    # Use existing shell file if it exists
    shell_file = scanner.get('shell_file')
    if shell_file and os.path.exists(shell_file):
        return shell_file
    
    # Create a default shell script for Linux/macOS
    if scanner_type == "cloud":
        shell_content = """#!/bin/bash

echo "TechStackLens Cloud Infrastructure Scanner"
echo "========================================="
echo

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.6 or higher and try again."
    echo
    exit 1
fi

# Make the script executable
chmod +x cloud_scanner.py

echo "Which cloud provider(s) would you like to scan?"
echo "1. AWS"
echo "2. Azure"
echo "3. GCP"
echo "4. All available providers"
echo
read -p "Enter your choice (1-4): " CHOICE

if [ "$CHOICE" = "1" ]; then
    python3 cloud_scanner.py --scan-aws
elif [ "$CHOICE" = "2" ]; then
    python3 cloud_scanner.py --scan-azure
elif [ "$CHOICE" = "3" ]; then
    python3 cloud_scanner.py --scan-gcp
elif [ "$CHOICE" = "4" ]; then
    python3 cloud_scanner.py --scan-aws --scan-azure --scan-gcp
else
    echo "Invalid choice. Running scan for all providers..."
    python3 cloud_scanner.py --scan-aws --scan-azure --scan-gcp
fi

echo
echo "Scan complete!"
echo "Results are saved in the techstacklens_data directory."
echo "Please upload these JSON files to the TechStackLens web application."
echo
"""
    else:
        shell_content = f"""#!/bin/bash

echo "TechStackLens {scanner['name']}"
echo "================================="
echo

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.6 or higher and try again."
    echo
    exit 1
fi

# Make the script executable
chmod +x {script_file}

echo "Running scan..."
echo "This may take a few minutes depending on your environment."
echo

# Run the scanner with default options
python3 {script_file} --scan-local --scan-network

echo
echo "Scan complete!"
echo "Results are saved in the techstacklens_data directory."
echo "Please upload these JSON files to the TechStackLens web application."
echo
"""

    # Write shell script
    shell_file = f"run_{scanner_type}_scanner.sh"
    with open(shell_file, "w") as f:
        f.write(shell_content)
    return shell_file

def create_scanner_package(scanner_type):
    """Create a ZIP package for a specific scanner."""
    scanner = SCANNERS[scanner_type]
    
    print(f"Creating TechStackLens {scanner['name']} package...")
    
    # Create dist directory if it doesn't exist
    os.makedirs("dist", exist_ok=True)
    
    # Determine files to include
    files_to_include = [
        scanner['script'],
        create_readme(scanner_type)
    ]
    
    # Add platform-specific scripts
    if scanner_type == "windows-iis" or scanner.get('batch_file'):
        files_to_include.append(create_batch_script(scanner_type))
    
    if scanner_type != "windows-iis" or scanner.get('shell_file'):
        files_to_include.append(create_shell_script(scanner_type))
    
    # Create ZIP file
    zip_filename = f"dist/techstacklens_{scanner_type}_scanner.zip"
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        for file in files_to_include:
            if os.path.exists(file):
                zipf.write(file, arcname=os.path.basename(file))
            else:
                print(f"Warning: File {file} not found, skipping")
    
    # Get file size
    size_kb = os.path.getsize(zip_filename) / 1024
    print(f"Package created successfully: {zip_filename}")
    print(f"Size: {size_kb:.1f} KB")
    
    # Clean up temporary files
    for file in files_to_include:
        if file != scanner['script'] and os.path.exists(file) and file.startswith(("README_", "run_")):
            os.remove(file)

def main():
    """Main function."""
    # Create packages for all scanners
    for scanner_type in SCANNERS:
        create_scanner_package(scanner_type)
    
    print("\nAll scanner packages have been created in the 'dist' directory.")
    print("Distribute these ZIP files to client systems according to their technology stack.")

if __name__ == "__main__":
    main()
