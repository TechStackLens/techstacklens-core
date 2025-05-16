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
        "description": "Collects information about XAMPP environments (Apache, MySQL, PHP, Perl) on Windows or Linux systems."
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
    
    # Create default readme header
    readme_content = f"""TechStackLens {scanner['name']}
==========================

This tool collects information about your environment
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
    elif scanner_type == "lamp":
        readme_content = f"""TechStackLens {scanner['name']}
==========================

This tool collects information about your LAMP stack environment (Linux, Apache, MySQL, PHP)
to be uploaded to the TechStackLens application for analysis.

Requirements:
- Linux system with Apache, MySQL/MariaDB, and/or PHP installed
- Python 3.6+ installed
- Appropriate permissions to read configuration files (root/sudo for some operations)
- Nmap installed (optional, for better network scanning)

Usage:
1. Extract this zip file to a directory on your Linux system
2. Make the shell script executable: chmod +x run_lamp_scanner.sh
3. Run one of the following commands:

   # Interactive guided scan:
   ./run_lamp_scanner.sh

   # Manual scan options:
   python lamp_scanner.py --scan-local
   python lamp_scanner.py --scan-network --network-range 192.168.1.0/24
   python lamp_scanner.py --scan-local --scan-network

4. After the scan completes, find the results in the 'techstacklens_data' directory
5. Upload the 'combined_scan_results.json' file to the TechStackLens web application

Common Options:
  --output-dir DIR     Directory to save results (default: techstacklens_data)
  --verbose, -v        Enable verbose output for debugging
  --help, -h           Show help message

For support, contact the TechStackLens team.
"""
    elif scanner_type == "cloud":
        readme_content = f"""TechStackLens {scanner['name']}
==========================

This tool collects information about your cloud infrastructure (AWS, Azure, and/or GCP)
to be uploaded to the TechStackLens application for analysis.

Requirements:
- Python 3.6+ installed
- AWS CLI configured (for AWS scanning)
- Azure CLI configured (for Azure scanning)
- Google Cloud SDK configured (for GCP scanning)
- Appropriate permissions to read cloud resources

Usage:
1. Extract this zip file to a directory on your system
2. Make sure you have authenticated with your cloud provider(s):
   - AWS: aws configure
   - Azure: az login
   - GCP: gcloud auth login
3. Run one of the following commands:

   # Interactive guided scan:
   ./run_cloud_scanner.sh (Linux/Mac)
   run_cloud_scanner.bat (Windows)

   # Manual scan options:
   python cloud_scanner.py --scan-aws --aws-region us-east-1
   python cloud_scanner.py --scan-azure
   python cloud_scanner.py --scan-gcp --gcp-project my-project-id
   python cloud_scanner.py --scan-aws --scan-azure --scan-gcp

4. After the scan completes, find the results in the 'techstacklens_data' directory
5. Upload the 'combined_scan_results.json' file to the TechStackLens web application

Common Options:
  --aws-services SERVICES    Comma-separated list of AWS services to scan
  --azure-services SERVICES  Comma-separated list of Azure services to scan
  --gcp-services SERVICES    Comma-separated list of GCP services to scan
  --output-dir DIR           Directory to save results (default: techstacklens_data)
  --verbose, -v              Enable verbose output for debugging
  --help, -h                 Show help message

For support, contact the TechStackLens team.
"""
    
    with open(f"README_{scanner_type}.txt", "w") as f:
        f.write(readme_content)
    return f"README_{scanner_type}.txt"

def create_batch_script(scanner_type):
    """Create a batch script for Windows scanners."""
    scanner = SCANNERS[scanner_type]
    script_file = scanner['script']
    
    if scanner_type == "windows-iis":
        batch_content = """@echo off
echo TechStackLens Windows IIS Scanner
echo ==============================
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
    elif scanner_type == "cloud":
        batch_content = """@echo off
echo TechStackLens Cloud Infrastructure Scanner
echo =====================================
echo.

echo This scanner requires that you have configured your cloud provider CLI tools:
echo  - AWS: aws configure
echo  - Azure: az login
echo  - GCP: gcloud auth login
echo.

echo Choose a cloud provider to scan:
echo 1. AWS
echo 2. Azure
echo 3. Google Cloud Platform (GCP)
echo 4. Scan all configured providers
echo 5. Exit
echo.

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    set /p region="Enter AWS region (e.g. us-east-1) or press Enter for all regions: "
    if "%region%"=="" (
        python cloud_scanner.py --scan-aws --verbose
    ) else (
        python cloud_scanner.py --scan-aws --aws-region %region% --verbose
    )
) else if "%choice%"=="2" (
    python cloud_scanner.py --scan-azure --verbose
) else if "%choice%"=="3" (
    set /p project="Enter GCP project ID or press Enter for default project: "
    if "%project%"=="" (
        python cloud_scanner.py --scan-gcp --verbose
    ) else (
        python cloud_scanner.py --scan-gcp --gcp-project %project% --verbose
    )
) else if "%choice%"=="4" (
    python cloud_scanner.py --scan-aws --scan-azure --scan-gcp --verbose
) else if "%choice%"=="5" (
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
    else:
        # No batch script for this scanner
        return None
    
    batch_file = scanner.get('batch_file')
    if not batch_file:
        return None
        
    with open(batch_file, "w") as f:
        f.write(batch_content)
    return batch_file

def create_shell_script(scanner_type):
    """Create a shell script for Unix/Linux scanners."""
    scanner = SCANNERS[scanner_type]
    script_file = scanner['script']
    
    if scanner_type == "lamp":
        shell_content = """#!/bin/bash

echo "TechStackLens LAMP Stack Scanner"
echo "=============================="
echo

# Check if running with sufficient privileges
if [ "$EUID" -ne 0 ]; then
    echo "WARNING: This script is not running with root privileges."
    echo "         Some features may not work correctly."
    echo "         Consider running with sudo for better results."
    echo
    read -p "Press Enter to continue anyway, or Ctrl+C to exit and restart with sudo..." 
fi

echo "Choose a scan type:"
echo "1. Scan local LAMP configuration"
echo "2. Scan network"
echo "3. Scan both LAMP configuration and network"
echo "4. Exit"
echo

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        python3 lamp_scanner.py --scan-local --verbose
        ;;
    2)
        read -p "Enter network range to scan (e.g. 192.168.1.0/24): " network
        python3 lamp_scanner.py --scan-network --network-range "$network" --verbose
        ;;
    3)
        read -p "Enter network range to scan (e.g. 192.168.1.0/24): " network
        python3 lamp_scanner.py --scan-local --scan-network --network-range "$network" --verbose
        ;;
    4)
        exit 0
        ;;
    *)
        echo "Invalid choice!"
        exit 1
        ;;
esac

echo
echo "Scan complete! Results are stored in the 'techstacklens_data' directory."
echo "Please upload the 'combined_scan_results.json' file to the TechStackLens web application."
echo
"""
    elif scanner_type == "cloud":
        shell_content = """#!/bin/bash

echo "TechStackLens Cloud Infrastructure Scanner"
echo "======================================="
echo

echo "This scanner requires that you have configured your cloud provider CLI tools:"
echo " - AWS: aws configure"
echo " - Azure: az login"
echo " - GCP: gcloud auth login"
echo

echo "Choose a cloud provider to scan:"
echo "1. AWS"
echo "2. Azure"
echo "3. Google Cloud Platform (GCP)"
echo "4. Scan all configured providers"
echo "5. Exit"
echo

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        read -p "Enter AWS region (e.g. us-east-1) or press Enter for all regions: " region
        if [ -z "$region" ]; then
            python3 cloud_scanner.py --scan-aws --verbose
        else
            python3 cloud_scanner.py --scan-aws --aws-region "$region" --verbose
        fi
        ;;
    2)
        python3 cloud_scanner.py --scan-azure --verbose
        ;;
    3)
        read -p "Enter GCP project ID or press Enter for default project: " project
        if [ -z "$project" ]; then
            python3 cloud_scanner.py --scan-gcp --verbose
        else
            python3 cloud_scanner.py --scan-gcp --gcp-project "$project" --verbose
        fi
        ;;
    4)
        python3 cloud_scanner.py --scan-aws --scan-azure --scan-gcp --verbose
        ;;
    5)
        exit 0
        ;;
    *)
        echo "Invalid choice!"
        exit 1
        ;;
esac

echo
echo "Scan complete! Results are stored in the 'techstacklens_data' directory."
echo "Please upload the 'combined_scan_results.json' file to the TechStackLens web application."
echo
"""
    else:
        # No shell script for this scanner
        return None
    
    shell_file = scanner.get('shell_file')
    if not shell_file:
        return None
        
    with open(shell_file, "w") as f:
        f.write(shell_content)
    os.chmod(shell_file, 0o755)  # Make executable
    return shell_file

def package_scanner(scanner_type):
    """Package a specific scanner into a zip file."""
    print(f"Creating TechStackLens {SCANNERS[scanner_type]['name']} package...")
    
    # Create output directory if it doesn't exist
    Path("dist").mkdir(exist_ok=True)
    
    # Create README and scripts
    readme_file = create_readme(scanner_type)
    
    files_to_include = [readme_file]
    
    # Create batch files for Windows-based scanners
    if 'batch_file' in SCANNERS[scanner_type]:
        batch_file = create_batch_script(scanner_type)
        if batch_file:
            files_to_include.append(batch_file)
    
    # Create shell scripts for Unix/Linux-based scanners
    if 'shell_file' in SCANNERS[scanner_type]:
        shell_file = create_shell_script(scanner_type)
        if shell_file:
            files_to_include.append(shell_file)
    
    # Define package name
    package_name = f"dist/techstacklens_{scanner_type}_scanner.zip"
    
    # Create ZIP file
    with zipfile.ZipFile(package_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add scanner script
        zipf.write(SCANNERS[scanner_type]['script'])
        
        # Add README and script files
        for file in files_to_include:
            zipf.write(file)
    
    # Clean up temporary files
    for file in files_to_include:
        os.remove(file)
    
    print(f"Package created successfully: {package_name}")
    print(f"Size: {os.path.getsize(package_name) / 1024:.1f} KB")

def create_all_packages():
    """Create packages for all scanners."""
    for scanner_type in SCANNERS:
        package_scanner(scanner_type)
    
    print("\nAll scanner packages have been created in the 'dist' directory.")
    print("Distribute these ZIP files to client systems according to their technology stack.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Package a specific scanner
        scanner_type = sys.argv[1]
        if scanner_type in SCANNERS:
            package_scanner(scanner_type)
        else:
            print(f"Unknown scanner type: {scanner_type}")
            print(f"Available scanners: {', '.join(SCANNERS.keys())}")
    else:
        # Package all scanners
        create_all_packages()