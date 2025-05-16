#!/bin/bash

echo
echo "=========================================="
echo "   TechStackLens XAMPP Scanner"
echo "=========================================="
echo

# Check for Python installation
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.6 or higher and try again."
    echo "On most Linux distributions, you can install using:"
    echo "  sudo apt install python3 python3-pip   # For Debian/Ubuntu"
    echo "  sudo yum install python3 python3-pip   # For RHEL/CentOS"
    echo
    exit 1
fi

# Make script executable
chmod +x xampp_scanner.py

echo "Scanning local XAMPP configuration and network..."
echo "This may take a few minutes..."
echo

# Run the scanner with options
python3 xampp_scanner.py --scan-local --scan-network

echo
echo "=========================================="
echo "Scan complete!"
echo
echo "Upload the JSON files from the 'techstacklens_data' folder" 
echo "to the TechStackLens web application for visualization."
echo "=========================================="
echo