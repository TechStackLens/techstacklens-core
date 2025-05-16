@echo off
echo.
echo ==========================================
echo   TechStackLens XAMPP Scanner
echo ==========================================
echo.

REM Check for Python installation
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in the PATH.
    echo Please install Python 3.6 or higher and try again.
    echo Visit https://www.python.org/downloads/ to download Python.
    echo.
    pause
    exit /b 1
)

echo Scanning local XAMPP configuration and network...
echo This may take a few minutes...
echo.

REM Run the scanner with options
python xampp_scanner.py --scan-local --scan-network

echo.
echo ==========================================
echo Scan complete!
echo.
echo Upload the JSON files from the 'techstacklens_data' folder 
echo to the TechStackLens web application for visualization.
echo ==========================================
echo.

pause