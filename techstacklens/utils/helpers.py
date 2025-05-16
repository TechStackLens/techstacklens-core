"""
Helpers module with utility functions for use across the tool.
"""

import os
import logging
import platform
import socket
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

def is_admin():
    """
    Check if the script is running with administrator privileges.
    
    Returns:
        bool: True if running as administrator, False otherwise
    """
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # For Unix systems, check if effective user ID is 0 (root)
            return os.geteuid() == 0
    except:
        return False

def check_nmap_installed():
    """
    Check if nmap is installed on the system.
    
    Returns:
        bool: True if nmap is installed, False otherwise
    """
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def get_local_ip():
    """
    Get the local IP address of the machine.
    
    Returns:
        str: Local IP address
    """
    try:
        # Create a socket to a known public host
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def ensure_directory(directory_path):
    """
    Ensure that a directory exists, creating it if necessary.
    
    Args:
        directory_path (str): Path to directory
        
    Returns:
        Path: Path object representing the directory
    """
    path = Path(directory_path)
    path.mkdir(parents=True, exist_ok=True)
    return path

def validate_ip_range(ip_range):
    """
    Validate that a given string is a valid IP range.
    
    Args:
        ip_range (str): IP range to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Simple validation - should be improved for production
    if not ip_range:
        return False
    
    # Check for CIDR notation (e.g., 192.168.1.0/24)
    if '/' in ip_range:
        parts = ip_range.split('/')
        if len(parts) != 2:
            return False
        
        ip_part = parts[0]
        prefix_part = parts[1]
        
        # Validate IP part
        try:
            socket.inet_aton(ip_part)
        except socket.error:
            return False
        
        # Validate prefix part
        try:
            prefix = int(prefix_part)
            return 0 <= prefix <= 32
        except ValueError:
            return False
    
    # Check for simple IP address
    try:
        socket.inet_aton(ip_range)
        return True
    except socket.error:
        return False
