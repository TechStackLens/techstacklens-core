#!/usr/bin/env python3
"""
TechStackLens LAMP Stack Scanner

This script collects Apache, MySQL, and PHP configuration information from Linux systems
and generates JSON files compatible with the TechStackLens web application.

Usage:
  python lamp_scanner.py --scan-local --scan-network --network-range 192.168.1.0/24
"""

import os
import sys
import json
import argparse
import logging
import socket
import subprocess
import re
import pwd
import grp
from pathlib import Path
from datetime import datetime
import configparser

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = Path("techstacklens_data")

class ApacheScanner:
    """
    Scanner for Apache configurations that extracts virtual hosts, modules,
    and application types.
    """
    
    def __init__(self):
        """Initialize the Apache Scanner."""
        # Common Apache config paths on various Linux distributions
        self.apache_conf_paths = [
            '/etc/apache2/apache2.conf',           # Debian/Ubuntu
            '/etc/apache2/httpd.conf',             # Some Debian/Ubuntu
            '/etc/httpd/conf/httpd.conf',          # Red Hat/CentOS/Fedora
            '/usr/local/apache2/conf/httpd.conf',  # Generic Apache installation
            '/usr/local/etc/apache24/httpd.conf',  # FreeBSD
        ]
        
        # Common paths for virtual host configurations
        self.vhost_paths = [
            '/etc/apache2/sites-enabled/',        # Debian/Ubuntu
            '/etc/httpd/conf.d/',                 # Red Hat/CentOS/Fedora
            '/etc/apache2/vhosts.d/',             # SUSE
            '/usr/local/apache2/conf/extra/',     # Generic Apache installation
            '/usr/local/etc/apache24/extra/',     # FreeBSD
        ]
        
        # Application type indicators
        self.app_types = {
            'wordpress': ['wp-config.php', 'wp-content', 'wp-admin'],
            'drupal': ['sites/default/settings.php', 'core/includes/bootstrap.inc'],
            'joomla': ['configuration.php', 'components', 'administrator/components'],
            'laravel': ['artisan', 'app/Http/Controllers'],
            'symfony': ['app/AppKernel.php', 'bin/console', 'config/bundles.php'],
            'django': ['manage.py', 'wsgi.py', 'settings.py'],
            'flask': ['app.py', 'wsgi.py', 'requirements.txt'],
            'nodejs': ['package.json', 'node_modules', 'server.js'],
            'ruby': ['Gemfile', 'config.ru', 'app/controllers'],
            'static': ['index.html', '.html', '.css', '.js']
        }
    
    def scan(self):
        """
        Scan Apache configuration to extract virtual hosts, modules, and application types.
        
        Returns:
            dict: Apache scan results
        """
        logger.info("Starting Apache configuration scan")
        
        results = {
            "apache_version": self._get_apache_version(),
            "config_file": self._find_main_config_file(),
            "modules": self._get_loaded_modules(),
            "virtual_hosts": [],
            "doc_roots": {},
            "app_types": {}
        }
        
        # Get virtual hosts
        vhosts = self._scan_virtual_hosts()
        results["virtual_hosts"] = vhosts
        
        # Extract document roots
        for vhost in vhosts:
            if "document_root" in vhost and vhost["document_root"]:
                server_name = vhost.get("server_name", "default")
                results["doc_roots"][server_name] = vhost["document_root"]
        
        # Detect application types
        for server_name, doc_root in results["doc_roots"].items():
            app_type = self._detect_app_type(doc_root)
            if app_type:
                results["app_types"][server_name] = app_type
        
        logger.info(f"Apache scan completed: found {len(results['virtual_hosts'])} virtual hosts")
        return {"apache_scan": results}
    
    def _find_main_config_file(self):
        """Find the main Apache configuration file."""
        for path in self.apache_conf_paths:
            if os.path.isfile(path):
                return path
        return None
    
    def _get_apache_version(self):
        """Get Apache version information."""
        try:
            # Try different Apache commands based on the distribution
            for cmd in ["apache2 -v", "httpd -v", "/usr/sbin/apache2 -v", "/usr/sbin/httpd -v"]:
                try:
                    process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0 and "Server version" in process.stdout:
                        version_line = next((line for line in process.stdout.splitlines() if "Server version" in line), "")
                        if version_line:
                            return version_line.strip()
                        break
                except:
                    continue
            
            # Fallback to reading from operating system information
            process = subprocess.run(["lsb_release", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode == 0:
                return f"Unknown (OS: {process.stdout.strip()})"
            
            return "Unknown"
        except Exception as e:
            logger.error(f"Error getting Apache version: {e}")
            return "Unknown"
    
    def _get_loaded_modules(self):
        """Get list of loaded Apache modules."""
        modules = []
        try:
            # Try different Apache commands based on the distribution
            for cmd in ["apache2ctl -M", "httpd -M", "/usr/sbin/apache2ctl -M", "/usr/sbin/httpd -M"]:
                try:
                    process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0 and "Loaded Modules" in process.stdout:
                        # Extract module names
                        for line in process.stdout.splitlines():
                            if "_module" in line:
                                module_name = line.strip().split()[0]
                                modules.append(module_name)
                        break
                except:
                    continue
        except Exception as e:
            logger.error(f"Error getting Apache modules: {e}")
        
        return modules
    
    def _scan_virtual_hosts(self):
        """Scan Apache configuration for virtual hosts."""
        vhosts = []
        
        # First, check if we can get vhosts directly from Apache
        try:
            process = subprocess.run(["apache2ctl", "-S"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode == 0:
                return self._parse_apache_s_output(process.stdout)
        except Exception as e:
            logger.debug(f"Could not get virtual hosts from apache2ctl: {e}")
        
        # If that fails, parse configuration files
        try:
            # First try the main configuration
            config_file = self._find_main_config_file()
            if config_file:
                vhosts.extend(self._parse_config_file_for_vhosts(config_file))
            
            # Then check virtual host configuration directories
            for vhost_path in self.vhost_paths:
                if os.path.isdir(vhost_path):
                    for filename in os.listdir(vhost_path):
                        if filename.endswith('.conf'):
                            vhost_file = os.path.join(vhost_path, filename)
                            vhosts.extend(self._parse_config_file_for_vhosts(vhost_file))
        except Exception as e:
            logger.error(f"Error scanning virtual hosts: {e}")
        
        return vhosts
    
    def _parse_apache_s_output(self, output):
        """Parse the output of 'apache2ctl -S' to extract virtual hosts."""
        vhosts = []
        
        for line in output.splitlines():
            # Look for lines with port and namevhost
            match = re.search(r'port (\d+) namevhost (\S+)', line)
            if match:
                port = match.group(1)
                server_name = match.group(2)
                
                vhost = {
                    "server_name": server_name,
                    "port": int(port),
                    "ssl": False  # We'll check this later
                }
                
                # Look for document root and config file
                config_match = re.search(r'\(([^:]+):(\d+)\)', line)
                if config_match:
                    vhost["config_file"] = config_match.group(1)
                
                vhosts.append(vhost)
        
        # Parse config files to get additional information
        for vhost in vhosts:
            if "config_file" in vhost:
                self._add_vhost_details(vhost, vhost["config_file"])
        
        return vhosts
    
    def _parse_config_file_for_vhosts(self, config_file):
        """Parse an Apache configuration file to extract virtual hosts."""
        vhosts = []
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Extract VirtualHost blocks
            vhost_blocks = re.findall(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>', content, re.DOTALL)
            
            for vhost_addr, vhost_content in vhost_blocks:
                vhost = {
                    "config_file": config_file,
                    "address": vhost_addr.strip()
                }
                
                # Extract port from address
                port_match = re.search(r':(\d+)', vhost_addr)
                if port_match:
                    vhost["port"] = int(port_match.group(1))
                else:
                    vhost["port"] = 80  # Default HTTP port
                
                # Check for SSL
                if "443" in vhost_addr or re.search(r'SSLEngine\s+on', vhost_content, re.IGNORECASE):
                    vhost["ssl"] = True
                else:
                    vhost["ssl"] = False
                
                # Extract ServerName
                server_name_match = re.search(r'ServerName\s+(\S+)', vhost_content)
                if server_name_match:
                    vhost["server_name"] = server_name_match.group(1)
                else:
                    vhost["server_name"] = "default"
                
                # Extract ServerAlias
                server_alias_match = re.search(r'ServerAlias\s+(.+?)$', vhost_content, re.MULTILINE)
                if server_alias_match:
                    vhost["server_alias"] = server_alias_match.group(1).strip().split()
                
                # Extract DocumentRoot
                doc_root_match = re.search(r'DocumentRoot\s+["\'"]?([^"\'\s]+)["\'"]?', vhost_content)
                if doc_root_match:
                    vhost["document_root"] = doc_root_match.group(1)
                
                # Add to list
                vhosts.append(vhost)
        except Exception as e:
            logger.error(f"Error parsing config file {config_file}: {e}")
        
        return vhosts
    
    def _add_vhost_details(self, vhost, config_file):
        """Add additional details to a virtual host by parsing its config file."""
        try:
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Extract DocumentRoot
            doc_root_match = re.search(r'DocumentRoot\s+["\'"]?([^"\'\s]+)["\'"]?', content)
            if doc_root_match:
                vhost["document_root"] = doc_root_match.group(1)
            
            # Check for SSL
            if re.search(r'SSLEngine\s+on', content, re.IGNORECASE):
                vhost["ssl"] = True
        except Exception as e:
            logger.error(f"Error adding vhost details from {config_file}: {e}")
    
    def _detect_app_type(self, doc_root):
        """
        Detect application type based on directory contents.
        
        Args:
            doc_root (str): Path to document root
            
        Returns:
            str: Detected application type or None
        """
        if not os.path.isdir(doc_root):
            return None
        
        # Check for each app type
        for app_type, indicators in self.app_types.items():
            found = 0
            for indicator in indicators:
                # Check if indicator is a file or directory in the document root
                if os.path.exists(os.path.join(doc_root, indicator)):
                    found += 1
                # Check if indicator is a string pattern in a filename
                elif indicator.startswith('.'):
                    # Look for files with this extension
                    ext = indicator
                    for filename in os.listdir(doc_root):
                        if filename.endswith(ext):
                            found += 1
                            break
                # For deeper paths like 'sites/default/settings.php'
                elif '/' in indicator:
                    if os.path.exists(os.path.join(doc_root, indicator)):
                        found += 1
            
            # If we found at least 2 indicators, consider it a match
            if found >= 2 or (found == 1 and len(indicators) == 1):
                return app_type
        
        # Check for PHP files
        php_files = [f for f in os.listdir(doc_root) if f.endswith('.php')]
        if php_files:
            return "php"
        
        # Default to static if we have HTML files
        html_files = [f for f in os.listdir(doc_root) if f.endswith(('.html', '.htm'))]
        if html_files:
            return "static"
        
        return "unknown"

class MySQLScanner:
    """
    Scanner for MySQL/MariaDB configurations and database information.
    """
    
    def __init__(self):
        """Initialize the MySQL Scanner."""
        # Common MySQL config paths
        self.mysql_conf_paths = [
            '/etc/mysql/my.cnf',
            '/etc/my.cnf',
            '/usr/local/etc/my.cnf',
            '~/.my.cnf'
        ]
    
    def scan(self):
        """
        Scan MySQL/MariaDB configuration and gather database information.
        
        Returns:
            dict: MySQL scan results
        """
        logger.info("Starting MySQL/MariaDB scan")
        
        results = {
            "version": self._get_mysql_version(),
            "config_file": self._find_mysql_config(),
            "running": self._check_if_running(),
            "databases": [],
            "config_details": self._extract_config_details()
        }
        
        # Try to get database information
        if results["running"]:
            results["databases"] = self._get_databases()
        
        logger.info("MySQL/MariaDB scan completed")
        return {"mysql_scan": results}
    
    def _get_mysql_version(self):
        """Get MySQL/MariaDB version information."""
        try:
            # Try to get version from mysql client
            for cmd in ["mysql --version", "mariadb --version"]:
                try:
                    process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0:
                        return process.stdout.strip()
                except:
                    continue
            
            # Try to get version from package manager
            for cmd in ["dpkg -l | grep mysql-server", "dpkg -l | grep mariadb-server", 
                      "rpm -qa | grep mysql", "rpm -qa | grep mariadb"]:
                try:
                    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0 and process.stdout.strip():
                        return process.stdout.strip()
                except:
                    continue
            
            return "Unknown"
        except Exception as e:
            logger.error(f"Error getting MySQL version: {e}")
            return "Unknown"
    
    def _find_mysql_config(self):
        """Find the main MySQL configuration file."""
        for path in self.mysql_conf_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.isfile(expanded_path):
                return expanded_path
        return None
    
    def _check_if_running(self):
        """Check if MySQL/MariaDB is running."""
        try:
            # Try different ways to check if MySQL is running
            
            # Method 1: Check system process list
            for process_name in ["mysqld", "mariadbd"]:
                try:
                    process = subprocess.run(["pgrep", process_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if process.returncode == 0:
                        return True
                except:
                    pass
            
            # Method 2: Check system service
            for service_name in ["mysql", "mysqld", "mariadb"]:
                try:
                    process = subprocess.run(["systemctl", "is-active", service_name], 
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0 and "active" in process.stdout:
                        return True
                except:
                    pass
            
            # Method 3: Try to connect
            try:
                socket.create_connection(("127.0.0.1", 3306), timeout=1).close()
                return True
            except:
                pass
            
            return False
        except Exception as e:
            logger.error(f"Error checking if MySQL is running: {e}")
            return False
    
    def _extract_config_details(self):
        """Extract important configuration details from MySQL config file."""
        config_details = {}
        
        config_file = self._find_mysql_config()
        if not config_file:
            return config_details
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Extract bind address
            bind_address_match = re.search(r'bind-address\s*=\s*(\S+)', content)
            if bind_address_match:
                config_details["bind_address"] = bind_address_match.group(1)
            
            # Extract port
            port_match = re.search(r'port\s*=\s*(\d+)', content)
            if port_match:
                config_details["port"] = int(port_match.group(1))
            else:
                config_details["port"] = 3306  # Default MySQL port
            
            # Extract data directory
            datadir_match = re.search(r'datadir\s*=\s*(\S+)', content)
            if datadir_match:
                config_details["data_directory"] = datadir_match.group(1)
            
            # Extract socket
            socket_match = re.search(r'socket\s*=\s*(\S+)', content)
            if socket_match:
                config_details["socket"] = socket_match.group(1)
        except Exception as e:
            logger.error(f"Error extracting MySQL config details: {e}")
        
        return config_details
    
    def _get_databases(self):
        """Try to get database information (requires permissions)."""
        databases = []
        
        try:
            # Try to get databases list using mysqladmin (which might work without password)
            process = subprocess.run(["mysqladmin", "-u", "root", "ping"], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if process.returncode == 0:
                # We have access as root without password, try to list databases
                process = subprocess.run(["mysql", "-u", "root", "-e", "SHOW DATABASES;"], 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if process.returncode == 0:
                    # Parse output
                    lines = process.stdout.strip().split('\n')
                    if len(lines) > 1:  # Skip header row
                        for line in lines[1:]:
                            db_name = line.strip()
                            if db_name and db_name not in ["information_schema", "performance_schema", "mysql", "sys"]:
                                databases.append({"name": db_name})
        except Exception as e:
            logger.debug(f"Could not get MySQL databases: {e}")
        
        return databases

class PHPScanner:
    """
    Scanner for PHP configurations and modules.
    """
    
    def __init__(self):
        """Initialize the PHP Scanner."""
        # Common PHP config paths
        self.php_conf_paths = [
            '/etc/php/*/apache2/php.ini',
            '/etc/php/*/cli/php.ini',
            '/etc/php/*/fpm/php.ini',
            '/etc/php.ini',
            '/usr/local/etc/php.ini'
        ]
    
    def scan(self):
        """
        Scan PHP configuration and gather module information.
        
        Returns:
            dict: PHP scan results
        """
        logger.info("Starting PHP scan")
        
        results = {
            "version": self._get_php_version(),
            "config_files": self._find_php_configs(),
            "modules": self._get_php_modules(),
            "config_details": self._extract_config_details()
        }
        
        logger.info("PHP scan completed")
        return {"php_scan": results}
    
    def _get_php_version(self):
        """Get PHP version information."""
        try:
            process = subprocess.run(["php", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode == 0:
                # Extract version from the first line
                version_line = process.stdout.splitlines()[0]
                return version_line.strip()
            return "Unknown"
        except Exception as e:
            logger.error(f"Error getting PHP version: {e}")
            return "Unknown"
    
    def _find_php_configs(self):
        """Find PHP configuration files."""
        config_files = []
        
        for path_pattern in self.php_conf_paths:
            # Handle glob patterns
            if '*' in path_pattern:
                import glob
                for path in glob.glob(path_pattern):
                    if os.path.isfile(path):
                        config_files.append(path)
            else:
                if os.path.isfile(path_pattern):
                    config_files.append(path_pattern)
        
        return config_files
    
    def _get_php_modules(self):
        """Get list of PHP modules."""
        modules = []
        
        try:
            process = subprocess.run(["php", "-m"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode == 0:
                # Parse module list, skipping headers
                in_module_list = False
                for line in process.stdout.splitlines():
                    line = line.strip()
                    if line == "[PHP Modules]":
                        in_module_list = True
                        continue
                    elif line == "[Zend Modules]":
                        in_module_list = False
                        continue
                    
                    if in_module_list and line:
                        modules.append(line)
        except Exception as e:
            logger.error(f"Error getting PHP modules: {e}")
        
        return modules
    
    def _extract_config_details(self):
        """Extract important configuration details from PHP config files."""
        config_details = {}
        
        config_files = self._find_php_configs()
        if not config_files:
            return config_details
        
        # Only parse the first config file
        try:
            with open(config_files[0], 'r') as f:
                content = f.read()
            
            # Extract important settings
            for setting in ['memory_limit', 'upload_max_filesize', 'post_max_size', 
                           'max_execution_time', 'display_errors', 'error_reporting']:
                pattern = rf'{setting}\s*=\s*([^\r\n;]+)'
                match = re.search(pattern, content)
                if match:
                    config_details[setting] = match.group(1).strip()
        except Exception as e:
            logger.error(f"Error extracting PHP config details: {e}")
        
        return config_details

class LAMPNetworkScanner:
    """
    Scanner for network hosts and services in a LAMP environment.
    Detects cross-server dependencies such as middleware and databases.
    """
    
    def __init__(self):
        """Initialize the Network Scanner."""
        self.interesting_ports = [
            # Web/App servers
            80, 443, 8080, 8443, 
            # Databases
            3306, 5432, 27017, 6379, 
            # Middleware
            8000, 8088, 9000, 9090, 
            # Other common services
            21, 22, 25, 389, 636, 5672, 15672
        ]
        
        # Service identification patterns
        self.service_patterns = {
            "web": ["http", "https", "www", "apache", "nginx"],
            "database": ["mysql", "mariadb", "postgres", "mongodb", "redis"],
            "middleware": ["php-fpm", "php", "tomcat", "jetty", "node", "rabbitmq", "activemq"],
            "mail": ["smtp", "pop3", "imap", "mail", "postfix", "dovecot"],
            "file": ["ftp", "sftp", "smb", "cifs", "nfs", "samba"],
            "directory": ["ldap", "openldap", "389-ds"],
            "cache": ["redis", "memcached", "varnish"]
        }
        
        # Check if nmap is available
        self.nmap_available = self._check_nmap_installed()
    
    def scan(self, target_range):
        """
        Scan network range for hosts and services.
        
        Args:
            target_range (str): Network range to scan (e.g., "192.168.1.0/24")
            
        Returns:
            dict: Network scan results
        """
        logger.info(f"Starting network scan on range {target_range}")
        
        results = {
            "scan_info": {
                "target": target_range,
                "timestamp": datetime.now().isoformat(),
                "local_hostname": socket.gethostname(),
                "local_ip": self._get_local_ip()
            },
            "hosts": []
        }
        
        try:
            if self.nmap_available:
                logger.info("Using nmap for network scanning")
                scan_results = self._scan_with_nmap(target_range)
            else:
                logger.info("Nmap not available, using basic network tools")
                scan_results = self._scan_with_basic_tools(target_range)
            
            # Process scan results
            if scan_results:
                for host_ip, host_data in scan_results.items():
                    host_info = self._process_host_data(host_ip, host_data)
                    if host_info:
                        results["hosts"].append(host_info)
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
        
        logger.info(f"Network scan completed: found {len(results['hosts'])} hosts")
        return {"network_scan": results}
    
    def _check_nmap_installed(self):
        """Check if nmap is installed and available."""
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False
    
    def _get_local_ip(self):
        """Get local IP address."""
        try:
            # Create a socket to a known public host to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def _scan_with_nmap(self, target_range):
        """
        Scan network using nmap.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Nmap scan results
        """
        logger.debug(f"Scanning with nmap: {target_range}")
        
        # Convert list of ports to string for nmap
        ports_str = ",".join(map(str, self.interesting_ports))
        
        # Build nmap command
        cmd = ["nmap", "-sV", "--version-intensity", "2", "-p", ports_str, "--open", "-oX", "-", target_range]
        
        try:
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode != 0:
                logger.error(f"Nmap error: {process.stderr}")
                return {}
            
            # Parse XML output
            return self._parse_nmap_xml(process.stdout)
        except Exception as e:
            logger.error(f"Error running nmap subprocess: {e}")
            return {}
    
    def _scan_with_basic_tools(self, target_range):
        """
        Scan network using basic tools like ping and nc.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Scan results
        """
        logger.debug(f"Scanning with basic tools: {target_range}")
        results = {}
        
        # Parse target range
        if '/' in target_range:  # CIDR notation
            import ipaddress
            try:
                network = ipaddress.ip_network(target_range)
                hosts = list(network.hosts())
                # Limit to first 20 hosts for performance
                hosts = hosts[:20]
            except:
                logger.error(f"Invalid network range: {target_range}")
                return results
        else:
            # Single IP
            hosts = [target_range]
        
        # Scan each host
        for host in hosts:
            host_ip = str(host)
            
            # Skip localhost
            if host_ip == "127.0.0.1":
                continue
            
            # Check if host is up using ping
            ping_cmd = ["ping", "-c", "1", "-W", "1", host_ip]
            try:
                ping_process = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if ping_process.returncode != 0:
                    continue  # Host is down or unreachable
                
                # Host is up, initialize data
                results[host_ip] = {
                    "hostname": "",
                    "tcp": {}
                }
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(host_ip)[0]
                    results[host_ip]["hostname"] = hostname
                except:
                    pass
                
                # Check open ports
                for port in self.interesting_ports:
                    # Try nc (netcat)
                    nc_cmd = ["nc", "-z", "-w", "1", host_ip, str(port)]
                    try:
                        nc_process = subprocess.run(nc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if nc_process.returncode == 0:
                            # Port is open
                            service_name = self._guess_service_from_port(port)
                            results[host_ip]["tcp"][str(port)] = {
                                "state": "open",
                                "name": service_name,
                                "product": ""
                            }
                    except:
                        # If nc fails, try direct socket connection
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1)
                            sock.connect((host_ip, port))
                            sock.close()
                            
                            # Port is open
                            service_name = self._guess_service_from_port(port)
                            results[host_ip]["tcp"][str(port)] = {
                                "state": "open",
                                "name": service_name,
                                "product": ""
                            }
                        except:
                            pass
            except Exception as e:
                logger.debug(f"Error scanning host {host_ip}: {e}")
        
        return results
    
    def _guess_service_from_port(self, port):
        """Guess the service name based on port number."""
        common_ports = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            80: "http",
            443: "https",
            3306: "mysql",
            5432: "postgresql",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb"
        }
        return common_ports.get(port, "unknown")
    
    def _parse_nmap_xml(self, xml_data):
        """
        Parse nmap XML output to dict structure.
        
        Args:
            xml_data (str): Nmap XML output
            
        Returns:
            dict: Parsed scan results
        """
        hosts = {}
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            
            for host_elem in root.findall('.//host'):
                # Check if host is up
                status = host_elem.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Get host IP
                addr_elem = host_elem.find(".//address[@addrtype='ipv4']")
                if addr_elem is None:
                    continue
                
                host_ip = addr_elem.get('addr')
                hosts[host_ip] = {"tcp": {}}
                
                # Get hostname if available
                hostname_elem = host_elem.find(".//hostname")
                if hostname_elem is not None:
                    hosts[host_ip]["hostname"] = hostname_elem.get('name', '')
                
                # Get ports and services
                for port_elem in host_elem.findall('.//port'):
                    if port_elem.get('protocol') == 'tcp':
                        port_id = port_elem.get('portid')
                        
                        # Get state
                        state_elem = port_elem.find('state')
                        if state_elem is not None and state_elem.get('state') == 'open':
                            hosts[host_ip]['tcp'][port_id] = {'state': 'open'}
                            
                            # Get service details
                            service_elem = port_elem.find('service')
                            if service_elem is not None:
                                hosts[host_ip]['tcp'][port_id]['name'] = service_elem.get('name', 'unknown')
                                hosts[host_ip]['tcp'][port_id]['product'] = service_elem.get('product', '')
        except Exception as e:
            logger.error(f"Error parsing nmap XML: {e}")
        
        return hosts
    
    def _process_host_data(self, host_ip, host_data):
        """
        Process raw host data into structured format.
        
        Args:
            host_ip (str): Host IP address
            host_data (dict): Raw host data from scan
            
        Returns:
            dict: Structured host information
        """
        if not host_data.get("tcp"):
            return None
        
        host_info = {
            "ip": host_ip,
            "hostname": host_data.get("hostname", ""),
            "services": [],
            "roles": set()
        }
        
        # Process open ports and services
        for port, port_data in host_data["tcp"].items():
            if port_data.get("state") == "open":
                service_info = {
                    "port": int(port),
                    "name": port_data.get("name", "unknown"),
                    "product": port_data.get("product", "")
                }
                
                # Determine service role
                service_role = self._determine_service_role(service_info)
                if service_role:
                    service_info["role"] = service_role
                    host_info["roles"].add(service_role)
                
                host_info["services"].append(service_info)
        
        # Convert roles set to list
        host_info["roles"] = list(host_info["roles"])
        
        return host_info
    
    def _determine_service_role(self, service_info):
        """
        Determine the role of a service based on port and service name.
        
        Args:
            service_info (dict): Service information
            
        Returns:
            str: Service role or None
        """
        port = service_info["port"]
        service_name = service_info["name"].lower()
        product = service_info["product"].lower()
        
        combined_text = f"{service_name} {product}"
        
        # Check port-based rules first
        if port in [80, 443, 8080, 8443]:
            return "web"
        elif port in [3306, 5432, 27017, 6379]:
            return "database"
        elif port in [8000, 8088, 9000, 9090]:
            return "middleware"
        
        # Then check service name patterns
        for role, patterns in self.service_patterns.items():
            if any(pattern in combined_text for pattern in patterns):
                return role
        
        return None

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='TechStackLens LAMP Stack Scanner')
    parser.add_argument('--scan-local', action='store_true',
                        help='Scan local LAMP configuration')
    parser.add_argument('--scan-network', action='store_true',
                        help='Perform network scan')
    parser.add_argument('--network-range', type=str,
                        help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--output-dir', type=str, default='techstacklens_data',
                        help='Directory to save results (default: techstacklens_data)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    
    return parser.parse_args()

def ensure_output_dir(output_dir):
    """Ensure the output directory exists."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path

def save_results(data, output_dir, filename):
    """Save JSON data to file."""
    output_path = output_dir / filename
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"Results saved to {output_path}")
    return output_path

def main():
    """Main function."""
    args = parse_arguments()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Ensure output directory exists
    output_dir = ensure_output_dir(args.output_dir)
    
    scan_results = {}
    
    # Perform scans if requested
    if args.scan_local:
        logger.info("Starting local LAMP stack scan...")
        
        # Apache scan
        try:
            apache_scanner = ApacheScanner()
            apache_results = apache_scanner.scan()
            scan_results.update(apache_results)
            save_results(apache_results, output_dir, "apache_scan_results.json")
        except Exception as e:
            logger.error(f"Error during Apache scan: {e}")
        
        # MySQL scan
        try:
            mysql_scanner = MySQLScanner()
            mysql_results = mysql_scanner.scan()
            scan_results.update(mysql_results)
            save_results(mysql_results, output_dir, "mysql_scan_results.json")
        except Exception as e:
            logger.error(f"Error during MySQL scan: {e}")
        
        # PHP scan
        try:
            php_scanner = PHPScanner()
            php_results = php_scanner.scan()
            scan_results.update(php_results)
            save_results(php_results, output_dir, "php_scan_results.json")
        except Exception as e:
            logger.error(f"Error during PHP scan: {e}")
    
    if args.scan_network:
        if not args.network_range:
            local_ip = LAMPNetworkScanner()._get_local_ip()
            network_range = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            logger.info(f"No network range specified, using {network_range}")
        else:
            network_range = args.network_range
        
        logger.info(f"Starting network scan on range {network_range}...")
        network_scanner = LAMPNetworkScanner()
        network_results = network_scanner.scan(network_range)
        scan_results.update(network_results)
        save_results(network_results, output_dir, "network_scan_results.json")
    
    # Save combined results
    if scan_results:
        save_results(scan_results, output_dir, "combined_scan_results.json")
        logger.info(f"All scan results have been saved to the {output_dir} directory")
        logger.info(f"Upload combined_scan_results.json to the TechStackLens web application")
    else:
        logger.warning("No scans were performed. Use --scan-local or --scan-network flags.")
        print("\nUsage examples:")
        print("  python lamp_scanner.py --scan-local")
        print("  python lamp_scanner.py --scan-network --network-range 192.168.1.0/24")
        print("  python lamp_scanner.py --scan-local --scan-network --verbose")

if __name__ == "__main__":
    try:
        print("\nTechStackLens LAMP Stack Scanner")
        print("--------------------------------")
        main()
        print("\nCollection completed. Check the techstacklens_data directory for results.")
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print("\nScan interrupted. Partial results may have been saved.")
    except Exception as e:
        logger.error(f"Error in collection script: {e}", exc_info=True)
        print(f"\nAn error occurred: {e}")
        print("Check the logs for more details.")