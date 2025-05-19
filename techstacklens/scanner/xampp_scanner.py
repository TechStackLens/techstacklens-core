#!/usr/bin/env python3
"""
TechStackLens XAMPP Stack Scanner

This script collects Apache, MySQL, PHP, and Perl configuration information 
from Windows or Linux systems running XAMPP and generates JSON files 
compatible with the TechStackLens web application.

Usage:
  python xampp_scanner.py --scan-local --scan-network --network-range 192.168.1.0/24
"""

import os
import sys
import json
import argparse
import logging
import socket
import subprocess
import re
import platform
from pathlib import Path
from datetime import datetime
import configparser

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = Path("techstacklens_data")

class XAMPPScanner:
    """
    Scanner for XAMPP installations that detects Apache, MySQL, PHP, and Perl components
    along with virtual hosts and application types.
    """
    
    def __init__(self):
        """Initialize the XAMPP Scanner."""
        self.is_windows = platform.system() == "Windows"
        
        # Common XAMPP paths
        if self.is_windows:
            self.xampp_paths = [
                'C:\\xampp',
                'C:\\Program Files\\xampp',
                'C:\\Program Files (x86)\\xampp',
                'D:\\xampp'
            ]
            self.apache_conf_paths = ['apache\\conf\\httpd.conf', 'apache\\conf\\extra\\httpd-vhosts.conf']
            self.mysql_conf_paths = ['mysql\\bin\\my.ini']
            self.php_conf_paths = ['php\\php.ini']
        else:
            self.xampp_paths = [
                '/opt/lampp',
                '/usr/local/xampp',
                '~/xampp'
            ]
            self.apache_conf_paths = ['etc/httpd.conf', 'etc/extra/httpd-vhosts.conf']
            self.mysql_conf_paths = ['etc/my.cnf']
            self.php_conf_paths = ['etc/php.ini']

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
        
        # ELT tool indicators
        self.elt_indicators = {
            'talend': ['Talend-', '.job', 'talend.project'],
            'informatica': ['Informatica', 'powercenter', '.infa'],
            'apache_nifi': ['nifi', 'flow.xml.gz', 'conf/nifi.properties'],
            'apache_airflow': ['airflow.cfg', 'dags/', 'airflow/'],
            'kettle': ['kettle', 'spoon.sh', '.ktr', '.kjb'],
            'pentaho': ['pentaho', 'data-integration', 'pdi-'],
            'sql_server_ssis': ['.dtsx', 'Integration Services', 'SSIS'],
            'oracle_odi': ['ODI', 'odiparams', 'oracle.odi'],
            'aws_glue': ['glue', 'AWS Glue', 'GlueContext'],
            'azure_data_factory': ['ADF', 'datafactory', 'pipeline.json']
        }
    
    def scan(self):
        """
        Scan XAMPP installation to extract configuration and components.
        
        Returns:
            dict: XAMPP scan results
        """
        logger.info("Starting XAMPP scan")
        
        # Find XAMPP installation
        xampp_path = self._find_xampp_installation()
        if not xampp_path:
            logger.error("XAMPP installation not found")
            return {"xampp_scan": {"error": "XAMPP installation not found"}}
        
        logger.info(f"Found XAMPP installation at {xampp_path}")
        
        results = {
            "installation_path": str(xampp_path),
            "platform": platform.system(),
            "components": self._detect_components(xampp_path),
            "apache": self._scan_apache(xampp_path),
            "mysql": self._scan_mysql(xampp_path),
            "php": self._scan_php(xampp_path),
            "virtual_hosts": self._scan_virtual_hosts(xampp_path),
            "doc_roots": {},
            "app_types": {},
            "elt_tools": self._detect_elt_tools(xampp_path)
        }
        
        # Extract document roots from virtual hosts
        for vhost in results["virtual_hosts"]:
            if "document_root" in vhost and vhost["document_root"]:
                server_name = vhost.get("server_name", "default")
                results["doc_roots"][server_name] = vhost["document_root"]
        
        # Detect application types
        for server_name, doc_root in results["doc_roots"].items():
            app_type = self._detect_app_type(doc_root)
            if app_type:
                results["app_types"][server_name] = app_type
        
        logger.info(f"XAMPP scan completed: found {len(results['virtual_hosts'])} virtual hosts")
        return {"xampp_scan": results}
    
    def _find_xampp_installation(self):
        """Find the XAMPP installation directory."""
        for base_path in self.xampp_paths:
            path = Path(os.path.expanduser(base_path))
            if path.exists():
                # Verify it's a XAMPP installation by checking for key directories
                required_dirs = ['apache', 'mysql', 'php'] if self.is_windows else ['bin', 'etc', 'htdocs']
                if all(path.joinpath(d).exists() for d in required_dirs):
                    return path
        return None
    
    def _detect_components(self, xampp_path):
        """Detect installed XAMPP components."""
        components = {}
        
        # Check for Apache
        apache_path = xampp_path / ('apache' if self.is_windows else 'bin/httpd')
        if apache_path.exists():
            components["apache"] = True
            # Get version
            try:
                if self.is_windows:
                    cmd = f"{xampp_path}\\apache\\bin\\httpd.exe -v"
                else:
                    cmd = f"{xampp_path}/bin/httpd -v"
                process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if process.returncode == 0:
                    version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', process.stdout)
                    if version_match:
                        components["apache_version"] = version_match.group(1)
            except:
                pass
        
        # Check for MySQL/MariaDB
        mysql_path = xampp_path / ('mysql' if self.is_windows else 'bin/mysql')
        if mysql_path.exists():
            components["mysql"] = True
            # Get version
            try:
                if self.is_windows:
                    cmd = f"{xampp_path}\\mysql\\bin\\mysql.exe --version"
                else:
                    cmd = f"{xampp_path}/bin/mysql --version"
                process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if process.returncode == 0:
                    version_match = re.search(r'(MySQL|MariaDB).*?(\d+\.\d+\.\d+)', process.stdout)
                    if version_match:
                        components["mysql_version"] = version_match.group(2)
                        components["mysql_type"] = version_match.group(1).lower()
            except:
                pass
        
        # Check for PHP
        php_path = xampp_path / ('php' if self.is_windows else 'bin/php')
        if php_path.exists():
            components["php"] = True
            # Get version
            try:
                if self.is_windows:
                    cmd = f"{xampp_path}\\php\\php.exe -v"
                else:
                    cmd = f"{xampp_path}/bin/php -v"
                process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if process.returncode == 0:
                    version_match = re.search(r'PHP (\d+\.\d+\.\d+)', process.stdout)
                    if version_match:
                        components["php_version"] = version_match.group(1)
            except:
                pass
        
        # Check for Perl (only in Windows XAMPP)
        if self.is_windows:
            perl_path = xampp_path / 'perl'
            if perl_path.exists():
                components["perl"] = True
                # Get version
                try:
                    cmd = f"{xampp_path}\\perl\\bin\\perl.exe -v"
                    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0:
                        version_match = re.search(r'perl (\d+\.\d+\.\d+)', process.stdout)
                        if version_match:
                            components["perl_version"] = version_match.group(1)
                except:
                    pass
        
        # Check for phpMyAdmin
        phpmyadmin_path = xampp_path / ('phpMyAdmin' if self.is_windows else 'phpmyadmin')
        if phpmyadmin_path.exists() or (xampp_path / 'htdocs' / 'phpmyadmin').exists():
            components["phpmyadmin"] = True
        
        # Check for FileZilla (only in older Windows XAMPP)
        if self.is_windows:
            filezilla_path = xampp_path / 'FileZilla'
            if filezilla_path.exists():
                components["filezilla"] = True
        
        return components
    
    def _scan_apache(self, xampp_path):
        """Scan Apache configuration."""
        apache_info = {
            "modules": [],
            "config_file": None
        }
        
        # Find main config file
        for conf_path in self.apache_conf_paths:
            full_path = xampp_path / conf_path
            if full_path.exists():
                apache_info["config_file"] = str(full_path)
                break
        
        # Get loaded modules
        try:
            if self.is_windows:
                cmd = f"{xampp_path}\\apache\\bin\\httpd.exe -M"
            else:
                cmd = f"{xampp_path}/bin/httpd -M"
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode == 0:
                # Extract module names
                for line in process.stdout.splitlines():
                    if "_module" in line:
                        module_name = line.strip().split()[0]
                        apache_info["modules"].append(module_name)
        except Exception as e:
            logger.error(f"Error getting Apache modules: {e}")
        
        return apache_info
    
    def _scan_mysql(self, xampp_path):
        """Scan MySQL configuration."""
        mysql_info = {
            "config_file": None,
            "running": False,
            "databases": []
        }
        
        # Find main config file
        for conf_path in self.mysql_conf_paths:
            full_path = xampp_path / conf_path
            if full_path.exists():
                mysql_info["config_file"] = str(full_path)
                break
        
        # Check if MySQL is running
        try:
            if self.is_windows:
                # On Windows, check if the process is running
                process = subprocess.run("tasklist /fi \"imagename eq mysqld.exe\"", shell=True, 
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                mysql_info["running"] = "mysqld.exe" in process.stdout
            else:
                # On Linux/macOS, check if the process is running
                process = subprocess.run("ps -ef | grep mysqld | grep -v grep", shell=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                mysql_info["running"] = process.returncode == 0 and process.stdout.strip() != ""
        except:
            mysql_info["running"] = False
        
        # If MySQL is running, try to get databases
        if mysql_info["running"]:
            try:
                if self.is_windows:
                    cmd = f"{xampp_path}\\mysql\\bin\\mysql.exe -e \"SHOW DATABASES;\" --skip-column-names"
                else:
                    cmd = f"{xampp_path}/bin/mysql -e \"SHOW DATABASES;\" --skip-column-names"
                process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if process.returncode == 0:
                    mysql_info["databases"] = [db.strip() for db in process.stdout.splitlines() if db.strip()]
            except Exception as e:
                logger.error(f"Error getting MySQL databases: {e}")
        
        return mysql_info
    
    def _scan_php(self, xampp_path):
        """Scan PHP configuration."""
        php_info = {
            "config_file": None,
            "extensions": [],
            "settings": {}
        }
        
        # Find main config file
        for conf_path in self.php_conf_paths:
            full_path = xampp_path / conf_path
            if full_path.exists():
                php_info["config_file"] = str(full_path)
                
                # Parse PHP configuration
                try:
                    # Get PHP extensions and key settings
                    if self.is_windows:
                        cmd = f"{xampp_path}\\php\\php.exe -m"
                    else:
                        cmd = f"{xampp_path}/bin/php -m"
                    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if process.returncode == 0:
                        extensions = [ext.strip() for ext in process.stdout.splitlines() 
                                    if ext.strip() and not ext.startswith('[')]
                        php_info["extensions"] = extensions
                    
                    # Get key PHP settings
                    key_settings = ["memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time"]
                    for setting in key_settings:
                        try:
                            if self.is_windows:
                                cmd = f"{xampp_path}\\php\\php.exe -r \"echo ini_get('{setting}');\""
                            else:
                                cmd = f"{xampp_path}/bin/php -r \"echo ini_get('{setting}');\""
                            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            if process.returncode == 0 and process.stdout.strip():
                                php_info["settings"][setting] = process.stdout.strip()
                        except:
                            pass
                except Exception as e:
                    logger.error(f"Error reading PHP configuration: {e}")
                
                break
        
        return php_info
    
    def _scan_virtual_hosts(self, xampp_path):
        """Scan Apache configuration for virtual hosts."""
        vhosts = []
        
        # Find vhosts configuration
        apache_conf = None
        vhosts_conf = None
        
        for conf_path in self.apache_conf_paths:
            full_path = xampp_path / conf_path
            if full_path.exists():
                if 'httpd.conf' in str(full_path):
                    apache_conf = full_path
                elif 'httpd-vhosts.conf' in str(full_path):
                    vhosts_conf = full_path
        
        # First check main httpd.conf for Include directives pointing to vhosts
        if apache_conf and not vhosts_conf:
            try:
                with open(apache_conf, 'r') as f:
                    for line in f:
                        if 'Include' in line and 'vhosts' in line.lower():
                            vhost_path = line.split('Include')[1].strip()
                            if self.is_windows and not vhost_path.startswith('/'):
                                if vhost_path.startswith('"') and vhost_path.endswith('"'):
                                    vhost_path = vhost_path[1:-1]
                                if not os.path.isabs(vhost_path):
                                    vhost_path = os.path.join(xampp_path, 'apache', vhost_path)
                                vhosts_conf = Path(vhost_path)
            except Exception as e:
                logger.error(f"Error reading Apache config: {e}")
        
        # Parse vhosts configuration file
        config_files = []
        if vhosts_conf:
            config_files.append(vhosts_conf)
        elif apache_conf:
            config_files.append(apache_conf)
        
        for config_file in config_files:
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                
                # Extract VirtualHost blocks
                vhost_blocks = re.findall(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>', content, re.DOTALL)
                
                for vhost_addr, vhost_content in vhost_blocks:
                    vhost = {
                        "config_file": str(config_file),
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
        
        # If no vhosts found, create default entry for htdocs
        if not vhosts:
            htdocs_path = xampp_path / ('htdocs' if not self.is_windows or xampp_path.joinpath('htdocs').exists() else 'apache/htdocs')
            if htdocs_path.exists():
                vhosts.append({
                    "server_name": "localhost",
                    "port": 80,
                    "ssl": False,
                    "document_root": str(htdocs_path)
                })
        
        return vhosts
    
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
    
    def _detect_elt_tools(self, xampp_path):
        """
        Detect ELT (Extract, Load, Transform) tools in the environment.
        
        Args:
            xampp_path (Path): Path to XAMPP installation
            
        Returns:
            dict: Detected ELT tools
        """
        elt_tools = {}
        
        # Look for ELT tools in htdocs and other locations
        search_paths = [
            xampp_path / ('htdocs' if not self.is_windows or xampp_path.joinpath('htdocs').exists() else 'apache/htdocs'),
            xampp_path / 'htdocs/etl',
            xampp_path / 'htdocs/data',
            Path(os.path.expanduser('~')) / 'etl',
            Path(os.path.expanduser('~')) / 'data-integration',
            Path('C:/Program Files/Talend') if self.is_windows else Path('/opt/talend'),
            Path('C:/Program Files/Informatica') if self.is_windows else Path('/opt/informatica'),
            Path('C:/Program Files/Pentaho') if self.is_windows else Path('/opt/pentaho')
        ]
        
        # Add drives on Windows
        if self.is_windows:
            for drive in ['C:', 'D:', 'E:']:
                search_paths.append(Path(f'{drive}/etl'))
                search_paths.append(Path(f'{drive}/data-integration'))
        
        # Search for ELT tool indicators
        for path in search_paths:
            if path.exists():
                for tool, indicators in self.elt_indicators.items():
                    found = False
                    # Check if any indicator exists in this path
                    for indicator in indicators:
                        # Check at current level
                        matches = list(path.glob(f'*{indicator}*'))
                        if matches:
                            found = True
                            break
                        
                        # Check subdirectories one level deep
                        for subdir in path.glob('*'):
                            if subdir.is_dir():
                                submatches = list(subdir.glob(f'*{indicator}*'))
                                if submatches:
                                    found = True
                                    break
                        
                        if found:
                            break
                    
                    if found:
                        elt_tools[tool] = str(path)
        
        # Look for ELT tool processes in running processes
        try:
            if self.is_windows:
                process = subprocess.run("tasklist", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                process_list = process.stdout.lower()
                
                # Check for common ELT process names
                for tool, keywords in {
                    'talend': ['talend', 'tdqrepositoryservice'],
                    'informatica': ['infaservice', 'pmrepagent', 'infacmd'],
                    'pentaho': ['spoon', 'kitchen', 'pan', 'carte'],
                    'apache_nifi': ['nifi'],
                    'apache_airflow': ['airflow'],
                    'sql_server_ssis': ['dtexec', 'dtsx'],
                    'aws_glue': ['glue'],
                    'azure_data_factory': ['datafactory']
                }.items():
                    for keyword in keywords:
                        if keyword in process_list:
                            elt_tools[tool] = "Running process detected"
                            break
            else:
                process = subprocess.run("ps -ef", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                process_list = process.stdout.lower()
                
                # Check for common ELT process names
                for tool, keywords in {
                    'talend': ['talend', 'tdqrepositoryservice'],
                    'informatica': ['infaservice', 'pmrepagent', 'infacmd'],
                    'pentaho': ['spoon', 'kitchen', 'pan', 'carte'],
                    'apache_nifi': ['nifi'],
                    'apache_airflow': ['airflow'],
                    'kettle': ['kettle', 'spoon'],
                    'aws_glue': ['glue'],
                    'azure_data_factory': ['datafactory']
                }.items():
                    for keyword in keywords:
                        if keyword in process_list:
                            elt_tools[tool] = "Running process detected"
                            break
        except Exception as e:
            logger.error(f"Error checking for ELT processes: {e}")
        
        return elt_tools


class XAMPPNetworkScanner:
    """
    Scanner for network hosts and services in a XAMPP environment.
    Detects cross-server dependencies such as middleware and databases.
    """
    
    def __init__(self):
        """Initialize the Network Scanner."""
        self.is_windows = platform.system() == "Windows"
    
    def scan(self, target_range):
        """
        Scan network range for hosts and services.
        
        Args:
            target_range (str): Network range to scan (e.g., "192.168.1.0/24")
            
        Returns:
            dict: Network scan results
        """
        logger.info(f"Starting network scan for {target_range}")
        
        # Check for nmap
        if self._check_nmap_installed():
            scan_results = self._scan_with_nmap(target_range)
        else:
            logger.warning("Nmap not found, using native tools (less accurate)")
            scan_results = self._scan_with_native_tools(target_range)
        
        logger.info(f"Network scan completed: found {len(scan_results.get('hosts', []))} hosts")
        return {"network_scan": scan_results}
    
    def _check_nmap_installed(self):
        """Check if nmap is installed and available."""
        try:
            process = subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return process.returncode == 0
        except:
            return False
    
    def _get_local_ip(self):
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            # Fallback
            return socket.gethostbyname(socket.gethostname())
    
    def _scan_with_nmap(self, target_range):
        """
        Scan network using nmap via subprocess.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Parsed nmap scan results
        """
        results = {
            "scan_tool": "nmap",
            "scan_type": "tcp_connect",
            "target_range": target_range,
            "hosts": []
        }
        
        temp_file = "nmap_scan_result.xml"
        
        try:
            # Run nmap with service detection and save to XML
            cmd = ["nmap", "-sT", "-sV", "-p", "21,22,23,25,80,443,1433,3306,3389,5432,8080,8443", 
                  "--open", "-oX", temp_file, target_range]
            logger.info(f"Running nmap scan: {' '.join(cmd)}")
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if process.returncode != 0:
                logger.error(f"Nmap error: {process.stderr}")
                return results
            
            # Read XML output
            try:
                with open(temp_file, 'r') as f:
                    xml_data = f.read()
                
                # Parse XML
                hosts_data = self._parse_nmap_xml(xml_data)
                
                # Process host data
                for host_ip, host_data in hosts_data.items():
                    processed_host = self._process_host_data(host_ip, host_data)
                    results["hosts"].append(processed_host)
                
            except Exception as e:
                logger.error(f"Error parsing nmap results: {e}")
            
            # Clean up temporary file
            try:
                os.remove(temp_file)
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error during nmap scan: {e}")
        
        return results
    
    def _scan_with_native_tools(self, target_range):
        """
        Scan network using native Windows/Linux tools.
        This is a fallback for when nmap is not available.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Scan results
        """
        results = {
            "scan_tool": "native",
            "scan_type": "ping",
            "target_range": target_range,
            "hosts": []
        }
        
        # Parse CIDR notation or convert single IP
        if "/" in target_range:
            # Parse CIDR notation
            ip_parts = target_range.split("/")
            base_ip = ip_parts[0]
            try:
                mask = int(ip_parts[1])
                # Convert to network range
                ip_prefix = ".".join(base_ip.split(".")[:3])
                start_ip = 1
                end_ip = 254  # Scan a limited range for speed
            except:
                # Invalid CIDR, just scan the given IP
                ip_prefix = ".".join(base_ip.split(".")[:3])
                start_ip = 1
                end_ip = 254
        else:
            # Single IP, just scan common ports on this IP
            ip_prefix = ".".join(target_range.split(".")[:3])
            start_ip = int(target_range.split(".")[-1])
            end_ip = start_ip
        
        # Scan IPs in the range
        for i in range(start_ip, end_ip + 1):
            ip = f"{ip_prefix}.{i}"
            try:
                # Ping the host to check if it's up
                if self.is_windows:
                    cmd = f"ping -n 1 -w 500 {ip}"
                else:
                    cmd = f"ping -c 1 -W 1 {ip}"
                
                process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if process.returncode == 0:
                    # Host is up, check for common ports
                    host_data = {
                        "ip": ip,
                        "status": "up",
                        "hostname": self._get_hostname(ip),
                        "services": self._check_common_ports(ip)
                    }
                    
                    # Only add if we found services
                    if host_data["services"]:
                        results["hosts"].append(host_data)
            except Exception as e:
                logger.debug(f"Error scanning {ip}: {e}")
        
        return results
    
    def _get_hostname(self, ip):
        """Get hostname for an IP address."""
        try:
            return socket.getfqdn(ip)
        except:
            return None
    
    def _check_common_ports(self, ip):
        """Check for common ports on a host."""
        services = []
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            80: "http",
            443: "https",
            1433: "ms-sql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            8080: "http-alt",
            8443: "https-alt"
        }
        
        for port, service_name in common_ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    services.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service_name,
                        "role": self._determine_service_role(service_name, port)
                    })
                s.close()
            except:
                pass
        
        return services
    
    def _parse_nmap_xml(self, xml_data):
        """
        Parse nmap XML output to dict structure.
        This is a simplified parser for when the python-nmap module is not available.
        
        Args:
            xml_data (str): Nmap XML output
            
        Returns:
            dict: Parsed scan results
        """
        hosts = {}
        
        # Extract hosts
        host_matches = re.findall(r'<host[^>]*>(.*?)</host>', xml_data, re.DOTALL)
        
        for host_xml in host_matches:
            # Extract address
            addr_match = re.search(r'<address addr="([^"]+)"', host_xml)
            if not addr_match:
                continue
            
            ip = addr_match.group(1)
            
            # Create host entry
            hosts[ip] = {
                "ip": ip,
                "status": "up",
                "hostname": None,
                "ports": []
            }
            
            # Extract hostname
            hostname_match = re.search(r'<hostname name="([^"]+)"', host_xml)
            if hostname_match:
                hosts[ip]["hostname"] = hostname_match.group(1)
            
            # Extract ports
            port_matches = re.findall(r'<port protocol="([^"]+)" portid="(\d+)".*?<state state="([^"]+)"', host_xml, re.DOTALL)
            
            for protocol, port, state in port_matches:
                if state == "open":
                    # Extract service info
                    service_match = re.search(r'<port protocol="{}" portid="{}".*?<service name="([^"]+)"(?:\s+product="([^"]+)")?(?:\s+version="([^"]+)")?'.format(
                        re.escape(protocol), re.escape(port)), host_xml, re.DOTALL)
                    
                    if service_match:
                        service_name = service_match.group(1)
                        product = service_match.group(2) if service_match.group(2) else ""
                        version = service_match.group(3) if service_match.group(3) else ""
                    else:
                        service_name = self._guess_service_from_port(int(port))
                        product = ""
                        version = ""
                    
                    port_info = {
                        "protocol": protocol,
                        "port": int(port),
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "state": state
                    }
                    
                    hosts[ip]["ports"].append(port_info)
        
        return hosts
    
    def _process_host_data(self, host_ip, host_data):
        """
        Process raw host data into structured format.
        
        Args:
            host_ip (str): Host IP address
            host_data (dict): Raw host data from nmap
            
        Returns:
            dict: Structured host information
        """
        services = []
        
        # Process each port
        for port_info in host_data.get("ports", []):
            service = {
                "port": port_info["port"],
                "protocol": port_info["protocol"],
                "service": port_info["service"],
                "version": port_info.get("product", "") + " " + port_info.get("version", "")
            }
            
            # Determine the role of this service
            role = self._determine_service_role(port_info["service"], port_info["port"])
            if role:
                service["role"] = role
            
            services.append(service)
        
        # Create structured host info
        return {
            "ip": host_ip,
            "hostname": host_data.get("hostname"),
            "status": host_data.get("status", "unknown"),
            "services": services
        }
    
    def _guess_service_from_port(self, port):
        """Guess the service name based on port number."""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            80: "http",
            443: "https",
            1433: "ms-sql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            8080: "http-alt",
            8443: "https-alt"
        }
        
        return common_ports.get(port, f"unknown-{port}")
    
    def _determine_service_role(self, service_name, port):
        """
        Determine the role of a service based on port and service name.
        
        Args:
            service_name (str): Service name
            port (int): Port number
            
        Returns:
            str: Service role or None
        """
        # Map services to infrastructure roles
        role_map = {
            "http": "web-server",
            "https": "web-server",
            "http-alt": "web-server",
            "https-alt": "web-server",
            "mysql": "database",
            "mariadb": "database",
            "ms-sql": "database",
            "postgresql": "database",
            "oracle": "database",
            "redis": "database",
            "mongodb": "database",
            "cassandra": "database",
            "ftp": "file-server",
            "sftp": "file-server",
            "ssh": "management",
            "telnet": "management",
            "rdp": "management",
            "smtp": "mail-server",
            "pop3": "mail-server",
            "imap": "mail-server",
            "ldap": "directory-service",
            "dns": "directory-service",
            "nfs": "file-server",
            "smb": "file-server",
            "cifs": "file-server"
        }
        
        # Special cases based on port
        if port == 8080 or port == 8000:
            return "application-server"
        elif port == 9000:
            return "application-server"  # Often PHP-FPM
        elif port == 6379:
            return "database"  # Redis
        elif port == 27017:
            return "database"  # MongoDB
        elif port == 5672 or port == 5671:
            return "message-queue"  # RabbitMQ
        elif port == 9092:
            return "message-queue"  # Kafka
        
        # Default mapping
        return role_map.get(service_name.lower())


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='TechStackLens XAMPP Stack Scanner')
    parser.add_argument('--scan-local', action='store_true',
                        help='Scan local XAMPP configuration')
    parser.add_argument('--scan-network', action='store_true',
                        help='Scan network for hosts and services')
    parser.add_argument('--network-range', type=str, default=None,
                        help='Network range to scan (CIDR notation, e.g., 192.168.1.0/24)')
    parser.add_argument('--output-dir', type=str, default=None,
                        help='Directory to save output files')
    return parser.parse_args()

def ensure_output_dir(output_dir):
    """Ensure the output directory exists."""
    os.makedirs(output_dir, exist_ok=True)
    return Path(output_dir)

def save_results(data, output_dir, filename):
    """Save JSON data to file."""
    file_path = output_dir / filename
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"Results saved to {file_path}")
    return file_path

def main():
    """Main function."""
    print("="*80)
    print("TechStackLens XAMPP Stack Scanner")
    print("="*80)
    
    args = parse_arguments()
    
    # Set output directory
    global OUTPUT_DIR
    if args.output_dir:
        OUTPUT_DIR = ensure_output_dir(args.output_dir)
    else:
        OUTPUT_DIR = ensure_output_dir(OUTPUT_DIR)
    
    # Check if at least one scan type is specified
    if not (args.scan_local or args.scan_network):
        print("\nNo scan type specified. Please use at least one of the following options:")
        print("  --scan-local     : Scan local XAMPP configuration")
        print("  --scan-network   : Scan network for hosts and services")
        print("\nFor more information, use --help")
        return
    
    # Combined results
    all_results = {}
    
    # Scan local XAMPP configuration
    if args.scan_local:
        logger.info("Starting local XAMPP stack scan...")
        try:
            xampp_scanner = XAMPPScanner()
            results = xampp_scanner.scan()
            
            # Save results
            save_results(results, OUTPUT_DIR, "xampp_scan_results.json")
            
            # Add to combined results
            all_results.update(results)
            
            print(f"\n✓ XAMPP scan completed")
            
        except Exception as e:
            logger.error(f"Error during XAMPP scan: {e}")
            print(f"\nError during XAMPP scan: {e}")
    
    # Scan network
    if args.scan_network:
        network_range = args.network_range
        if not network_range:
            # Use local subnet as default
            local_ip = XAMPPNetworkScanner()._get_local_ip()
            network_range = f"{local_ip}/24"
            logger.info(f"No network range specified, using local subnet: {network_range}")
        
        logger.info(f"Starting network scan for {network_range}...")
        try:
            network_scanner = XAMPPNetworkScanner()
            results = network_scanner.scan(network_range)
            
            # Save results
            save_results(results, OUTPUT_DIR, "network_scan_results.json")
            
            # Add to combined results
            all_results.update(results)
            
            host_count = len(results.get("network_scan", {}).get("hosts", []))
            print(f"\n✓ Network scan completed: discovered {host_count} hosts with relevant services")
            
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            print(f"\nError during network scan: {e}")
    
    # Save combined results
    if all_results:
        save_results(all_results, OUTPUT_DIR, "combined_results.json")
    
    print("\nTechStackLens XAMPP Stack Scanner completed successfully")
    print(f"Results saved to {OUTPUT_DIR}")
    print("\nUpload the JSON files to the TechStackLens web application for visualization and analysis.")
    print("="*80)

if __name__ == "__main__":
    main()