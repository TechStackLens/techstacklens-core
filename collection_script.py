#!/usr/bin/env python3
"""
TechStackLens Collection Script

This script collects IIS and network information from Windows systems
and generates JSON files compatible with the TechStackLens web application.

Usage:
  python collection_script.py --scan-local --scan-network --network-range 192.168.1.0/24
"""

import os
import sys
import json
import argparse
import logging
import socket
import subprocess
import re
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = Path("techstacklens_data")

class IISScanner:
    """
    Scanner for IIS configurations that extracts site bindings, SNI hostnames,
    and application types from applicationHost.config and web.config files.
    """
    
    def __init__(self):
        """Initialize the IIS Scanner."""
        self.app_host_config_path = os.environ.get(
            'IIS_APP_HOST_CONFIG', 
            r'C:\Windows\System32\inetsrv\config\applicationHost.config'
        )
        self.web_config_patterns = [
            # Default web.config paths
            r'C:\inetpub\wwwroot\*\web.config',
            r'C:\inetpub\wwwroot\web.config'
        ]
        self.app_types = {
            'flutter': ['flutter', 'dart'],
            '.net': ['aspnet', 'asp.net', '.net', 'dotnet'],
            'php': ['php'],
            'node': ['node', 'nodejs', 'express'],
            'java': ['java', 'jsp', 'servlet'],
            'python': ['python', 'django', 'flask'],
            'static': ['html', 'static']
        }
    
    def scan(self):
        """
        Scan IIS configuration to extract site bindings, SNI hostnames,
        and application types.
        
        Returns:
            dict: IIS scan results
        """
        logger.info("Starting IIS configuration scan")
        
        results = {
            "iis_sites": [],
            "hostname_map": {},
            "app_types": {}
        }
        
        # Scan applicationHost.config for site bindings
        try:
            sites = self._scan_app_host_config()
            results["iis_sites"] = sites
            
            # Extract hostname mapping
            for site in sites:
                for binding in site.get("bindings", []):
                    if binding.get("hostname"):
                        results["hostname_map"][binding["hostname"]] = {
                            "site_name": site["name"],
                            "site_id": site["id"],
                            "ip": binding.get("ip", "*"),
                            "port": binding.get("port", 80),
                            "protocol": binding.get("protocol", "http")
                        }
        except Exception as e:
            logger.error(f"Error scanning applicationHost.config: {e}")
        
        # Scan web.config files for application types
        try:
            app_types = self._scan_web_configs()
            results["app_types"] = app_types
            
            # Associate app types with sites
            for site in results["iis_sites"]:
                site_path = site.get("physical_path", "")
                if site_path in app_types:
                    site["app_type"] = app_types[site_path]
        except Exception as e:
            logger.error(f"Error scanning web.config files: {e}")
        
        logger.info(f"IIS scan completed: found {len(results['iis_sites'])} sites")
        return {"iis_scan": results}
    
    def _scan_app_host_config(self):
        """
        Scan applicationHost.config to extract site information.
        
        Returns:
            list: List of site dictionaries with bindings
        """
        logger.debug(f"Scanning applicationHost.config at {self.app_host_config_path}")
        sites = []
        
        try:
            if not os.path.exists(self.app_host_config_path):
                logger.warning(f"applicationHost.config not found at {self.app_host_config_path}")
                return sites
            
            tree = ET.parse(self.app_host_config_path)
            root = tree.getroot()
            
            # Find the sites section
            sites_element = root.find("./system.applicationHost/sites")
            if sites_element is None:
                logger.warning("No sites section found in applicationHost.config")
                return sites
            
            # Process each site
            for site_element in sites_element.findall("./site"):
                site_id = site_element.get("id")
                site_name = site_element.get("name")
                
                site_info = {
                    "id": site_id,
                    "name": site_name,
                    "bindings": [],
                    "applications": []
                }
                
                # Get physical path from the first application
                app_element = site_element.find("./application/virtualDirectory")
                if app_element is not None:
                    site_info["physical_path"] = app_element.get("physicalPath", "")
                
                # Process bindings
                bindings_element = site_element.find("./bindings")
                if bindings_element is not None:
                    for binding in bindings_element.findall("./binding"):
                        binding_info = self._parse_binding_info(binding.get("bindingInformation", ""))
                        binding_info["protocol"] = binding.get("protocol", "http")
                        
                        # Check for SNI hostname
                        sni_element = binding.find("./sslFlags")
                        if sni_element is not None and "sni" in str(sni_element.text).lower():
                            binding_info["sni"] = True
                        
                        site_info["bindings"].append(binding_info)
                
                # Process applications
                for app_element in site_element.findall("./application"):
                    app_path = app_element.get("path", "/")
                    vdir_element = app_element.find("./virtualDirectory")
                    physical_path = vdir_element.get("physicalPath", "") if vdir_element is not None else ""
                    
                    app_info = {
                        "path": app_path,
                        "physical_path": physical_path
                    }
                    site_info["applications"].append(app_info)
                
                sites.append(site_info)
        except Exception as e:
            logger.error(f"Error parsing applicationHost.config: {e}")
        
        return sites
    
    def _parse_binding_info(self, binding_info):
        """
        Parse IIS binding information string.
        
        Args:
            binding_info (str): Binding information string in format "IP:port:hostname"
            
        Returns:
            dict: Parsed binding information
        """
        parts = binding_info.split(":")
        result = {"ip": "*", "port": 80, "hostname": ""}
        
        if len(parts) >= 1 and parts[0]:
            result["ip"] = parts[0]
        
        if len(parts) >= 2 and parts[1]:
            try:
                result["port"] = int(parts[1])
            except ValueError:
                logger.warning(f"Invalid port number in binding: {binding_info}")
        
        if len(parts) >= 3 and parts[2]:
            result["hostname"] = parts[2]
        
        return result
    
    def _scan_web_configs(self):
        """
        Scan web.config files to determine application types.
        
        Returns:
            dict: Mapping of site paths to application types
        """
        logger.debug("Scanning web.config files for application types")
        app_types = {}
        
        for pattern in self.web_config_patterns:
            base_dir = os.path.dirname(pattern)
            if not os.path.exists(base_dir):
                continue
            
            # Find web.config files
            for root, _, files in os.walk(base_dir):
                if "web.config" in files:
                    config_path = os.path.join(root, "web.config")
                    app_type = self._detect_app_type(config_path, root)
                    if app_type:
                        app_types[root] = app_type
        
        return app_types
    
    def _detect_app_type(self, config_path, site_path):
        """
        Detect application type from web.config and site files.
        
        Args:
            config_path (str): Path to web.config file
            site_path (str): Path to site root directory
            
        Returns:
            str: Detected application type
        """
        app_type = "unknown"
        
        try:
            # Parse web.config
            tree = ET.parse(config_path)
            root = tree.getroot()
            
            # Check for .NET
            if root.find("./system.web") is not None:
                return ".net"
            
            # Check for other specific configurations
            handlers = root.find("./system.webServer/handlers")
            if handlers is not None:
                handlers_text = ET.tostring(handlers, encoding='utf8', method='text').decode('utf8').lower()
                
                for type_name, keywords in self.app_types.items():
                    if any(keyword in handlers_text for keyword in keywords):
                        return type_name
            
            # Check files in directory for application clues
            return self._detect_app_type_from_files(site_path)
            
        except Exception as e:
            logger.debug(f"Error detecting app type from {config_path}: {e}")
            
        return app_type
    
    def _detect_app_type_from_files(self, site_path):
        """
        Detect application type by examining files in the site directory.
        
        Args:
            site_path (str): Path to site root directory
            
        Returns:
            str: Detected application type
        """
        # File patterns that indicate application types
        type_indicators = {
            'flutter': [r'\.dart$', r'flutter_service_worker\.js$'],
            '.net': [r'\.aspx$', r'\.cshtml$', r'\.vb$', r'\.cs$', r'Web\.config$', r'Global\.asax$'],
            'php': [r'\.php$', r'wp-config\.php$'],
            'node': [r'package\.json$', r'server\.js$', r'app\.js$'],
            'java': [r'\.jsp$', r'\.java$', r'WEB-INF/web\.xml$'],
            'python': [r'\.py$', r'\.wsgi$', r'requirements\.txt$'],
            'static': [r'\.html$', r'\.htm$', r'\.css$', r'\.js$']
        }
        
        # Count occurrences of each type
        type_counts = {t: 0 for t in type_indicators.keys()}
        
        for root, _, files in os.walk(site_path, topdown=True, followlinks=False):
            # Limit depth to prevent excessive scanning
            if root.replace(site_path, '').count(os.sep) > 3:
                continue
                
            for filename in files:
                file_path = os.path.join(root, filename)
                
                for app_type, patterns in type_indicators.items():
                    if any(re.search(pattern, filename, re.IGNORECASE) for pattern in patterns):
                        type_counts[app_type] += 1
        
        # Determine most likely type (with some special logic)
        if type_counts['.net'] > 0:
            return '.net'  # Prioritize .NET
        elif type_counts['flutter'] > 0:
            return 'flutter'  # Flutter is distinctive
        elif type_counts['php'] > 0:
            return 'php'
        elif type_counts['node'] > 0:
            return 'node'
        elif type_counts['java'] > 0:
            return 'java'
        elif type_counts['python'] > 0:
            return 'python'
        elif type_counts['static'] > 0:
            return 'static'
        
        return "unknown"

class NetworkScanner:
    """
    Scanner for network hosts and services using nmap or native Windows tools.
    Detects cross-server dependencies such as middleware and databases.
    """
    
    def __init__(self):
        """Initialize the Network Scanner."""
        self.interesting_ports = [
            # Web/App servers
            80, 443, 8080, 8443, 
            # Databases
            1433, 3306, 5432, 27017, 6379, 
            # Middleware
            8000, 8088, 9000, 9090, 
            # Other common services
            21, 22, 25, 389, 636, 5672, 15672
        ]
        
        # Service identification patterns
        self.service_patterns = {
            "web": ["http", "https", "www"],
            "database": ["sql", "mysql", "postgres", "oracle", "mongodb", "redis", "db"],
            "middleware": ["jboss", "tomcat", "websphere", "weblogic", "middleware", "rabbitmq", "activemq"],
            "mail": ["smtp", "pop3", "imap", "mail", "exchange"],
            "file": ["ftp", "sftp", "smb", "cifs", "nfs"],
            "directory": ["ldap", "active directory", "ad"],
            "cache": ["redis", "memcached", "cache"]
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
                logger.info("Nmap not available, using native Windows tools")
                scan_results = self._scan_with_windows_tools(target_range)
            
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
        Scan network using nmap via subprocess.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Parsed nmap scan results
        """
        logger.debug(f"Scanning with nmap: {target_range}")
        
        ports_str = ",".join(map(str, self.interesting_ports))
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
    
    def _scan_with_windows_tools(self, target_range):
        """
        Scan network using native Windows tools (ping and netstat).
        This is a fallback for when nmap is not available.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Scan results
        """
        logger.debug(f"Scanning with Windows tools: {target_range}")
        results = {}
        
        # Extract network prefix and start/end hosts to scan
        if '/' in target_range:  # CIDR notation
            ip_base, prefix = target_range.split('/')
            prefix = int(prefix)
            parts = ip_base.split('.')
            
            # Convert to simpler range for class C networks
            if prefix == 24:
                # Scan a /24 network (e.g., 192.168.1.0/24)
                base_ip = '.'.join(parts[:3]) + '.'
                start_host, end_host = 1, 254
            else:
                logger.info(f"Only scanning first 20 hosts in {target_range} using Windows tools")
                base_ip = '.'.join(parts[:3]) + '.'
                start_host, end_host = 1, 20
        else:
            # Single IP address
            base_ip = '.'.join(target_range.split('.')[:3]) + '.'
            start_host, end_host = int(target_range.split('.')[-1]), int(target_range.split('.')[-1])
        
        # Scan hosts with ping
        for host in range(start_host, end_host + 1):
            ip = f"{base_ip}{host}"
            
            # Skip localhost
            if ip == "127.0.0.1":
                continue
                
            cmd = ["ping", "-n", "1", "-w", "100", ip]
            try:
                process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if "Reply from" in process.stdout:
                    # Host is up, try to resolve hostname
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass
                    
                    # Initialize host data
                    results[ip] = {
                        "hostname": hostname,
                        "tcp": {}
                    }
                    
                    # Scan ports on live host
                    for port in self.interesting_ports:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            # Port is open
                            service_name = self._guess_service_from_port(port)
                            results[ip]["tcp"][str(port)] = {
                                "state": "open",
                                "name": service_name,
                                "product": ""
                            }
                        sock.close()
            except Exception as e:
                logger.debug(f"Error scanning host {ip}: {e}")
        
        return results
    
    def _guess_service_from_port(self, port):
        """Guess the service name based on port number."""
        common_ports = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            80: "http",
            443: "https",
            1433: "ms-sql-server",
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
        This is a simplified parser for when the python-nmap module is not available.
        
        Args:
            xml_data (str): Nmap XML output
            
        Returns:
            dict: Parsed scan results
        """
        hosts = {}
        current_host = None
        current_port = None
        
        try:
            root = ET.fromstring(xml_data)
            
            for host_elem in root.findall('.//host'):
                # Get host IP
                addr_elem = host_elem.find(".//address[@addrtype='ipv4']")
                if addr_elem is not None:
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
            host_data (dict): Raw host data from nmap
            
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
        elif port in [1433, 3306, 5432, 27017, 6379]:
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
    parser = argparse.ArgumentParser(description='TechStackLens Collection Script')
    parser.add_argument('--scan-local', action='store_true',
                        help='Scan local IIS configuration')
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
        logger.info("Starting local IIS scan...")
        iis_scanner = IISScanner()
        iis_results = iis_scanner.scan()
        scan_results.update(iis_results)
        save_results(iis_results, output_dir, "iis_scan_results.json")
    
    if args.scan_network:
        if not args.network_range:
            local_ip = NetworkScanner()._get_local_ip()
            network_range = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            logger.info(f"No network range specified, using {network_range}")
        else:
            network_range = args.network_range
        
        logger.info(f"Starting network scan on range {network_range}...")
        network_scanner = NetworkScanner()
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
        print("  python collection_script.py --scan-local")
        print("  python collection_script.py --scan-network --network-range 192.168.1.0/24")
        print("  python collection_script.py --scan-local --scan-network --verbose")

if __name__ == "__main__":
    try:
        print("\nTechStackLens Collection Script")
        print("-------------------------------")
        main()
        print("\nCollection completed. Check the techstacklens_data directory for results.")
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print("\nScan interrupted. Partial results may have been saved.")
    except Exception as e:
        logger.error(f"Error in collection script: {e}", exc_info=True)
        print(f"\nAn error occurred: {e}")
        print("Check the logs for more details.")