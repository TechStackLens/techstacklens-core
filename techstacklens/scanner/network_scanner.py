"""
Network Scanner module for discovering hosts and services on the network.
Uses python-nmap to perform lightweight scans.
"""

import os
import socket
import logging
import subprocess
import json
from datetime import datetime

# Try to import python-nmap, with fallback to using subprocess directly
try:
    import nmap
    NMAP_MODULE_AVAILABLE = True
except ImportError:
    NMAP_MODULE_AVAILABLE = False

logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    Scanner for network hosts and services using nmap.
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
            if NMAP_MODULE_AVAILABLE:
                scan_results = self._scan_with_module(target_range)
            else:
                scan_results = self._scan_with_subprocess(target_range)
            
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
    
    def _scan_with_module(self, target_range):
        """
        Scan network using python-nmap module.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Raw nmap scan results
        """
        logger.debug(f"Scanning with python-nmap module: {target_range}")
        nm = nmap.PortScanner()
        
        # Convert list of ports to string for nmap
        ports_str = ",".join(map(str, self.interesting_ports))
        
        # Perform scan with service detection (-sV) but limit intensity (--version-intensity 2)
        arguments = f"-sV --version-intensity 2 -p {ports_str} --open"
        logger.debug(f"Nmap arguments: {arguments}")
        
        try:
            nm.scan(hosts=target_range, arguments=arguments)
            return nm.all_hosts()
        except Exception as e:
            logger.error(f"Error in nmap scan: {e}")
            return {}
    
    def _scan_with_subprocess(self, target_range):
        """
        Scan network using nmap via subprocess when python-nmap is not available.
        
        Args:
            target_range (str): Network range to scan
            
        Returns:
            dict: Parsed nmap scan results
        """
        logger.debug(f"Scanning with nmap subprocess: {target_range}")
        
        # Check if nmap is available
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            logger.error("Nmap not found. Please install nmap or python-nmap.")
            return {}
        
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
    
    def _parse_nmap_xml(self, xml_data):
        """
        Parse nmap XML output to dict structure.
        This is a simplified parser for when python-nmap is not available.
        
        Args:
            xml_data (str): Nmap XML output
            
        Returns:
            dict: Parsed scan results
        """
        # Very simple XML parsing - in a real implementation, use xml.etree.ElementTree
        hosts = {}
        current_host = None
        current_port = None
        
        for line in xml_data.splitlines():
            if "<host " in line:
                current_host = {}
            elif "<address addr=" in line and "addrtype=\"ipv4\"" in line:
                addr = line.split("addr=\"")[1].split("\"")[0]
                current_host["ip"] = addr
                hosts[addr] = {"tcp": {}}
            elif "<hostname name=" in line:
                hostname = line.split("name=\"")[1].split("\"")[0]
                hosts[current_host["ip"]]["hostname"] = hostname
            elif "<port protocol=" in line:
                portid = line.split("portid=\"")[1].split("\"")[0]
                current_port = portid
                hosts[current_host["ip"]]["tcp"][portid] = {}
            elif "<state state=" in line and "open" in line:
                hosts[current_host["ip"]]["tcp"][current_port]["state"] = "open"
            elif "<service name=" in line:
                service = line.split("name=\"")[1].split("\"")[0]
                hosts[current_host["ip"]]["tcp"][current_port]["name"] = service
                if "product=" in line:
                    product = line.split("product=\"")[1].split("\"")[0]
                    hosts[current_host["ip"]]["tcp"][current_port]["product"] = product
        
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
