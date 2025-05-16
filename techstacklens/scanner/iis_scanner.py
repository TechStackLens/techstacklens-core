"""
IIS Scanner module for extracting information from IIS configuration files.
"""

import os
import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger(__name__)

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
                        if sni_element is not None and "sni" in sni_element.text.lower():
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
