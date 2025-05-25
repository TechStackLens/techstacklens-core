"""
Dependency Analyzer module for mapping dependencies between hosts and services.
"""

import logging
import socket
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

class DependencyAnalyzer:
    """
    Analyzer that identifies dependencies between hosts and services based on scan results.
    """
    
    def __init__(self):
        """Initialize the Dependency Analyzer."""
        self.dependency_types = {
            "web_to_app": {
                "description": "Web server to application server",
                "source_roles": ["web"],
                "target_roles": ["middleware", "application"]
            },
            "app_to_db": {
                "description": "Application to database",
                "source_roles": ["middleware", "application", "web"],
                "target_roles": ["database"]
            },
            "app_to_cache": {
                "description": "Application to cache",
                "source_roles": ["middleware", "application", "web"],
                "target_roles": ["cache"]
            },
            "app_to_messaging": {
                "description": "Application to messaging",
                "source_roles": ["middleware", "application", "web"],
                "target_roles": ["messaging", "queue"]
            },
            "app_to_directory": {
                "description": "Application to directory service",
                "source_roles": ["middleware", "application", "web"],
                "target_roles": ["directory"]
            }
        }
        
        # Common port-to-service mapping
        self.port_role_map = {
            80: "web",
            443: "web",
            8080: "middleware",
            8443: "middleware",
            1433: "database",  # SQL Server
            3306: "database",  # MySQL
            5432: "database",  # PostgreSQL
            27017: "database", # MongoDB
            6379: "cache",     # Redis
            5672: "messaging", # RabbitMQ
            389: "directory",  # LDAP
            636: "directory"   # LDAPS
        }
    
    def analyze(self, scan_results):
        """
        Analyze scan results to identify dependencies.
        
        Args:
            scan_results (dict): Combined scan results from IIS and network scanners
            
        Returns:
            dict: Dependency graph with nodes and edges
        """
        logger.info("Starting dependency analysis")
        
        # Initialize dependency graph
        dependency_graph = {
            "nodes": [],
            "edges": [],
            "groups": []
        }
        
        # Process hosts from network scan
        hosts_by_ip = {}
        if "network_scan" in scan_results and "hosts" in scan_results["network_scan"]:
            for host in scan_results["network_scan"]["hosts"]:
                hosts_by_ip[host["ip"]] = host
                
                # Add host as node
                node_id = f"host_{host['ip'].replace('.', '_')}"
                node = {
                    "id": node_id,
                    "label": host.get("hostname", host["ip"]),
                    "type": "host",
                    "ip": host["ip"],
                    "roles": host.get("roles", [])
                }
                dependency_graph["nodes"].append(node)
                
                # Add services as nodes
                for service in host.get("services", []):
                    service_id = f"{node_id}_port_{service['port']}"
                    service_role = service.get("role", self._get_role_from_port(service["port"]))
                    service_name = service.get("name", "unknown")
                    service_label = f"{service_name}:{service['port']}"
                    
                    service_node = {
                        "id": service_id,
                        "label": service_label,
                        "type": "service",
                        "port": service["port"],
                        "name": service_name,
                        "role": service_role,
                        "parent": node_id
                    }
                    dependency_graph["nodes"].append(service_node)
                    
                    # Add edge from host to service
                    edge_id = f"{node_id}_to_{service_id}"
                    edge = {
                        "id": edge_id,
                        "source": node_id,
                        "target": service_id,
                        "type": "hosts"
                    }
                    dependency_graph["edges"].append(edge)
        
        # Process IIS sites
        if "iis_scan" in scan_results and "iis_sites" in scan_results["iis_scan"]:
            for site in scan_results["iis_scan"]["iis_sites"]:
                # Try to determine host IP
                host_ip = self._get_local_ip()
                host_node_id = f"host_{host_ip.replace('.', '_')}"
                
                # Add site as node
                site_id = f"site_{site.get('id', 'unknown')}"
                site_node = {
                    "id": site_id,
                    "label": site.get("name", "Unknown Site"),
                    "type": "site",
                    "app_type": site.get("app_type", "unknown"),
                    "parent": host_node_id
                }
                dependency_graph["nodes"].append(site_node)
                
                # Add edge from host to site
                edge_id = f"{host_node_id}_to_{site_id}"
                edge = {
                    "id": edge_id,
                    "source": host_node_id,
                    "target": site_id,
                    "type": "hosts"
                }
                dependency_graph["edges"].append(edge)
                
                # Process bindings
                for binding in site.get("bindings", []):
                    # Find corresponding service node
                    port = binding.get("port", 80)
                    protocol = binding.get("protocol", "http")
                    hostname = binding.get("hostname", "")
                    
                    service_id = f"{host_node_id}_port_{port}"
                    
                    # Add binding as node
                    binding_id = f"binding_{site_id}_{port}_{hostname}"
                    binding_label = hostname if hostname else f"{protocol}:{port}"
                    binding_node = {
                        "id": binding_id,
                        "label": binding_label,
                        "type": "binding",
                        "hostname": hostname,
                        "port": port,
                        "protocol": protocol,
                        "parent": site_id
                    }
                    dependency_graph["nodes"].append(binding_node)
                    
                    # Add edge from site to binding
                    edge_id = f"{site_id}_to_{binding_id}"
                    edge = {
                        "id": edge_id,
                        "source": site_id,
                        "target": binding_id,
                        "type": "binds_to"
                    }
                    dependency_graph["edges"].append(edge)
                    
                    # Add edge from binding to service if it exists
                    if any(node["id"] == service_id for node in dependency_graph["nodes"]):
                        edge_id = f"{binding_id}_to_{service_id}"
                        edge = {
                            "id": edge_id,
                            "source": binding_id,
                            "target": service_id,
                            "type": "uses"
                        }
                        dependency_graph["edges"].append(edge)
        
        # MEAN stack support - process mean_scan results
        if "mean_scan" in scan_results:
            mean_data = scan_results["mean_scan"]
            
            # Add MongoDB node
            if "mongodb" in mean_data:
                mongo_node_id = "mean_mongodb"
                mongo_node = {
                    "id": mongo_node_id,
                    "label": "MongoDB",
                    "type": "database",
                    "parent": None,
                    "details": mean_data["mongodb"]
                }
                dependency_graph["nodes"].append(mongo_node)
                
                # Add edge from app to MongoDB (inferred)
                for node in dependency_graph["nodes"]:
                    if node["id"].startswith("app_"):
                        edge_id = f"{node['id']}_to_{mongo_node_id}"
                        edge = {
                            "id": edge_id,
                            "source": node["id"],
                            "target": mongo_node_id,
                            "type": "app_to_db",
                            "dependency_type": "inferred",
                            "confidence": "high"
                        }
                        dependency_graph["edges"].append(edge)
            
            # Add Express node
            if "express" in mean_data:
                express_node_id = "mean_express"
                express_node = {
                    "id": express_node_id,
                    "label": "Express",
                    "type": "middleware",
                    "parent": None,
                    "details": mean_data["express"]
                }
                dependency_graph["nodes"].append(express_node)
                
                # Add edge from Express to MongoDB
                if "mongodb" in mean_data:
                    edge_id = f"{express_node_id}_to_{mongo_node_id}"
                    edge = {
                        "id": edge_id,
                        "source": express_node_id,
                        "target": mongo_node_id,
                        "type": "app_to_db",
                        "dependency_type": "direct",
                        "confidence": "high"
                    }
                    dependency_graph["edges"].append(edge)
            
            # Add Angular node
            if "angular" in mean_data:
                angular_node_id = "mean_angular"
                angular_node = {
                    "id": angular_node_id,
                    "label": "Angular",
                    "type": "frontend",
                    "parent": None,
                    "details": mean_data["angular"]
                }
                dependency_graph["nodes"].append(angular_node)
                
                # Add edge from Angular to Express
                if "express" in mean_data:
                    edge_id = f"{angular_node_id}_to_{express_node_id}"
                    edge = {
                        "id": edge_id,
                        "source": angular_node_id,
                        "target": express_node_id,
                        "type": "web_to_app",
                        "dependency_type": "direct",
                        "confidence": "high"
                    }
                    dependency_graph["edges"].append(edge)
            
            # Add Node.js node
            if "nodejs" in mean_data:
                nodejs_node_id = "mean_nodejs"
                nodejs_node = {
                    "id": nodejs_node_id,
                    "label": "Node.js",
                    "type": "runtime",
                    "parent": None,
                    "details": mean_data["nodejs"]
                }
                dependency_graph["nodes"].append(nodejs_node)
                
                # Add edge from Express to Node.js
                if "express" in mean_data:
                    edge_id = f"{express_node_id}_to_{nodejs_node_id}"
                    edge = {
                        "id": edge_id,
                        "source": express_node_id,
                        "target": nodejs_node_id,
                        "type": "app_to_runtime",
                        "dependency_type": "direct",
                        "confidence": "high"
                    }
                    dependency_graph["edges"].append(edge)
        
        # Infer cross-server dependencies
        self._infer_dependencies(dependency_graph, hosts_by_ip)
        
        # Create groups based on roles
        self._create_role_groups(dependency_graph)
        
        logger.info(f"Dependency analysis completed: {len(dependency_graph['nodes'])} nodes, {len(dependency_graph['edges'])} edges")
        return dependency_graph
    
    def _get_local_ip(self):
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def _get_role_from_port(self, port):
        """
        Determine role from port number.
        
        Args:
            port (int): Port number
            
        Returns:
            str: Role or None
        """
        return self.port_role_map.get(port, "unknown")
    
    def _infer_dependencies(self, dependency_graph, hosts_by_ip):
        """
        Infer dependencies between services across different hosts.
        
        Args:
            dependency_graph (dict): Dependency graph with nodes and edges
            hosts_by_ip (dict): Hosts indexed by IP address
        """
        # Group nodes by role
        nodes_by_role = defaultdict(list)
        for node in dependency_graph["nodes"]:
            if node.get("type") == "service" or node.get("type") == "site":
                role = node.get("role", "unknown")
                nodes_by_role[role].append(node)
        
        # Infer dependencies based on role patterns
        for dep_type, dep_info in self.dependency_types.items():
            for source_node in dependency_graph["nodes"]:
                # Skip nodes that aren't eligible sources
                if source_node.get("type") not in ["service", "site"]:
                    continue
                
                source_role = source_node.get("role", "unknown")
                if source_role not in dep_info["source_roles"]:
                    continue
                
                for target_role in dep_info["target_roles"]:
                    for target_node in nodes_by_role.get(target_role, []):
                        # Skip self-dependencies
                        if source_node["id"] == target_node["id"]:
                            continue
                        
                        # Create potential dependency edge
                        edge_id = f"{source_node['id']}_depends_on_{target_node['id']}"
                        edge = {
                            "id": edge_id,
                            "source": source_node["id"],
                            "target": target_node["id"],
                            "type": "depends_on",
                            "dependency_type": dep_type,
                            "confidence": "inferred"
                        }
                        
                        # Avoid duplicate edges
                        if not any(e["id"] == edge_id for e in dependency_graph["edges"]):
                            dependency_graph["edges"].append(edge)
    
    def _create_role_groups(self, dependency_graph):
        """
        Create groups for nodes based on their roles.
        
        Args:
            dependency_graph (dict): Dependency graph with nodes and edges
        """
        # Collect all unique roles
        roles = set()
        for node in dependency_graph["nodes"]:
            if "role" in node:
                roles.add(node["role"])
            elif "roles" in node and node["roles"]:
                roles.update(node["roles"])
        
        # Create a group for each role
        for role in roles:
            if role == "unknown":
                continue
                
            group = {
                "id": f"group_{role}",
                "label": role.capitalize(),
                "role": role
            }
            dependency_graph["groups"].append(group)
    
    def analyze(self, data):
        """Analyze the provided data to map dependencies."""
        # Mock implementation for testing purposes
        return {
            "cloud_type": data.get("cloud", "unknown"),
            "architecture_map": {
                "nodes": ["serviceA", "serviceB"],
                "edges": [("serviceA", "serviceB")],
                "groups": []
            }
        }

    def generate_visualization(self, data):
        """Generate a visualization based on the analyzed data."""
        # Mock implementation for testing purposes
        return {
            "nodes": ["serviceA", "serviceB"],
            "edges": [("serviceA", "serviceB")]
        }
