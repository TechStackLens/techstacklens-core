import os
import re
import xml.etree.ElementTree as ET
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class TomcatScanner:
    """
    Scanner for Apache Tomcat server configurations and deployed applications.
    """
    def __init__(self, tomcat_base=None):
        self.tomcat_base = tomcat_base or os.environ.get('CATALINA_HOME', '/opt/tomcat')
        self.server_xml = os.path.join(self.tomcat_base, 'conf', 'server.xml')
        self.webapps_dir = os.path.join(self.tomcat_base, 'webapps')

    def scan(self):
        logger.info(f"Scanning Tomcat at {self.tomcat_base}")
        results = {
            "timestamp": datetime.now().isoformat(),
            "tomcat_base": self.tomcat_base,
            "ports": self._scan_ports(),
            "apps": self._scan_webapps(),
        }
        return {"tomcat_scan": results}

    def _scan_ports(self):
        ports = []
        if not os.path.exists(self.server_xml):
            logger.warning(f"server.xml not found at {self.server_xml}")
            return ports
        try:
            tree = ET.parse(self.server_xml)
            root = tree.getroot()
            for connector in root.iter('Connector'):
                port = connector.get('port')
                protocol = connector.get('protocol', 'HTTP/1.1')
                ports.append({"port": port, "protocol": protocol})
        except Exception as e:
            logger.error(f"Error parsing server.xml: {e}")
        return ports

    def _scan_webapps(self):
        apps = []
        if not os.path.exists(self.webapps_dir):
            logger.warning(f"webapps directory not found at {self.webapps_dir}")
            return apps
        for entry in os.listdir(self.webapps_dir):
            app_path = os.path.join(self.webapps_dir, entry)
            if os.path.isdir(app_path):
                apps.append({"name": entry, "path": app_path})
            elif entry.endswith('.war'):
                apps.append({"name": entry, "type": "war", "path": app_path})
        return apps
