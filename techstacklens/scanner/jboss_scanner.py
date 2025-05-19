import os
import re
import xml.etree.ElementTree as ET
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class JBossScanner:
    """
    Scanner for JBoss/WildFly server configurations and deployed applications.
    """
    def __init__(self, jboss_base=None):
        self.jboss_base = jboss_base or os.environ.get('JBOSS_HOME', '/opt/jboss')
        self.standalone_xml = os.path.join(self.jboss_base, 'standalone', 'configuration', 'standalone.xml')
        self.deployments_dir = os.path.join(self.jboss_base, 'standalone', 'deployments')

    def scan(self):
        logger.info(f"Scanning JBoss/WildFly at {self.jboss_base}")
        results = {
            "timestamp": datetime.now().isoformat(),
            "jboss_base": self.jboss_base,
            "ports": self._scan_ports(),
            "apps": self._scan_deployments(),
        }
        return {"jboss_scan": results}

    def _scan_ports(self):
        ports = []
        if not os.path.exists(self.standalone_xml):
            logger.warning(f"standalone.xml not found at {self.standalone_xml}")
            return ports
        try:
            tree = ET.parse(self.standalone_xml)
            root = tree.getroot()
            for socket_binding in root.iter('socket-binding'):
                port = socket_binding.get('port')
                name = socket_binding.get('name')
                ports.append({"name": name, "port": port})
        except Exception as e:
            logger.error(f"Error parsing standalone.xml: {e}")
        return ports

    def _scan_deployments(self):
        apps = []
        if not os.path.exists(self.deployments_dir):
            logger.warning(f"deployments directory not found at {self.deployments_dir}")
            return apps
        for entry in os.listdir(self.deployments_dir):
            app_path = os.path.join(self.deployments_dir, entry)
            if os.path.isdir(app_path):
                apps.append({"name": entry, "path": app_path})
            elif entry.endswith(('.war', '.ear', '.jar')):
                apps.append({"name": entry, "type": os.path.splitext(entry)[1][1:], "path": app_path})
        return apps
