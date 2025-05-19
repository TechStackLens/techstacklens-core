import os
import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class NodejsScanner:
    """
    Scanner for Node.js/Express applications.
    """
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.getcwd()

    def scan(self):
        logger.info(f"Scanning Node.js/Express apps in {self.base_dir}")
        results = {
            "timestamp": datetime.now().isoformat(),
            "base_dir": self.base_dir,
            "apps": self._scan_apps(),
        }
        return {"nodejs_scan": results}

    def _scan_apps(self):
        apps = []
        for root, dirs, files in os.walk(self.base_dir):
            if 'package.json' in files:
                app_info = self._parse_package_json(os.path.join(root, 'package.json'))
                app_info['path'] = root
                # Detect common entry points
                for entry in ['server.js', 'app.js', 'index.js']:
                    if entry in files:
                        app_info['entry_point'] = entry
                        break
                apps.append(app_info)
        return apps

    def _parse_package_json(self, path):
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return {
                "name": data.get("name", "unknown"),
                "dependencies": list(data.get("dependencies", {}).keys()),
                "devDependencies": list(data.get("devDependencies", {}).keys()),
                "scripts": data.get("scripts", {}),
            }
        except Exception as e:
            logger.error(f"Error parsing {path}: {e}")
            return {"name": "unknown", "dependencies": [], "devDependencies": [], "scripts": {}}
