import os
import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class ReactScanner:
    """
    Scanner for React applications (standalone or as part of Node.js projects).
    """
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.getcwd()

    def scan(self):
        logger.info(f"Scanning React apps in {self.base_dir}")
        results = {
            "timestamp": datetime.now().isoformat(),
            "base_dir": self.base_dir,
            "apps": self._scan_apps(),
        }
        return {"react_scan": results}

    def _scan_apps(self):
        apps = []
        for root, dirs, files in os.walk(self.base_dir):
            if 'package.json' in files:
                package_path = os.path.join(root, 'package.json')
                if self._is_react_app(package_path):
                    app_info = self._parse_package_json(package_path)
                    app_info['path'] = root
                    apps.append(app_info)
        return apps

    def _is_react_app(self, package_path):
        try:
            with open(package_path, 'r') as f:
                data = json.load(f)
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})
            return 'react' in deps or 'react' in dev_deps
        except Exception as e:
            logger.error(f"Error parsing {package_path}: {e}")
            return False

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
