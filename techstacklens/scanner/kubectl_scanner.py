import subprocess
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class KubectlScanner:
    """
    Scanner for Kubernetes clusters using kubectl.
    """
    def __init__(self, context=None):
        self.context = context

    def scan(self):
        logger.info("Scanning Kubernetes cluster using kubectl")
        results = {
            "timestamp": datetime.now().isoformat(),
            "context": self.context,
            "pods": self._get_resource('pods'),
            "services": self._get_resource('services'),
            "ingress": self._get_resource('ingress'),
        }
        return {"kubernetes_scan": results}

    def _get_resource(self, resource):
        cmd = ["kubectl", "get", resource, "-o", "json"]
        if self.context:
            cmd += ["--context", self.context]
        try:
            output = subprocess.check_output(cmd, text=True)
            return json.loads(output)
        except Exception as e:
            logger.error(f"Error running {' '.join(cmd)}: {e}")
            return []
