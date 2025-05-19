import subprocess
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class DockerScanner:
    """
    Scanner for Docker containers and images.
    """
    def scan(self):
        logger.info("Scanning Docker containers and images")
        results = {
            "timestamp": datetime.now().isoformat(),
            "containers": self._get_containers(),
            "images": self._get_images(),
        }
        return {"docker_scan": results}

    def _get_containers(self):
        try:
            output = subprocess.check_output(["docker", "ps", "-a", "--format", "{{json .}}"], text=True)
            containers = [json.loads(line) for line in output.strip().splitlines() if line.strip()]
            return containers
        except Exception as e:
            logger.error(f"Error running docker ps: {e}")
            return []

    def _get_images(self):
        try:
            output = subprocess.check_output(["docker", "images", "--format", "{{json .}}"], text=True)
            images = [json.loads(line) for line in output.strip().splitlines() if line.strip()]
            return images
        except Exception as e:
            logger.error(f"Error running docker images: {e}")
            return []
