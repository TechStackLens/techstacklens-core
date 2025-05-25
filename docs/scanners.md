# TechStackLens Scanner Components

This document tracks the status and purpose of scanner components in TechStackLens.

## Overview

TechStackLens supports scanning a variety of technology stacks. Each scanner is implemented as a Python module in `techstacklens/scanner/` and can be used to generate custom entry-point scripts for distribution or direct use.

## Available Scanners

- **IIS Scanner** (`iis_scanner.py`): Scans Windows IIS configurations and bindings.
- **Network Scanner** (`network_scanner.py`): Scans network hosts and services.
- **LAMP Scanner** (`lamp_scanner.py`): Scans Apache, MySQL, and PHP on Linux systems.
- **Cloud Scanner** (`cloud_scanner.py`): Scans AWS, Azure, and GCP environments.
- **XAMPP Scanner** (`xampp_scanner.py`): Scans XAMPP stack environments (Apache, MySQL, PHP, Perl).
- **Tomcat Scanner** (`tomcat_scanner.py`): Scans Apache Tomcat server configs and deployed webapps.
- **JBoss Scanner** (`jboss_scanner.py`): Scans JBoss/WildFly configs and deployments.
- **Node.js/Express Scanner** (`nodejs_scanner.py`): Scans for Node.js/Express apps and dependencies.
- **React Scanner** (`react_scanner.py`): Scans for React apps and their dependencies.
- **Kubernetes Scanner** (`kubectl_scanner.py`): Uses `kubectl` to inventory pods, services, and ingress.
- **Docker Scanner** (`docker_scanner.py`): Lists running containers and images.

## JSON Output Format

- The generated scanner script outputs a single JSON file with a top-level dictionary. Each key corresponds to a scan type, e.g.:

```json
{
  "network_scan": { ... },
  "iis_scan": { ... },
  "lamp_scan": { ... },
  "cloud_scan": { ... },
  "tomcat_scan": { ... },
  "jboss_scan": { ... },
  "xampp_scan": { ... },
  "nodejs_scan": { ... },
  "react_scan": { ... },
  "kubectl_scan": { ... },
  "docker_scan": { ... }
}
```

- Each scan module is responsible for returning its results under a unique key (e.g., `network_scan`, `tomcat_scan`).
- The analyzer and report generator expect this structure for all uploaded scan results.

## Usage

- Use the web UI to generate a custom scanner script tailored to your environment. The script will import only the relevant scanner modules.
- The `scanners/` folder is now reserved for thin entry-point scripts if needed for packaging, but is not required for most users.

## Status

- All core scanning logic is maintained in `techstacklens/scanner/` for modularity and reuse.
- The script generation logic is now in `techstacklens/scanner/script_generator.py` and is used by the web UI to generate standalone scanner scripts (PowerShell or Python) based on user selection.
- Additional stack scanners (e.g., Tomcat, JBoss) can be added as new modules.

---

For more details, see the main [README.md](../README.md) and the [TechStackLens Design Document](../attached_assets/TechStackLens%20Design%20Document.markdown)
