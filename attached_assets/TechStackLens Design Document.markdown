# TechStackLens Design Document

## 1. Introduction
TechStackLens is a lightweight, open-source IT assessment tool designed to scan environments, map dependencies, and visualize flows for solution architects. Built anonymously in public, it starts with a Windows-IIS stack for the MVP, with plans to support LAMP and other stacks via a modular scanner kit. It targets small on-premises data centers and single cloud accounts, with potential integration under Hartis Consulting if successful.

## 2. System Overview
The tool is a kit of modular components, with stack-specific scanners and shared analysis/visualization:
- **Scanner Kit**: Stack-specific tools (e.g., Windows-IIS, LAMP) to collect configuration and network data.
- **Analyzer**: Identifies dependencies and gaps from scanner output.
- **Visualizer**: Displays interactive dependency maps.
- **Solution Engine**: Proposes architectural improvements.
- **Report Generator**: Creates actionable reports.

## 3. Functional Requirements
### 3.1. Scanner Kit
- **Windows-IIS Scanner (MVP)**:
  - Run on IIS servers with admin access to read `applicationHost.config` for SNI hostnames and `web.config` for app types (Flutter, .NET).
  - Lightweight `nmap` scan for cross-server dependencies (e.g., middleware on 8080, databases on 1433).
  - Output JSON with hosts, ports, services, SNI sites, and app types.
- **LAMP Scanner**:
  - Parse Apache `httpd.conf` and virtual host files for site hostnames.
  - Extract MySQL connection details from PHP configs (e.g., `wp-config.php`).
  - Use `nmap` for cross-server dependencies.
  - Output JSON with hosts, services, virtual hosts, and detected app types.
- **XAMPP Scanner**:
  - Detect XAMPP stack (Apache, MySQL, PHP, Perl) on Windows or Linux.
  - Identify ELT/ETL tools (e.g., Talend, Informatica, Pentaho, Airflow, Nifi).
  - Output JSON with stack components, virtual hosts, and ELT tools.
- **Cloud Infrastructure Scanner**:
  - Scan AWS, Azure, and GCP environments using their respective CLI tools.
  - Collect inventory of VMs, databases, storage, and networking resources.
  - Output JSON with cloud resources and relationships.
- **Tomcat/JBoss/Java App Server Scanner (Planned)**:
  - Parse Tomcat/JBoss/WildFly configuration files for deployed apps and ports.
  - Detect Java web applications, middleware, and database connections.
  - Output JSON with app server deployments and dependencies.
- **Node.js/Express/React Scanner**:
  - Scan for Node.js/Express apps by detecting `package.json`, entry points, and dependencies.
  - Detect React apps by checking for `react` in dependencies.
  - Output JSON with app details, dependencies, and scripts.
- **Kubernetes Scanner**:
  - Use `kubectl` to inventory pods, services, and ingress resources.
  - Output JSON with cluster resources and relationships.
- **Docker Scanner**:
  - List running containers and images using the Docker CLI.
  - Output JSON with container/image metadata and exposed ports.
- **Other Technologies (Future)**:
  - Nginx/Node.js/Express: Parse configs, detect running apps and ports.
  - Kubernetes: Use `kubectl` to inventory pods, services, and ingress.
  - Docker: List running containers, images, and exposed ports.
  - Microsoft SQL Server, Oracle, PostgreSQL: Inventory databases and connection strings.
  - Add plugin architecture for easy extension to new stacks.
- **Dynamic Scanner Generation**: The web UI allows users to select compatible stacks and generate a custom scanner script. The script outputs a single JSON file with a top-level dictionary, where each key is a scan type (e.g., `network_scan`, `iis_scan`, `lamp_scan`, etc.).

- Support plugin architecture for adding new stack scanners.

### 3.2. Analyzer
- Map dependencies based on scanner output (e.g., Web → Middleware → Database).
- For Windows-IIS: Use SNI hostnames and port data to map site-specific dependencies.
- Apply basic Well-Architected Framework principles (reliability, security).
- **Analyzer/Reporter**: The analyzer and report generator process this combined JSON format, supporting modular extension as new scanners are added.

### 3.3. Visualizer
- Generate static graphs (Graphviz) showing hosts and SNI sites with dependencies.
- Label nodes with roles (Web, Middleware, Database) and app types (e.g., Flutter, .NET).
- Allow filtering by host or connection type (future web-based views).

### 3.4. Solution Engine
- Suggest fixes (e.g., close unused ports, add redundancy).
- Provide Infrastructure as Code (IaC) templates (e.g., Terraform).

### 3.5. Report Generator
- Produce PDF or HTML reports with assessment summary, issues, and solutions.

## 4. System Architecture
- **Data Flow**: Scanners output JSON to a shared in-memory store. Analyzer processes into a dependency graph. Visualizer and Solution Engine query the graph, and Report Generator compiles outputs.
- **Modularity**: Scanners are independent, with standardized JSON output. Other components (Analyzer, Visualizer) are stack-agnostic.

## 5. Technical Design
### 5.1. Scanner Kit
- **Windows-IIS Scanner**:
  - **Tools**: Python with `xml.etree.ElementTree` for IIS configs, `nmap` for network scanning.
  - **Input**: Local `applicationHost.config`, `web.config`, network range.
  - **Output**: JSON with host IP, ports, services, SNI sites (hostnames, app types).
- **LAMP Scanner (Planned)**:
  - **Tools**: Python with `configparser` for Apache configs, `nmap` for network.
  - **Input**: Apache configs, PHP files, network range.
  - **Output**: JSON with similar structure.

### 5.2. Analyzer
- **Logic**: Parse JSON to build a dependency graph (e.g., SNI sites → Middleware → Database).
- **Storage**: In-memory JSON for MVP; Neo4j for future phases.

### 5.3. Visualizer
- **Tech**: Python with `Graphviz` for static graphs; React/D3.js for future web interface.
- **Features**: Show hosts, SNI sites (sub-nodes), and dependencies with role/app labels.

### 5.4. Solution Engine
- **Approach**: Rule-based suggestions with pre-built IaC templates.
- **Output**: Text or IaC files.

### 5.5. Report Generator
- **Method**: Python with `reportlab` for PDF; Jinja2 for HTML.
- **Content**: Summary, issues, solutions.

## 6. User Experience
- **Workflow**: Run scanner on target server → Analyze dependencies → View graph → Review solutions → Generate report.
- **Interface**: Command-line for MVP; web dashboard in later phases.

## 7. Technology Stack
- **Language**: Python (core), JavaScript (future web).
- **Libraries**: `nmap`, `Graphviz`, `xml.etree.ElementTree`, `reportlab`, React, D3.js.
- **License**: MIT for open-source collaboration.

## 8. MVP Scope
- Windows-IIS scanner: Extract SNI hostnames and app types (Flutter, .NET) from IIS configs, scan network with `nmap`.
- Generate static dependency graph with `Graphviz`.
- Release by May 23, 2025.

## 9. Challenges and Mitigations
- **Config Parsing Errors**: Validate XML/config files; fallback to manual hostname input.
- **Performance**: Optimize for small environments; limit `nmap` to key ports.
- **Adoption**: Promote via Twitter and GitHub.

## 10. Future Roadmap
- **Phase 2 (May 23-June 6, 2025)**: Add cloud scanning (Azure) and LAMP scanner.
- **Phase 3 (June 6-July 4, 2025)**: Integrate Well-Architected analysis, IaC, and connection string parsing for database dependencies.
- **Phase 4 (July 4 onward)**: Add chatbot and multi-cloud support (AWS, GCP).
`````