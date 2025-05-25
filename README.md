# TechStackLens

TechStackLens is a lightweight, open-source IT assessment tool designed for solution architects to scan environments, map dependencies, and visualize flows. It supports Windows-IIS stacks (MVP) and is designed for modular extension (LAMP, cloud, etc.).

## Features

- **Scanner Kit**: Collects configuration and network data for different stacks (Windows-IIS, LAMP, XAMPP, Cloud)
- **Analyzer**: Identifies dependencies and gaps from scanner output
- **Visualizer**: Interactive dependency maps
- **Report Generator**: Creates actionable reports
- **Script Generator**: The web UI now uses `techstacklens.scanner.script_generator` to generate standalone scanner scripts (PowerShell or Python) based on selected stacks. This logic is fully modular and can be reused in other interfaces.

## Quick Start

1. Clone this repository
2. Install dependencies: `pip install -r requirements.txt` or use `pyproject.toml`
3. Use the web UI to generate a custom scanner script for your environment (select the stacks you want to scan)
4. Run the generated script on your target system (see script usage for CLI options)
5. Upload the generated JSON results to the web app (`python web_app.py`)
6. Analyze, visualize, and generate reports via the web UI

## Scanner Output Format

- The generated scanner script outputs a single JSON file with a top-level dictionary. Each key corresponds to a scan type (e.g., `network_scan`, `iis_scan`, `lamp_scan`, etc.).
- This format is required for analysis and reporting.

## Project Structure

- `techstacklens/` — Core package (scanner, analyzer, visualizer, reporter, utils)
  - `scanner/` — All stack/network scanner modules: `iis_scanner.py`, `network_scanner.py`, `lamp_scanner.py`, `xampp_scanner.py`, `cloud_scanner.py`, `tomcat_scanner.py`, `jboss_scanner.py`, `nodejs_scanner.py`, `react_scanner.py`, `kubectl_scanner.py`, `docker_scanner.py`
  - `scanner/script_generator.py` — Script generation logic for custom scanner scripts (PowerShell/Python)
- `templates/` — Web UI HTML templates
- `static/` — CSS/JS assets
- `main.py`, `web_app.py` — Entrypoints
- `scanners/` — (Optional) Thin entry-point scripts for distribution (see below)
- `dist/` — Pre-built scanner packages
- `attached_assets/` — Design docs

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE).

---

For more on common technology stacks ("TechStacks"), see [Webopedia: Web Stack Acronyms and Definitions](https://www.webopedia.com/reference/webstack-acronyms/).

## TODO / Roadmap

- Expand support to additional technology stacks (see [Webopedia reference](https://www.webopedia.com/reference/webstack-acronyms/))
- Make it easy to add new stack scanners and extend the platform for future technologies
- Improve plugin/extensibility model for custom scanning and reporting
- Enhance documentation and onboarding for contributors
