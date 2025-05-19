# Contributing to TechStackLens

Thank you for your interest in contributing to TechStackLens! We welcome contributions of all kinds, including bug reports, feature requests, code, and documentation improvements.

## How to Contribute

1. **Fork the repository** and create your branch from `main`.
2. **Write clear, concise commit messages**.
3. **Add tests** for new features or bug fixes when possible.
4. **Run linting and ensure code quality** before submitting a pull request.
5. **Open a pull request** with a clear description of your changes.

## Project Structure

- `techstacklens/` — Core Python package
  - `scanner/` — Stack-specific and network scanners
  - `analyzer/` — Dependency analysis logic
  - `visualizer/` — Graph generation and visualization
  - `reporter/` — Report generation
  - `utils/` — Shared utilities
- `templates/` — HTML templates for the web UI
- `static/` — Static assets (CSS, JS)
- `main.py`, `web_app.py` — Entrypoints for CLI and web app
- `collection_script.py`, `lamp_scanner.py`, `cloud_scanner.py`, `xampp_scanner.py` — Standalone scanner scripts
- `dist/` — Pre-built scanner packages for distribution
- `attached_assets/` — Design docs and other assets

## Code Style
- Follow [PEP8](https://www.python.org/dev/peps/pep-0008/) for Python code.
- Use descriptive variable and function names.
- Document public functions and classes with docstrings.

## Reporting Issues
- Use [GitHub Issues](https://github.com/your-repo/issues) to report bugs or request features.
- Provide as much detail as possible, including steps to reproduce and environment info.

## Community
- Be respectful and inclusive.
- See the [Code of Conduct](CODE_OF_CONDUCT.md) for more details (if available).

---

Thank you for helping make TechStackLens better!
