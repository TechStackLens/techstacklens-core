#!/usr/bin/env python3
"""
TechStackLens - A lightweight IT assessment tool designed to scan environments,
map dependencies, and visualize flows for solution architects.
"""

from web_app import app

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
