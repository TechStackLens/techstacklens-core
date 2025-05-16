#!/usr/bin/env python3
"""
TechStackLens Web Application - A web interface for TechStackLens tool.

This Flask application provides a user-friendly interface for running
scans, visualizing dependencies, and viewing reports.
"""

import os
import sys
import json
import logging
import tempfile
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file

from techstacklens.scanner.iis_scanner import IISScanner
from techstacklens.scanner.network_scanner import NetworkScanner
from techstacklens.analyzer.dependency_analyzer import DependencyAnalyzer
from techstacklens.visualizer.graph_generator import GraphGenerator
from techstacklens.reporter.report_generator import ReportGenerator
from techstacklens.utils.helpers import (
    is_admin, check_nmap_installed, get_local_ip, ensure_directory, validate_ip_range
)

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "techstacklens_secret_key")

# Ensure output directory exists
OUTPUT_DIR = Path("output")
ensure_directory(OUTPUT_DIR)

# Global state to store scan results
scan_state = {
    "iis_scan_results": None,
    "network_scan_results": None,
    "aws_scan_results": None,
    "azure_scan_results": None,
    "gcp_scan_results": None,
    "lamp_scan_results": None,
    "combined_results": None,
    "dependency_graph": None,
    "visualization_path": None,
    "report_path": None
}

@app.route('/')
def index():
    """Render the main page."""
    local_ip = get_local_ip()
    admin_status = is_admin()
    nmap_installed = check_nmap_installed()
    
    scan_completed = scan_state["iis_scan_results"] is not None or scan_state["network_scan_results"] is not None
    analysis_completed = scan_state["dependency_graph"] is not None
    report_generated = scan_state["report_path"] is not None
    
    return render_template('index.html', 
                          local_ip=local_ip,
                          admin_status=admin_status,
                          nmap_installed=nmap_installed,
                          scan_completed=scan_completed,
                          analysis_completed=analysis_completed,
                          report_generated=report_generated)

@app.route('/scan', methods=['POST'])
def run_scan():
    """Run a scan based on user input."""
    scan_type = request.form.get('scan_type')
    
    if scan_type == 'iis':
        # Run IIS scan
        try:
            iis_scanner = IISScanner()
            results = iis_scanner.scan()
            scan_state["iis_scan_results"] = results
            
            # Save results to file
            with open(OUTPUT_DIR / "iis_scan_results.json", 'w') as f:
                json.dump(results, f, indent=2)
            
            flash("IIS scan completed successfully", "success")
        except Exception as e:
            logger.error(f"Error during IIS scan: {e}")
            flash(f"Error during IIS scan: {e}", "danger")
    
    elif scan_type == 'network':
        network_range = request.form.get('network_range')
        
        if not network_range:
            flash("Network range is required for network scan", "danger")
            return redirect(url_for('index'))
        
        if not validate_ip_range(network_range):
            flash("Invalid network range format", "danger")
            return redirect(url_for('index'))
        
        try:
            network_scanner = NetworkScanner()
            results = network_scanner.scan(network_range)
            scan_state["network_scan_results"] = results
            
            # Save results to file
            with open(OUTPUT_DIR / "network_scan_results.json", 'w') as f:
                json.dump(results, f, indent=2)
            
            flash("Network scan completed successfully", "success")
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            flash(f"Error during network scan: {e}", "danger")
    
    else:
        flash("Invalid scan type", "danger")
    
    return redirect(url_for('index'))

@app.route('/analyze', methods=['POST'])
def analyze_dependencies():
    """Analyze dependencies from scan results."""
    # Check if we have combined results from multiple file uploads
    if scan_state.get("combined_results"):
        combined_results = scan_state["combined_results"]
    else:
        # Otherwise, build combined results from individual scans
        combined_results = {}
        
        # Check all possible scan types
        scan_types = [
            "iis_scan_results", 
            "network_scan_results", 
            "aws_scan_results", 
            "azure_scan_results", 
            "gcp_scan_results", 
            "lamp_scan_results"
        ]
        
        for scan_type in scan_types:
            if scan_state.get(scan_type):
                combined_results.update(scan_state[scan_type])
    
    if not combined_results:
        flash("No scan results available for analysis. Please upload scan data first.", "danger")
        return redirect(url_for('index'))
    
    try:
        analyzer = DependencyAnalyzer()
        dependency_graph = analyzer.analyze(combined_results)
        scan_state["dependency_graph"] = dependency_graph
        
        # Save analysis results
        with open(OUTPUT_DIR / "dependency_analysis.json", 'w') as f:
            json.dump(dependency_graph, f, indent=2)
        
        # Generate visualization
        visualizer = GraphGenerator()
        graph_path = OUTPUT_DIR / "dependency_graph"
        visualizer.generate(dependency_graph, str(graph_path))
        scan_state["visualization_path"] = f"{graph_path}.html"
        
        # Count analyzed resources
        node_count = len(dependency_graph.get("nodes", []))
        edge_count = len(dependency_graph.get("edges", []))
        
        flash(f"Dependency analysis completed successfully: {node_count} nodes and {edge_count} relationships mapped", "success")
    except Exception as e:
        logger.error(f"Error during dependency analysis: {e}")
        flash(f"Error during dependency analysis: {e}", "danger")
    
    return redirect(url_for('index'))

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate a report from scan and analysis results."""
    combined_results = {}
    
    if scan_state["iis_scan_results"]:
        combined_results.update(scan_state["iis_scan_results"])
    
    if scan_state["network_scan_results"]:
        combined_results.update(scan_state["network_scan_results"])
    
    if not combined_results:
        flash("No scan results available for report generation", "danger")
        return redirect(url_for('index'))
    
    if not scan_state["dependency_graph"]:
        flash("No dependency analysis available for report generation", "danger")
        return redirect(url_for('index'))
    
    try:
        reporter = ReportGenerator()
        report_path = OUTPUT_DIR / "techstacklens_report.pdf"
        reporter.generate_report(combined_results, scan_state["dependency_graph"], str(report_path))
        
        # Store HTML report path
        html_report_path = OUTPUT_DIR / "techstacklens_report.html"
        if os.path.exists(html_report_path):
            scan_state["report_path"] = str(html_report_path)
        else:
            scan_state["report_path"] = str(report_path)
        
        flash("Report generated successfully", "success")
    except Exception as e:
        logger.error(f"Error during report generation: {e}")
        flash(f"Error during report generation: {e}", "danger")
    
    return redirect(url_for('index'))

@app.route('/results')
def view_results():
    """View scan results."""
    # Combine scan results
    combined_results = {}
    
    if scan_state["iis_scan_results"]:
        combined_results.update(scan_state["iis_scan_results"])
    
    if scan_state["network_scan_results"]:
        combined_results.update(scan_state["network_scan_results"])
    
    if not combined_results:
        flash("No scan results available", "danger")
        return redirect(url_for('index'))
    
    return render_template('results.html', results=combined_results)

@app.route('/visualization')
def view_visualization():
    """View dependency visualization."""
    if not scan_state["dependency_graph"]:
        flash("No dependency analysis available", "danger")
        return redirect(url_for('index'))
    
    # If we have an HTML visualization, use it
    if scan_state["visualization_path"] and os.path.exists(scan_state["visualization_path"]):
        # Read the HTML content
        with open(scan_state["visualization_path"], 'r') as f:
            html_content = f.read()
        return render_template('visualization.html', html_content=html_content)
    
    # Otherwise, fall back to displaying the JSON
    return render_template('visualization.html', graph_data=json.dumps(scan_state["dependency_graph"]))

@app.route('/report')
def view_report():
    """View generated report."""
    if not scan_state["report_path"]:
        flash("No report has been generated", "danger")
        return redirect(url_for('index'))
    
    report_path = scan_state["report_path"]
    
    # If it's an HTML report, embed it
    if report_path.endswith('.html'):
        with open(report_path, 'r') as f:
            html_content = f.read()
        return render_template('report.html', html_content=html_content)
    
    # If it's a PDF, offer download
    return render_template('report.html', report_path=os.path.basename(report_path))

@app.route('/download/<path:filename>')
def download_file(filename):
    """Download a file from the output directory or scanner package."""
    # First check if it's a scanner package in the dist directory
    dist_dir = Path("dist")
    if dist_dir.exists() and (dist_dir / filename).exists():
        return send_file(dist_dir / filename, as_attachment=True)
    
    # Otherwise look in the output directory
    return send_file(OUTPUT_DIR / filename, as_attachment=True)

@app.route('/upload_results', methods=['POST'])
def upload_results():
    """Upload scan results from files."""
    if 'results_files' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
    
    files = request.files.getlist('results_files')
    
    if not files or all(file.filename == '' for file in files):
        flash('No selected files', 'danger')
        return redirect(url_for('index'))
    
    # Check if files should be merged
    merge_files = request.form.get('merge_files') == 'true'
    
    # Reset the state if we're uploading new files
    scan_state["iis_scan_results"] = None
    scan_state["network_scan_results"] = None
    scan_state["aws_scan_results"] = None
    scan_state["azure_scan_results"] = None
    scan_state["gcp_scan_results"] = None
    scan_state["lamp_scan_results"] = None
    
    # Combined results for merged processing
    combined_results = {}
    
    # Process all uploaded files
    successful_uploads = 0
    for file in files:
        if file and file.filename:
            try:
                # Parse the file contents
                file_content = file.read().decode('utf-8')
                results = json.loads(file_content)
                
                # Store the results based on type
                if 'iis_scan' in results:
                    scan_type = "iis_scan"
                    scan_name = "Windows IIS"
                elif 'network_scan' in results:
                    scan_type = "network_scan"
                    scan_name = "Network"
                elif 'aws_scan' in results:
                    scan_type = "aws_scan"
                    scan_name = "AWS Cloud"
                elif 'azure_scan' in results:
                    scan_type = "azure_scan"
                    scan_name = "Azure Cloud"
                elif 'gcp_scan' in results:
                    scan_type = "gcp_scan"
                    scan_name = "GCP Cloud"
                elif 'apache_scan' in results:
                    scan_type = "lamp_scan"
                    scan_name = "LAMP Stack"
                else:
                    flash(f"Unknown format in file {file.filename}", "warning")
                    continue
                
                # Save individual scan results to state and files
                scan_state[scan_type + "_results"] = results
                output_file = OUTPUT_DIR / f"{scan_type}_results.json"
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                
                # Add to combined results if merging
                if merge_files:
                    combined_results.update(results)
                
                successful_uploads += 1
                flash(f"{scan_name} scan results from {file.filename} uploaded successfully", "success")
                
            except json.JSONDecodeError:
                flash(f"Invalid JSON in file {file.filename}", "danger")
            except Exception as e:
                flash(f"Error processing file {file.filename}: {e}", "danger")
    
    # If merging is enabled and we have multiple successful uploads, save combined file
    if merge_files and successful_uploads > 1:
        try:
            with open(OUTPUT_DIR / "combined_scan_results.json", 'w') as f:
                json.dump(combined_results, f, indent=2)
            scan_state["combined_results"] = combined_results
            flash(f"Successfully merged {successful_uploads} files for unified analysis", "success")
        except Exception as e:
            flash(f"Error creating merged results: {e}", "warning")
    
    if successful_uploads == 0:
        flash("No files were successfully processed", "danger")
    
    return redirect(url_for('index'))

@app.route('/reset', methods=['POST'])
def reset_state():
    """Reset the application state."""
    scan_state["iis_scan_results"] = None
    scan_state["network_scan_results"] = None
    scan_state["dependency_graph"] = None
    scan_state["visualization_path"] = None
    scan_state["report_path"] = None
    
    flash("Application state has been reset", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
