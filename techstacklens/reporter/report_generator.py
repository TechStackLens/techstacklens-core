"""
Report Generator module for creating reports from scan and analysis results.
"""

import os
import logging
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generator for scan and analysis reports.
    """
    
    def __init__(self):
        """Initialize the Report Generator."""
        pass
    
    def generate_report(self, scan_results, dependency_graph, output_path):
        """
        Generate a report from scan results and dependency graph.
        
        Args:
            scan_results (dict): Combined scan results
            dependency_graph (dict): Dependency graph data
            output_path (str): Path to output report file
            
        Returns:
            str: Path to generated report file
        """
        logger.info(f"Generating report to {output_path}")
        
        try:
            # For PDF generation, use reportlab
            pdf_path = self._generate_pdf_report(scan_results, dependency_graph, output_path)
            
            # Also generate an HTML report
            html_path = f"{os.path.splitext(output_path)[0]}.html"
            self._generate_html_report(scan_results, dependency_graph, html_path)
            
            return pdf_path
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            
            # Fallback to simple text report if PDF generation fails
            text_path = f"{os.path.splitext(output_path)[0]}.txt"
            self._generate_text_report(scan_results, dependency_graph, text_path)
            
            return text_path
    
    def _generate_pdf_report(self, scan_results, dependency_graph, output_path):
        """
        Generate a PDF report using reportlab.
        
        Args:
            scan_results (dict): Combined scan results
            dependency_graph (dict): Dependency graph data
            output_path (str): Path to output PDF file
            
        Returns:
            str: Path to generated PDF file
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
            from reportlab.lib.units import inch
            
            # Create document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='Center', alignment=1, parent=styles['Heading1']))
            
            # Build content
            content = []
            
            # Title
            title = Paragraph("TechStackLens Infrastructure Assessment Report", styles['Center'])
            content.append(title)
            content.append(Spacer(1, 0.25*inch))
            
            # Timestamp
            timestamp = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
            content.append(timestamp)
            content.append(Spacer(1, 0.25*inch))
            
            # Summary
            summary_title = Paragraph("Executive Summary", styles['Heading2'])
            content.append(summary_title)
            
            # Count hosts, services, sites
            num_hosts = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "host")
            num_services = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "service")
            num_sites = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "site")
            num_dependencies = sum(1 for edge in dependency_graph.get("edges", []) if edge.get("type") == "depends_on")
            
            summary_text = f"This report provides an assessment of the scanned IT infrastructure. "
            summary_text += f"The scan identified {num_hosts} hosts, {num_services} services, {num_sites} IIS sites, "
            summary_text += f"and {num_dependencies} dependencies between components."
            
            summary = Paragraph(summary_text, styles['Normal'])
            content.append(summary)
            content.append(Spacer(1, 0.25*inch))
            
            # Hosts Section
            hosts_title = Paragraph("Discovered Hosts", styles['Heading2'])
            content.append(hosts_title)
            
            if "network_scan" in scan_results and "hosts" in scan_results["network_scan"]:
                hosts = scan_results["network_scan"]["hosts"]
                if hosts:
                    # Create table for hosts
                    host_data = [["IP Address", "Hostname", "Roles", "Services"]]
                    
                    for host in hosts:
                        ip = host.get("ip", "")
                        hostname = host.get("hostname", "")
                        roles = ", ".join(host.get("roles", []))
                        
                        services_list = []
                        for service in host.get("services", []):
                            service_name = service.get("name", "unknown")
                            port = service.get("port", "")
                            services_list.append(f"{service_name}:{port}")
                        
                        services_text = ", ".join(services_list)
                        host_data.append([ip, hostname, roles, services_text])
                    
                    host_table = Table(host_data, colWidths=[1.2*inch, 1.5*inch, 1.5*inch, 2.5*inch])
                    host_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    content.append(host_table)
                else:
                    content.append(Paragraph("No hosts were discovered during the scan.", styles['Normal']))
            else:
                content.append(Paragraph("No network scan data available.", styles['Normal']))
            
            content.append(Spacer(1, 0.25*inch))
            
            # IIS Sites Section
            sites_title = Paragraph("IIS Sites", styles['Heading2'])
            content.append(sites_title)
            
            if "iis_scan" in scan_results and "iis_sites" in scan_results["iis_scan"]:
                sites = scan_results["iis_scan"]["iis_sites"]
                if sites:
                    # Create table for sites
                    site_data = [["Site Name", "Application Type", "Bindings"]]
                    
                    for site in sites:
                        name = site.get("name", "")
                        app_type = site.get("app_type", "unknown")
                        
                        bindings_list = []
                        for binding in site.get("bindings", []):
                            protocol = binding.get("protocol", "http")
                            hostname = binding.get("hostname", "*")
                            port = binding.get("port", 80)
                            bindings_list.append(f"{protocol}://{hostname}:{port}")
                        
                        bindings_text = ", ".join(bindings_list)
                        site_data.append([name, app_type, bindings_text])
                    
                    site_table = Table(site_data, colWidths=[2*inch, 1.5*inch, 3.2*inch])
                    site_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    content.append(site_table)
                else:
                    content.append(Paragraph("No IIS sites were discovered during the scan.", styles['Normal']))
            else:
                content.append(Paragraph("No IIS scan data available.", styles['Normal']))
            
            content.append(Spacer(1, 0.25*inch))
            
            # Dependencies Section
            dep_title = Paragraph("Dependencies", styles['Heading2'])
            content.append(dep_title)
            
            dep_edges = [edge for edge in dependency_graph.get("edges", []) if edge.get("type") == "depends_on"]
            if dep_edges:
                # Create table for dependencies
                dep_data = [["Source", "Dependency Type", "Target", "Confidence"]]
                
                # Get node lookup dictionary
                node_dict = {node["id"]: node for node in dependency_graph.get("nodes", [])}
                
                for edge in dep_edges:
                    source_id = edge.get("source", "")
                    target_id = edge.get("target", "")
                    
                    source_node = node_dict.get(source_id, {})
                    target_node = node_dict.get(target_id, {})
                    
                    source_label = source_node.get("label", source_id)
                    target_label = target_node.get("label", target_id)
                    
                    dep_type = edge.get("dependency_type", "").replace("_", " ").title()
                    confidence = edge.get("confidence", "unknown")
                    
                    dep_data.append([source_label, dep_type, target_label, confidence])
                
                dep_table = Table(dep_data, colWidths=[2*inch, 2*inch, 2*inch, 1*inch])
                dep_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                content.append(dep_table)
            else:
                content.append(Paragraph("No dependencies were identified during analysis.", styles['Normal']))
            
            content.append(Spacer(1, 0.25*inch))
            
            # Recommendations Section
            rec_title = Paragraph("Recommendations", styles['Heading2'])
            content.append(rec_title)
            
            # Basic recommendations based on scan results
            recommendations = []
            
            # Check for multiple roles on same host
            for node in dependency_graph.get("nodes", []):
                if node.get("type") == "host" and len(node.get("roles", [])) > 1:
                    if "web" in node.get("roles", []) and "database" in node.get("roles", []):
                        recommendations.append("Consider separating web and database roles onto different hosts for better security isolation.")
            
            # Check for missing roles
            roles_found = set()
            for node in dependency_graph.get("nodes", []):
                if "role" in node:
                    roles_found.add(node["role"])
                if "roles" in node:
                    roles_found.update(node["roles"])
            
            if "web" not in roles_found:
                recommendations.append("No web servers detected. Consider adding a web tier for external access.")
            
            if "database" not in roles_found:
                recommendations.append("No database servers detected. Consider adding a database tier for persistent storage.")
            
            # Add general recommendations
            recommendations.append("Review network segmentation to ensure proper separation between tiers.")
            recommendations.append("Implement regular backup procedures for all critical systems.")
            recommendations.append("Ensure all systems are patched with the latest security updates.")
            
            # Deduplicate recommendations
            unique_recommendations = list(set(recommendations))
            
            for recommendation in unique_recommendations:
                content.append(Paragraph(f"• {recommendation}", styles['Normal']))
            
            content.append(Spacer(1, 0.25*inch))
            
            # Build the PDF
            doc.build(content)
            
            logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except ImportError:
            logger.warning("ReportLab not installed. Falling back to text report.")
            return self._generate_text_report(scan_results, dependency_graph, f"{os.path.splitext(output_path)[0]}.txt")
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return self._generate_text_report(scan_results, dependency_graph, f"{os.path.splitext(output_path)[0]}.txt")
    
    def _generate_html_report(self, scan_results, dependency_graph, output_path):
        """
        Generate an HTML report.
        
        Args:
            scan_results (dict): Combined scan results
            dependency_graph (dict): Dependency graph data
            output_path (str): Path to output HTML file
            
        Returns:
            str: Path to generated HTML file
        """
        # Count hosts, services, sites
        num_hosts = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "host")
        num_services = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "service")
        num_sites = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "site")
        num_dependencies = sum(1 for edge in dependency_graph.get("edges", []) if edge.get("type") == "depends_on")
        
        # Get node lookup dictionary
        node_dict = {node["id"]: node for node in dependency_graph.get("nodes", [])}
        
        # Create HTML content
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechStackLens Infrastructure Assessment Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        h1 {
            text-align: center;
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        h2 {
            color: #2c3e50;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        
        .timestamp {
            text-align: right;
            font-style: italic;
            color: #7f8c8d;
            margin-bottom: 30px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        
        th {
            background-color: #f2f2f2;
            color: #333;
        }
        
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        .summary-stats {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            margin: 20px 0;
        }
        
        .stat-item {
            background-color: #f0f0f0;
            border-radius: 5px;
            padding: 15px;
            text-align: center;
            margin: 10px;
            min-width: 200px;
        }
        
        .stat-number {
            font-size: 30px;
            font-weight: bold;
            color: #3498db;
        }
        
        .stat-label {
            font-size: 14px;
            color: #7f8c8d;
        }
        
        .recommendations {
            background-color: #f9f9f9;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 20px 0;
        }
        
        .recommendations li {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <h1>TechStackLens Infrastructure Assessment Report</h1>
    
    <div class="timestamp">
        Generated on: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
    </div>
    
    <h2>Executive Summary</h2>
    <p>
        This report provides an assessment of the scanned IT infrastructure. 
        The scan identified hosts, services, IIS sites, and dependencies between components.
    </p>
    
    <div class="summary-stats">
        <div class="stat-item">
            <div class="stat-number">""" + str(num_hosts) + """</div>
            <div class="stat-label">Hosts</div>
        </div>
        <div class="stat-item">
            <div class="stat-number">""" + str(num_services) + """</div>
            <div class="stat-label">Services</div>
        </div>
        <div class="stat-item">
            <div class="stat-number">""" + str(num_sites) + """</div>
            <div class="stat-label">IIS Sites</div>
        </div>
        <div class="stat-item">
            <div class="stat-number">""" + str(num_dependencies) + """</div>
            <div class="stat-label">Dependencies</div>
        </div>
    </div>
    
    <h2>Discovered Hosts</h2>
"""

        # Add hosts section
        if "network_scan" in scan_results and "hosts" in scan_results["network_scan"]:
            hosts = scan_results["network_scan"]["hosts"]
            if hosts:
                html_content += """
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Roles</th>
                <th>Services</th>
            </tr>
        </thead>
        <tbody>
"""
                
                for host in hosts:
                    ip = host.get("ip", "")
                    hostname = host.get("hostname", "")
                    roles = ", ".join(host.get("roles", []))
                    
                    services_list = []
                    for service in host.get("services", []):
                        service_name = service.get("name", "unknown")
                        port = service.get("port", "")
                        services_list.append(f"{service_name}:{port}")
                    
                    services_text = ", ".join(services_list)
                    
                    html_content += f"""
            <tr>
                <td>{ip}</td>
                <td>{hostname}</td>
                <td>{roles}</td>
                <td>{services_text}</td>
            </tr>
"""
                
                html_content += """
        </tbody>
    </table>
"""
            else:
                html_content += "<p>No hosts were discovered during the scan.</p>"
        else:
            html_content += "<p>No network scan data available.</p>"
        
        # Add IIS sites section
        html_content += """
    <h2>IIS Sites</h2>
"""
        
        if "iis_scan" in scan_results and "iis_sites" in scan_results["iis_scan"]:
            sites = scan_results["iis_scan"]["iis_sites"]
            if sites:
                html_content += """
    <table>
        <thead>
            <tr>
                <th>Site Name</th>
                <th>Application Type</th>
                <th>Bindings</th>
            </tr>
        </thead>
        <tbody>
"""
                
                for site in sites:
                    name = site.get("name", "")
                    app_type = site.get("app_type", "unknown")
                    
                    bindings_list = []
                    for binding in site.get("bindings", []):
                        protocol = binding.get("protocol", "http")
                        hostname = binding.get("hostname", "*")
                        port = binding.get("port", 80)
                        bindings_list.append(f"{protocol}://{hostname}:{port}")
                    
                    bindings_text = ", ".join(bindings_list)
                    
                    html_content += f"""
            <tr>
                <td>{name}</td>
                <td>{app_type}</td>
                <td>{bindings_text}</td>
            </tr>
"""
                
                html_content += """
        </tbody>
    </table>
"""
            else:
                html_content += "<p>No IIS sites were discovered during the scan.</p>"
        else:
            html_content += "<p>No IIS scan data available.</p>"
        
        # Add dependencies section
        html_content += """
    <h2>Dependencies</h2>
"""
        
        dep_edges = [edge for edge in dependency_graph.get("edges", []) if edge.get("type") == "depends_on"]
        if dep_edges:
            html_content += """
    <table>
        <thead>
            <tr>
                <th>Source</th>
                <th>Dependency Type</th>
                <th>Target</th>
                <th>Confidence</th>
            </tr>
        </thead>
        <tbody>
"""
            
            for edge in dep_edges:
                source_id = edge.get("source", "")
                target_id = edge.get("target", "")
                
                source_node = node_dict.get(source_id, {})
                target_node = node_dict.get(target_id, {})
                
                source_label = source_node.get("label", source_id)
                target_label = target_node.get("label", target_id)
                
                dep_type = edge.get("dependency_type", "").replace("_", " ").title()
                confidence = edge.get("confidence", "unknown")
                
                html_content += f"""
            <tr>
                <td>{source_label}</td>
                <td>{dep_type}</td>
                <td>{target_label}</td>
                <td>{confidence}</td>
            </tr>
"""
            
            html_content += """
        </tbody>
    </table>
"""
        else:
            html_content += "<p>No dependencies were identified during analysis.</p>"
        
        # Add recommendations section
        html_content += """
    <h2>Recommendations</h2>
    <div class="recommendations">
        <ul>
"""
        
        # Basic recommendations based on scan results
        recommendations = []
        
        # Check for multiple roles on same host
        for node in dependency_graph.get("nodes", []):
            if node.get("type") == "host" and len(node.get("roles", [])) > 1:
                if "web" in node.get("roles", []) and "database" in node.get("roles", []):
                    recommendations.append("Consider separating web and database roles onto different hosts for better security isolation.")
        
        # Check for missing roles
        roles_found = set()
        for node in dependency_graph.get("nodes", []):
            if "role" in node:
                roles_found.add(node["role"])
            if "roles" in node:
                roles_found.update(node["roles"])
        
        if "web" not in roles_found:
            recommendations.append("No web servers detected. Consider adding a web tier for external access.")
        
        if "database" not in roles_found:
            recommendations.append("No database servers detected. Consider adding a database tier for persistent storage.")
        
        # Add general recommendations
        recommendations.append("Review network segmentation to ensure proper separation between tiers.")
        recommendations.append("Implement regular backup procedures for all critical systems.")
        recommendations.append("Ensure all systems are patched with the latest security updates.")
        
        # Deduplicate recommendations
        unique_recommendations = list(set(recommendations))
        
        for recommendation in unique_recommendations:
            html_content += f"            <li>{recommendation}</li>\n"
        
        html_content += """
        </ul>
    </div>
    
    <h2>Next Steps</h2>
    <p>
        Based on this assessment, we recommend the following next steps:
    </p>
    <ol>
        <li>Review the identified dependencies and validate that they align with the expected architecture.</li>
        <li>Address any security concerns identified in the recommendations section.</li>
        <li>Consider running additional detailed scans on critical components.</li>
        <li>Develop a remediation plan for any identified issues.</li>
    </ol>
    
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _generate_text_report(self, scan_results, dependency_graph, output_path):
        """
        Generate a simple text report as fallback.
        
        Args:
            scan_results (dict): Combined scan results
            dependency_graph (dict): Dependency graph data
            output_path (str): Path to output text file
            
        Returns:
            str: Path to generated text file
        """
        with open(output_path, 'w') as f:
            f.write("TechStackLens Infrastructure Assessment Report\n")
            f.write("="*50 + "\n\n")
            
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("Executive Summary\n")
            f.write("-"*20 + "\n")
            
            # Count hosts, services, sites
            num_hosts = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "host")
            num_services = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "service")
            num_sites = sum(1 for node in dependency_graph.get("nodes", []) if node.get("type") == "site")
            num_dependencies = sum(1 for edge in dependency_graph.get("edges", []) if edge.get("type") == "depends_on")
            
            f.write(f"This report provides an assessment of the scanned IT infrastructure.\n")
            f.write(f"The scan identified {num_hosts} hosts, {num_services} services, {num_sites} IIS sites, ")
            f.write(f"and {num_dependencies} dependencies between components.\n\n")
            
            # Hosts section
            f.write("Discovered Hosts\n")
            f.write("-"*20 + "\n")
            
            if "network_scan" in scan_results and "hosts" in scan_results["network_scan"]:
                hosts = scan_results["network_scan"]["hosts"]
                if hosts:
                    for host in hosts:
                        ip = host.get("ip", "")
                        hostname = host.get("hostname", "")
                        roles = ", ".join(host.get("roles", []))
                        
                        f.write(f"Host: {hostname if hostname else ip}\n")
                        f.write(f"  IP: {ip}\n")
                        f.write(f"  Roles: {roles}\n")
                        
                        f.write("  Services:\n")
                        for service in host.get("services", []):
                            service_name = service.get("name", "unknown")
                            port = service.get("port", "")
                            role = service.get("role", "unknown")
                            f.write(f"    - {service_name}:{port} ({role})\n")
                        
                        f.write("\n")
                else:
                    f.write("No hosts were discovered during the scan.\n\n")
            else:
                f.write("No network scan data available.\n\n")
            
            # IIS sites section
            f.write("IIS Sites\n")
            f.write("-"*20 + "\n")
            
            if "iis_scan" in scan_results and "iis_sites" in scan_results["iis_scan"]:
                sites = scan_results["iis_scan"]["iis_sites"]
                if sites:
                    for site in sites:
                        name = site.get("name", "")
                        app_type = site.get("app_type", "unknown")
                        
                        f.write(f"Site: {name}\n")
                        f.write(f"  Application Type: {app_type}\n")
                        
                        f.write("  Bindings:\n")
                        for binding in site.get("bindings", []):
                            protocol = binding.get("protocol", "http")
                            hostname = binding.get("hostname", "*")
                            port = binding.get("port", 80)
                            f.write(f"    - {protocol}://{hostname}:{port}\n")
                        
                        f.write("\n")
                else:
                    f.write("No IIS sites were discovered during the scan.\n\n")
            else:
                f.write("No IIS scan data available.\n\n")
            
            # Dependencies section
            f.write("Dependencies\n")
            f.write("-"*20 + "\n")
            
            dep_edges = [edge for edge in dependency_graph.get("edges", []) if edge.get("type") == "depends_on"]
            if dep_edges:
                # Get node lookup dictionary
                node_dict = {node["id"]: node for node in dependency_graph.get("nodes", [])}
                
                for edge in dep_edges:
                    source_id = edge.get("source", "")
                    target_id = edge.get("target", "")
                    
                    source_node = node_dict.get(source_id, {})
                    target_node = node_dict.get(target_id, {})
                    
                    source_label = source_node.get("label", source_id)
                    target_label = target_node.get("label", target_id)
                    
                    dep_type = edge.get("dependency_type", "").replace("_", " ").title()
                    confidence = edge.get("confidence", "unknown")
                    
                    f.write(f"{source_label} -> {target_label}\n")
                    f.write(f"  Type: {dep_type}\n")
                    f.write(f"  Confidence: {confidence}\n\n")
            else:
                f.write("No dependencies were identified during analysis.\n\n")
            
            # Recommendations section
            f.write("Recommendations\n")
            f.write("-"*20 + "\n")
            
            # Basic recommendations based on scan results
            recommendations = []
            
            # Check for multiple roles on same host
            for node in dependency_graph.get("nodes", []):
                if node.get("type") == "host" and len(node.get("roles", [])) > 1:
                    if "web" in node.get("roles", []) and "database" in node.get("roles", []):
                        recommendations.append("Consider separating web and database roles onto different hosts for better security isolation.")
            
            # Check for missing roles
            roles_found = set()
            for node in dependency_graph.get("nodes", []):
                if "role" in node:
                    roles_found.add(node["role"])
                if "roles" in node:
                    roles_found.update(node["roles"])
            
            if "web" not in roles_found:
                recommendations.append("No web servers detected. Consider adding a web tier for external access.")
            
            if "database" not in roles_found:
                recommendations.append("No database servers detected. Consider adding a database tier for persistent storage.")
            
            # Add general recommendations
            recommendations.append("Review network segmentation to ensure proper separation between tiers.")
            recommendations.append("Implement regular backup procedures for all critical systems.")
            recommendations.append("Ensure all systems are patched with the latest security updates.")
            
            # Deduplicate recommendations
            unique_recommendations = list(set(recommendations))
            
            for recommendation in unique_recommendations:
                f.write(f"- {recommendation}\n")
        
        logger.info(f"Text report generated: {output_path}")
        return output_path
    
    def generate_remediation_suggestions(self, data):
        """Generate remediation suggestions based on identified issues."""
        # Mock implementation for testing purposes
        suggestions = []
        for issue in data.get("issues", []):
            if issue["type"] == "outdated_dependency":
                suggestions.append(f"Upgrade {issue['name']} to the latest version.")
            elif issue["type"] == "security_vulnerability":
                suggestions.append(f"Address high-severity vulnerability in {issue['name']}.")
        return suggestions

    def highlight_modernization_opportunities(self, data):
        """Highlight opportunities for modernization based on the architecture."""
        # Mock implementation for testing purposes
        return {
            "serverless_migration": "Consider migrating to serverless architecture.",
            "containerization": "Evaluate containerizing services for better scalability."
        }
