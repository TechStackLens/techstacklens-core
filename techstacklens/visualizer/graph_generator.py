"""
Graph Generator module for visualizing dependency graphs using Graphviz.
"""

import os
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class GraphGenerator:
    """
    Generator for dependency visualizations using Graphviz.
    """
    
    def __init__(self):
        """Initialize the Graph Generator."""
        # Define node shapes and colors for different types
        self.node_styles = {
            "host": {"shape": "box", "color": "lightblue"},
            "service": {"shape": "ellipse", "color": "lightgreen"},
            "site": {"shape": "box", "color": "lightyellow"},
            "binding": {"shape": "diamond", "color": "lightgrey"}
        }
        
        # Define role colors
        self.role_colors = {
            "web": "#ADD8E6",  # Light blue
            "middleware": "#90EE90",  # Light green
            "application": "#90EE90",  # Light green
            "database": "#FFB6C1",  # Light pink
            "cache": "#FFA07A",  # Light salmon
            "messaging": "#D8BFD8",  # Thistle
            "directory": "#DDA0DD",  # Plum
            "unknown": "#D3D3D3"   # Light grey
        }
        
        # Define edge styles
        self.edge_styles = {
            "hosts": {"style": "solid", "color": "black"},
            "binds_to": {"style": "dashed", "color": "grey"},
            "uses": {"style": "dotted", "color": "blue"},
            "depends_on": {"style": "bold", "color": "red"}
        }
    
    def generate(self, dependency_graph, output_path_base):
        """
        Generate visualization of dependency graph.
        
        Args:
            dependency_graph (dict): Dependency graph with nodes and edges
            output_path_base (str): Base path for output files (without extension)
            
        Returns:
            str: Path to generated visualization file
        """
        logger.info(f"Generating visualization to {output_path_base}")
        
        try:
            # Save graph data as JSON for reference
            json_path = f"{output_path_base}.json"
            with open(json_path, 'w') as f:
                json.dump(dependency_graph, f, indent=2)
            
            # Generate DOT file
            dot_path = f"{output_path_base}.dot"
            self._generate_dot_file(dependency_graph, dot_path)
            
            # Generate graph image using Graphviz
            png_path = f"{output_path_base}.png"
            self._run_graphviz(dot_path, png_path)
            
            # Generate HTML visualization
            html_path = f"{output_path_base}.html"
            self._generate_html_visualization(dependency_graph, html_path)
            
            return png_path
        except Exception as e:
            logger.error(f"Error generating visualization: {e}")
            return None
    
    def _generate_dot_file(self, dependency_graph, output_path):
        """
        Generate DOT file for Graphviz.
        
        Args:
            dependency_graph (dict): Dependency graph with nodes and edges
            output_path (str): Path to output DOT file
        """
        nodes = dependency_graph.get("nodes", [])
        edges = dependency_graph.get("edges", [])
        
        with open(output_path, 'w') as f:
            f.write("digraph DependencyGraph {\n")
            f.write("  graph [rankdir=LR, fontname=Arial, nodesep=0.8, ranksep=1.0];\n")
            f.write("  node [fontname=Arial, fontsize=10];\n")
            f.write("  edge [fontname=Arial, fontsize=8];\n\n")
            
            # Add nodes
            for node in nodes:
                node_id = node["id"]
                node_label = node.get("label", node_id)
                node_type = node.get("type", "unknown")
                node_role = node.get("role", "unknown")
                
                # Select style based on node type and role
                style = self.node_styles.get(node_type, {"shape": "box", "color": "white"})
                shape = style["shape"]
                
                # Select color based on role if available
                if node_role != "unknown":
                    color = self.role_colors.get(node_role, style["color"])
                else:
                    color = style["color"]
                
                # Add additional info to label
                extra_info = []
                if "ip" in node:
                    extra_info.append(f"IP: {node['ip']}")
                if "port" in node:
                    extra_info.append(f"Port: {node['port']}")
                if "app_type" in node and node["app_type"] != "unknown":
                    extra_info.append(f"Type: {node['app_type']}")
                if "hostname" in node and node["hostname"]:
                    extra_info.append(f"Host: {node['hostname']}")
                
                label = node_label
                if extra_info:
                    label += "\\n" + "\\n".join(extra_info)
                
                f.write(f'  "{node_id}" [label="{label}", shape={shape}, style=filled, fillcolor="{color}"];\n')
            
            f.write("\n")
            
            # Add edges
            for edge in edges:
                source_id = edge["source"]
                target_id = edge["target"]
                edge_type = edge.get("type", "default")
                
                # Select style based on edge type
                style = self.edge_styles.get(edge_type, {"style": "solid", "color": "black"})
                edge_style = style["style"]
                edge_color = style["color"]
                
                edge_label = edge_type.replace("_", " ")
                if "dependency_type" in edge:
                    edge_label += f"\\n{edge['dependency_type'].replace('_', ' ')}"
                
                f.write(f'  "{source_id}" -> "{target_id}" [label="{edge_label}", style={edge_style}, color="{edge_color}"];\n')
            
            f.write("}\n")
    
    def _run_graphviz(self, dot_path, output_path):
        """
        Run Graphviz to generate image from DOT file.
        
        Args:
            dot_path (str): Path to DOT file
            output_path (str): Path to output image file
        """
        try:
            import subprocess
            cmd = ["dot", "-Tpng", "-o", output_path, dot_path]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if process.returncode != 0:
                logger.error(f"Graphviz error: {process.stderr.decode()}")
                # If dot command fails, add a message to the log
                logger.info("If Graphviz is not installed, you can install it with 'apt-get install graphviz' on Linux or visit graphviz.org")
        except Exception as e:
            logger.error(f"Error running Graphviz: {e}")
    
    def _generate_html_visualization(self, dependency_graph, output_path):
        """
        Generate interactive HTML visualization.
        
        Args:
            dependency_graph (dict): Dependency graph with nodes and edges
            output_path (str): Path to output HTML file
        """
        # Create a simplified version of the graph for D3.js
        d3_data = {
            "nodes": [],
            "links": []
        }
        
        # Convert nodes
        for node in dependency_graph.get("nodes", []):
            node_type = node.get("type", "unknown")
            node_role = node.get("role", "unknown")
            
            # Select color based on role if available
            if node_role != "unknown":
                color = self.role_colors.get(node_role, "#D3D3D3")
            else:
                color = self.node_styles.get(node_type, {"color": "#D3D3D3"})["color"]
            
            d3_node = {
                "id": node["id"],
                "label": node.get("label", node["id"]),
                "type": node_type,
                "role": node_role,
                "color": color
            }
            
            # Add other properties
            for key, value in node.items():
                if key not in ["id", "label", "type", "role"] and not isinstance(value, dict) and not isinstance(value, list):
                    d3_node[key] = value
            
            d3_data["nodes"].append(d3_node)
        
        # Convert edges
        for edge in dependency_graph.get("edges", []):
            edge_type = edge.get("type", "default")
            style = self.edge_styles.get(edge_type, {"style": "solid", "color": "black"})
            
            d3_link = {
                "source": edge["source"],
                "target": edge["target"],
                "type": edge_type,
                "color": style["color"]
            }
            
            # Add other properties
            for key, value in edge.items():
                if key not in ["source", "target", "type"] and not isinstance(value, dict) and not isinstance(value, list):
                    d3_link[key] = value
            
            d3_data["links"].append(d3_link)
        
        # Create the HTML file with embedded D3.js visualization
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechStackLens Dependency Visualization</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        h1 {
            text-align: center;
            color: #333;
        }
        
        #graph {
            width: 100%;
            height: 700px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: white;
            margin-top: 20px;
        }
        
        .controls {
            margin: 20px 0;
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .controls button, .controls select {
            padding: 8px 12px;
            background-color: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
        }
        
        .controls button:hover {
            background-color: #e8e8e8;
        }
        
        .tooltip {
            position: absolute;
            padding: 10px;
            background-color: rgba(0, 0, 0, 0.7);
            color: white;
            border-radius: 4px;
            pointer-events: none;
            font-size: 14px;
            max-width: 300px;
        }
        
        .node text {
            font-size: 10px;
        }
        
        .legend {
            margin-top: 20px;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 15px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            margin-right: 10px;
        }
        
        .legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border: 1px solid #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>TechStackLens Dependency Visualization</h1>
        
        <div class="controls">
            <button id="reset">Reset View</button>
            <select id="filter-type">
                <option value="all">All Node Types</option>
                <option value="host">Hosts</option>
                <option value="service">Services</option>
                <option value="site">Sites</option>
                <option value="binding">Bindings</option>
            </select>
            <select id="filter-role">
                <option value="all">All Roles</option>
                <option value="web">Web</option>
                <option value="middleware">Middleware</option>
                <option value="database">Database</option>
                <option value="cache">Cache</option>
                <option value="messaging">Messaging</option>
                <option value="directory">Directory</option>
            </select>
        </div>
        
        <div id="graph"></div>
        
        <div class="legend">
            <h3>Node Types:</h3>
            <div class="legend-item">
                <div class="legend-color" style="background-color: lightblue;"></div>
                <span>Host</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: lightgreen;"></div>
                <span>Service</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: lightyellow;"></div>
                <span>Site</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: lightgrey;"></div>
                <span>Binding</span>
            </div>
        </div>
        
        <div class="legend">
            <h3>Service Roles:</h3>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ADD8E6;"></div>
                <span>Web</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #90EE90;"></div>
                <span>Middleware/Application</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #FFB6C1;"></div>
                <span>Database</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #FFA07A;"></div>
                <span>Cache</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #D8BFD8;"></div>
                <span>Messaging</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #DDA0DD;"></div>
                <span>Directory</span>
            </div>
        </div>
    </div>

    <script>
    // Graph data
    const graphData = """ + json.dumps(d3_data) + """;
    
    // Create a force-directed graph
    const width = document.getElementById('graph').clientWidth;
    const height = document.getElementById('graph').clientHeight;
    
    // Create a tooltip div
    const tooltip = d3.select('body').append('div')
        .attr('class', 'tooltip')
        .style('opacity', 0);
    
    // Set up the simulation
    const simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(50));
    
    // Create the SVG
    const svg = d3.select('#graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .call(d3.zoom().on('zoom', (event) => {
            g.attr('transform', event.transform);
        }));
    
    const g = svg.append('g');
    
    // Define arrow marker
    svg.append('defs').append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '-0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('orient', 'auto')
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('xoverflow', 'visible')
        .append('svg:path')
        .attr('d', 'M 0,-5 L 10 ,0 L 0,5')
        .attr('fill', '#999')
        .style('stroke', 'none');
    
    // Create the graph elements
    let nodeElements, linkElements;
    
    function updateGraph(nodes, links) {
        // Remove existing elements
        g.selectAll('.link').remove();
        g.selectAll('.node').remove();
        
        // Add links
        linkElements = g.append('g')
            .selectAll('line')
            .data(links)
            .enter().append('line')
            .attr('class', 'link')
            .attr('stroke', d => d.color || '#999')
            .attr('stroke-width', 1.5)
            .attr('marker-end', 'url(#arrowhead)');
        
        // Add nodes
        nodeElements = g.append('g')
            .selectAll('circle')
            .data(nodes)
            .enter().append('circle')
            .attr('class', 'node')
            .attr('r', 12)
            .attr('fill', d => d.color || '#999')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Add node labels
        const textElements = g.append('g')
            .selectAll('text')
            .data(nodes)
            .enter().append('text')
            .text(d => d.label)
            .attr('dx', 15)
            .attr('dy', 4)
            .style('font-size', '10px');
        
        // Add tooltips
        nodeElements.on('mouseover', function(event, d) {
                tooltip.transition()
                    .duration(200)
                    .style('opacity', .9);
                    
                let tooltipContent = `<strong>${d.label}</strong><br>`;
                tooltipContent += `Type: ${d.type}<br>`;
                
                if (d.role && d.role !== 'unknown') {
                    tooltipContent += `Role: ${d.role}<br>`;
                }
                
                if (d.ip) {
                    tooltipContent += `IP: ${d.ip}<br>`;
                }
                
                if (d.port) {
                    tooltipContent += `Port: ${d.port}<br>`;
                }
                
                if (d.app_type && d.app_type !== 'unknown') {
                    tooltipContent += `Application Type: ${d.app_type}<br>`;
                }
                
                if (d.hostname) {
                    tooltipContent += `Hostname: ${d.hostname}<br>`;
                }
                
                tooltip.html(tooltipContent)
                    .style('left', (event.pageX + 10) + 'px')
                    .style('top', (event.pageY - 28) + 'px');
            })
            .on('mouseout', function() {
                tooltip.transition()
                    .duration(500)
                    .style('opacity', 0);
            });
        
        // Update simulation
        simulation.nodes(nodes).on('tick', ticked);
        simulation.force('link').links(links);
        simulation.alpha(1).restart();
        
        // Tick function
        function ticked() {
            linkElements
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            nodeElements
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
            
            textElements
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        }
    }
    
    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    // Filter functions
    function filterGraph() {
        const typeFilter = document.getElementById('filter-type').value;
        const roleFilter = document.getElementById('filter-role').value;
        
        let filteredNodes = graphData.nodes;
        
        if (typeFilter !== 'all') {
            filteredNodes = filteredNodes.filter(node => node.type === typeFilter);
        }
        
        if (roleFilter !== 'all') {
            filteredNodes = filteredNodes.filter(node => 
                node.role === roleFilter || 
                (node.roles && node.roles.includes(roleFilter))
            );
        }
        
        const nodeIds = new Set(filteredNodes.map(node => node.id));
        
        const filteredLinks = graphData.links.filter(link => 
            nodeIds.has(link.source) && nodeIds.has(link.target)
        );
        
        updateGraph(filteredNodes, filteredLinks);
    }
    
    // Event listeners
    document.getElementById('reset').addEventListener('click', () => {
        document.getElementById('filter-type').value = 'all';
        document.getElementById('filter-role').value = 'all';
        updateGraph(graphData.nodes, graphData.links);
    });
    
    document.getElementById('filter-type').addEventListener('change', filterGraph);
    document.getElementById('filter-role').addEventListener('change', filterGraph);
    
    // Initial graph render
    updateGraph(graphData.nodes, graphData.links);
    </script>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html_content)
