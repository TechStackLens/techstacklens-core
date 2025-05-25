import pytest
from techstacklens.analyzer.dependency_analyzer import DependencyAnalyzer

def test_mean_stack_analysis():
    scan_results = {
        "mean_scan": {
            "mongodb": {"version": "4.4.0", "status": "running"},
            "express": {"version": "4.17.1", "apps": ["app1", "app2"]},
            "angular": {"projects": ["frontend1"]},
            "nodejs": {"version": "14.17.0"}
        }
    }
    analyzer = DependencyAnalyzer()
    graph = analyzer.analyze(scan_results)
    node_types = {n['type'] for n in graph['nodes']}
    node_names = {n['name'] for n in graph['nodes']}
    edge_types = {e['type'] for e in graph['edges']}
    assert "MongoDB" in node_names
    assert "Express" in node_names
    assert "Angular" in node_names
    assert "Node.js" in node_names
    assert "database" in node_types
    assert "middleware" in node_types
    assert "frontend" in node_types
    assert "runtime" in node_types
    assert "app_to_db" in edge_types
    assert "web_to_app" in edge_types
    assert "app_to_runtime" in edge_types
