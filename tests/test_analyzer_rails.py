from techstacklens.analyzer.dependency_analyzer import DependencyAnalyzer

def test_rails_stack_analysis():
    scan_results = {
        "rails_scan": {
            "apps": [
                {"name": "myapp", "db": "postgresql", "ruby_version": "3.1.0"}
            ],
            "gems": ["rails", "pg", "puma"]
        }
    }
    analyzer = DependencyAnalyzer()
    graph = analyzer.analyze(scan_results)
    assert isinstance(graph, dict)
    assert "nodes" in graph and "edges" in graph
    # Check for at least one Rails app node
    assert any("rails" in n.get("type", "") or "rails" in n.get("name", "").lower() for n in graph["nodes"])
