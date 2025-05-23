import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

import unittest
from techstacklens.analyzer.dependency_analyzer import DependencyAnalyzer

class TestAIDrivenDiscovery(unittest.TestCase):

    def setUp(self):
        # Initialize the DependencyAnalyzer or any required mock data
        self.analyzer = DependencyAnalyzer()
        self.mock_data = {
            "cloud": "hybrid",
            "dependencies": ["serviceA", "serviceB"],
        }

    def test_one_click_discovery(self):
        """Test the one-click discovery feature."""
        result = self.analyzer.analyze(self.mock_data)
        self.assertIsNotNone(result, "Discovery result should not be None")
        self.assertIn("architecture_map", result, "Result should include an architecture map")

    def test_hybrid_cloud_support(self):
        """Test support for hybrid cloud environments."""
        result = self.analyzer.analyze(self.mock_data)
        self.assertEqual(result.get("cloud_type"), "hybrid", "Cloud type should be hybrid")

    def test_actionable_visualizations(self):
        """Test generation of actionable visualizations."""
        visualization = self.analyzer.generate_visualization(self.mock_data)
        self.assertIsNotNone(visualization, "Visualization should not be None")
        self.assertIn("nodes", visualization, "Visualization should include nodes")
        self.assertIn("edges", visualization, "Visualization should include edges")

if __name__ == "__main__":
    unittest.main()
