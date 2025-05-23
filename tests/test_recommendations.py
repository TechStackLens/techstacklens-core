import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from techstacklens.utils.rules_engine import RulesEngine

class TestContextualRecommendations(unittest.TestCase):

    def setUp(self):
        # Initialize the RulesEngine or any required mock data
        self.rules_engine = RulesEngine()
        self.mock_data = {
            "stack": "LAMP",
            "compliance": "PCI-DSS",
            "business_goals": ["scalability", "cost-optimization"],
        }

    def test_context_aware_insights(self):
        """Test that recommendations are tailored to the provided context."""
        recommendations = self.rules_engine.generate_recommendations(self.mock_data)
        self.assertIsNotNone(recommendations, "Recommendations should not be None")
        self.assertIn("compliance", recommendations, "Recommendations should include compliance insights")
        self.assertIn("business_goals", recommendations, "Recommendations should include business goals insights")

    def test_rules_engine_adaptability(self):
        """Test that the rules engine adapts advice based on the detected stack."""
        recommendations = self.rules_engine.generate_recommendations(self.mock_data)
        self.assertEqual(recommendations.get("stack"), "LAMP", "Stack should match the input stack")

if __name__ == "__main__":
    unittest.main()
