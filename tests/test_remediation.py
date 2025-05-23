import unittest
from techstacklens.reporter.report_generator import ReportGenerator

class TestAutomatedRemediation(unittest.TestCase):

    def setUp(self):
        # Initialize the ReportGenerator or any required mock data
        self.report_generator = ReportGenerator()
        self.mock_data = {
            "issues": [
                {"type": "outdated_dependency", "name": "libraryA", "version": "1.0"},
                {"type": "security_vulnerability", "name": "serviceB", "severity": "high"}
            ]
        }

    def test_remediation_suggestions(self):
        """Test that remediation suggestions are generated correctly."""
        suggestions = self.report_generator.generate_remediation_suggestions(self.mock_data)
        self.assertIsNotNone(suggestions, "Suggestions should not be None")
        self.assertGreater(len(suggestions), 0, "There should be at least one suggestion")

    def test_modernization_opportunities(self):
        """Test that modernization opportunities are highlighted."""
        opportunities = self.report_generator.highlight_modernization_opportunities(self.mock_data)
        self.assertIsNotNone(opportunities, "Opportunities should not be None")
        self.assertIn("serverless_migration", opportunities, "Opportunities should include serverless migration")

if __name__ == "__main__":
    unittest.main()
