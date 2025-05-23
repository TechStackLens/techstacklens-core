import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

# Existing imports
from web_app import WebApp
import unittest

class TestIntegrationAndExtensibility(unittest.TestCase):

    def setUp(self):
        # Initialize the WebApp or any required mock data
        self.web_app = WebApp()
        self.mock_api_data = {
            "endpoint": "/api/v1/integrate",
            "payload": {"tool": "Jenkins", "action": "trigger_build"}
        }
        self.mock_plugin_data = {
            "plugin_name": "custom_scanner",
            "config": {"rule": "custom_rule"}
        }

    def test_api_support(self):
        """Test API integration with external tools."""
        response = self.web_app.handle_api_request(self.mock_api_data)
        self.assertEqual(response.status_code, 200, "API should return a 200 status code")
        self.assertIn("success", response.json(), "Response should indicate success")

    def test_plugin_support(self):
        """Test plugin functionality for custom scanning rules."""
        result = self.web_app.load_plugin(self.mock_plugin_data)
        self.assertTrue(result, "Plugin should load successfully")

    def test_custom_rules_and_policies(self):
        """Test custom rules and policies for scanning and reporting."""
        result = self.web_app.apply_custom_rules(self.mock_plugin_data["config"])
        self.assertIn("custom_rule", result, "Custom rule should be applied successfully")

if __name__ == "__main__":
    unittest.main()
