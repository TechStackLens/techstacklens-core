class AgentBase:
    """Base class for all MCP agents."""
    def handle(self, message: dict) -> dict:
        """Process a message and return a response."""
        raise NotImplementedError
