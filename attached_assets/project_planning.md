# TechStackLens Agentic MCP Refactor: Project Task List

## Goal
Refactor TechStackLens into an agentic MCP (Multi-Component Platform) where each major function (script generator, analyzer, report visualizer, etc.) is an agent with a common interface, orchestrated by a central controller.

---

## Task List

### 1. Define Agent Interface
- [ ] Create a base `AgentBase` class with a `handle(message: dict) -> dict` method.

### 2. MCP Controller
- [ ] Implement an `MCPController` that registers agents and dispatches messages.

### 3. Refactor Core Components as Agents
- [ ] Refactor script generator as `ScriptGeneratorAgent`.
- [ ] Refactor analyzer as `AnalyzerAgent`.
- [ ] Refactor report visualizer as `ReportVisualizerAgent`.
- [ ] Refactor report generator as `ReportGeneratorAgent`.

### 4. Update Web/CLI/API to Use MCP
- [ ] Update Flask routes (and/or CLI) to use the MCP controller for all operations.

### 5. Documentation
- [ ] Update documentation to describe the agentic architecture and how to add new agents.
- [ ] Add code examples for agent creation and registration.

### 6. Testing
- [ ] Add/expand tests for agent interfaces and MCP controller.
- [ ] Add integration tests for agent workflows (script → analyze → visualize → report).

### 7. Extensibility
- [ ] Document and test how to add a new stack agent (e.g., for a new tech stack or analysis type).

---

## Hosting Plan
| Component         | Hosting Location         | Notes |
|-------------------|-------------------------|-------|
| Front-end (Flask Web UI) | PythonAnywhere (or similar PaaS) | Public-facing, user interaction |
| MCP Controller    | PythonAnywhere (or dedicated backend) | Orchestrates all agents |
| Script Generator Agent | PythonAnywhere backend | Generates and serves scripts |
| Analyzer Agent    | PythonAnywhere backend | Handles uploaded scan data |
| Visualizer Agent  | PythonAnywhere backend | Generates graphs/visuals |
| Report Generator Agent | PythonAnywhere backend | Produces reports |
| Storage (scan results, reports) | PythonAnywhere file storage or cloud bucket | Persistent data |

---

## Notes
- Agents should be loosely coupled and communicate only via message dicts.
- The MCP controller can be extended to support async/distributed operation in the future.
- This refactor will make TechStackLens more maintainable, extensible, and ready for advanced automation.
