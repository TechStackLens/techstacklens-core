import json
from typing import Any, Dict, List, Optional

class ToscaNodeTemplate:
    def __init__(
        self,
        name: str,
        type: str,
        properties: Optional[Dict[str, Any]] = None,
        requirements: Optional[List[Dict[str, Any]]] = None,
        capabilities: Optional[Dict[str, Any]] = None,
        interfaces: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.type = type
        self.properties = properties or {}
        self.requirements = requirements or []
        self.capabilities = capabilities or {}
        self.interfaces = interfaces or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "properties": self.properties,
            "requirements": self.requirements,
            "capabilities": self.capabilities,
            "interfaces": self.interfaces,
        }


class ToscaTopologyTemplate:
    def __init__(
        self,
        node_templates: Optional[List[ToscaNodeTemplate]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        outputs: Optional[Dict[str, Any]] = None,
    ):
        self.node_templates = node_templates or []
        self.inputs = inputs or {}
        self.outputs = outputs or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_templates": [nt.to_dict() for nt in self.node_templates],
            "inputs": self.inputs,
            "outputs": self.outputs,
        }


class ToscaServiceTemplate:
    def __init__(
        self,
        tosca_definitions_version: str,
        description: Optional[str] = None,
        topology_template: Optional[ToscaTopologyTemplate] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.tosca_definitions_version = tosca_definitions_version
        self.description = description
        self.topology_template = topology_template or ToscaTopologyTemplate()
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tosca_definitions_version": self.tosca_definitions_version,
            "description": self.description,
            "metadata": self.metadata,
            "topology_template": self.topology_template.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)