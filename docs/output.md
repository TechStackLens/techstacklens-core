# Output TOSCA Data Model (JSON Format)

This document describes the structure of the output TOSCA (Topology and Orchestration Specification for Cloud Applications) data model in JSON format.

## Example

```json
{
    "tosca_definitions_version": "tosca_simple_yaml_1_3",
    "description": "Sample TOSCA output model",
    "topology_template": {
        "inputs": {
            "input_name": {
                "type": "string",
                "description": "Description of the input"
            }
        },
        "node_templates": {
            "node_name": {
                "type": "tosca.nodes.Compute",
                "properties": {
                    "property_name": "value"
                },
                "requirements": [
                    {
                        "host": "another_node"
                    }
                ]
            }
        },
        "outputs": {
            "output_name": {
                "description": "Description of the output",
                "value": {
                    "get_attribute": [
                        "node_name",
                        "attribute_name"
                    ]
                }
            }
        }
    }
}
```

## Fields

- **tosca_definitions_version**: Specifies the TOSCA version.
- **description**: Human-readable description of the TOSCA template.
- **topology_template**: Main section containing the application topology.
    - **inputs**: Defines input parameters for the template.
    - **node_templates**: Declares the nodes and their relationships.
    - **outputs**: Specifies outputs, referencing node attributes or values.

## Outputs Section

Each output entry includes:
- **description**: Explains the output.
- **value**: Expression or reference to a node attribute, property, or function.

## References

- [OASIS TOSCA Specification](https://docs.oasis-open.org/tosca/TOSCA-Simple-Profile-YAML/v1.3/os/TOSCA-Simple-Profile-YAML-v1.3-os.html)