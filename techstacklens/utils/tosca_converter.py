from tosca import ToscaModel, ToscaComponent

def scanner_output_to_tosca(scanner_output):
    """
    Converts scanner output (list of dicts) to ToscaModel (JSON serializable).
    Each scanner output dict should have at least: name, type, version, and optionally dependencies.
    """
    components = []
    for item in scanner_output:
        component = ToscaComponent(
            name=item.get("name"),
            type=item.get("type"),
            version=item.get("version"),
            dependencies=item.get("dependencies", [])
        )
        components.append(component)
    model = ToscaModel(components=components)
    return model.to_json()