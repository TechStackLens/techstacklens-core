def standardize_scan_output(results, stack_name=None):
    """
    Ensure scan results are wrapped in a uniform structure for downstream analysis/reporting.
    If stack_name is provided, wrap results under that key.
    """
    if stack_name:
        return {stack_name: results}
    # If already top-level dict with known keys, return as is
    if isinstance(results, dict):
        return results
    return {"scan_results": results}
