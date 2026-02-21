"""
Severity normalization across different scanners.

Each scanner uses different scales:
- Qualys: 1-5 numeric
- Nessus: Critical/High/Medium/Low/Info
- Tenable: Similar to Nessus
- Rapid7: Critical/Severe/Moderate/Low
"""

from typing import Optional, Dict

SEVERITY_MAPPINGS: Dict[str, Dict[str, str]] = {
    "qualys": {
        "5": "Critical",
        "4": "High",
        "3": "Medium",
        "2": "Low",
        "1": "Low",
    },
    "nessus": {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Low",
        "Informational": "Low",
        "None": "Low",
    },
    "tenable": {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Informational": "Low",
    },
    "rapid7": {
        "Critical": "Critical",
        "Severe": "Critical",
        "High": "High",
        "Moderate": "Medium",
        "Medium": "Medium",
        "Low": "Low",
    },
    "openvas": {
        "High": "Critical",
        "Medium": "High",
        "Low": "Medium",
        "Log": "Low",
    },
    "generic": {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Moderate": "Medium",
        "Low": "Low",
        "Informational": "Low",
        "Info": "Low",
    },
}


def normalize_severity(value: Optional[str | int], scanner: str = "generic") -> str:
    """
    Normalize severity to standard levels: Critical, High, Medium, Low.
    
    Args:
        value: Raw severity from scanner (e.g., "5", "Critical", "High")
        scanner: Scanner name for specific mapping
        
    Returns:
        Normalized severity string
        
    Examples:
        >>> normalize_severity("5", "qualys")
        'Critical'
        >>> normalize_severity("Info", "nessus")
        'Low'
    """
    if value is None:
        return "Low"
    
    mapping = SEVERITY_MAPPINGS.get(scanner.lower(), SEVERITY_MAPPINGS["generic"])
    str_value = str(value).strip()
    
    # Direct match
    if str_value in mapping:
        return mapping[str_value]
    
    # Case-insensitive match
    for key, normalized in mapping.items():
        if key.lower() == str_value.lower():
            return normalized
    
    return "Low"
