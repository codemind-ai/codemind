"""Configuration import module."""

import yaml
import requests
from pathlib import Path
from typing import Optional


def import_config(source: str, target_path: Path) -> bool:
    """
    Import configuration from a file or URL.
    
    Args:
        source: File path or URL to import from
        target_path: Path to save the imported configuration
        
    Returns:
        True if successful
    """
    content = ""
    
    if source.startswith(("http://", "https://")):
        # Import from URL
        response = requests.get(source, timeout=10)
        response.raise_for_status()
        content = response.text
    else:
        # Import from file
        source_path = Path(source)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source}")
        content = source_path.read_text(encoding="utf-8")
    
    # Validate YAML before saving
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("Invalid configuration format")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML content: {e}")
    
    # Write to target path
    target_path.write_text(content, encoding="utf-8")
    
    return True
