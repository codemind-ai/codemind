"""Configuration export module."""

import yaml
from pathlib import Path
from typing import Optional
from ..cli.config import Config, load_config


def export_config(output_path: Path, config: Optional[Config] = None) -> bool:
    """
    Export current configuration to a file.
    
    Args:
        output_path: Path to save the exported config
        config: Config object to export (will load if None)
        
    Returns:
        True if successful
    """
    if config is None:
        config = load_config()
    
    if not config.config_path or not config.config_path.exists():
        # If no config file exists, create a default export
        from ..cli.config import get_default_config_content
        data = yaml.safe_load(get_default_config_content())
    else:
        # Export the actual config file content
        content = config.config_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, indent=2)
    
    return True
