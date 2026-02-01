"""Tests for config module with schema validation."""

import pytest
import tempfile
from pathlib import Path

from codemind.cli.config import ConfigLoader, load_config, Config


class TestConfigSchemaValidation:
    """Tests for YAML schema validation."""
    
    def test_valid_config_loads_successfully(self, temp_dir):
        """Test that valid config loads without errors."""
        config_content = """
enabled: ask
ide:
  preferred:
    - cursor
    - vscode
  auto_inject: true
  auto_submit: false
review:
  max_comments: 5
  strict_format: true
  fail_on:
    - security
rules:
  review_only_diff: true
  allow_feature_suggestions: false
prompt:
  extra_rules: []
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        config = loader.load()
        
        assert config.enabled == "ask"
        assert config.review.max_comments == 5
    
    def test_invalid_enabled_value(self, temp_dir):
        """Test that invalid 'enabled' value raises error."""
        config_content = """
enabled: invalid_value
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        assert "'enabled' must be one of" in str(exc_info.value)
    
    def test_invalid_max_comments_type(self, temp_dir):
        """Test that non-integer max_comments raises error."""
        config_content = """
review:
  max_comments: "five"
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        assert "'review.max_comments' must be an integer" in str(exc_info.value)
    
    def test_max_comments_out_of_range(self, temp_dir):
        """Test that max_comments out of range raises error."""
        config_content = """
review:
  max_comments: 500
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        assert "must be between 1 and 100" in str(exc_info.value)
    
    def test_invalid_auto_inject_type(self, temp_dir):
        """Test that non-boolean auto_inject raises error."""
        config_content = """
ide:
  auto_inject: "yes"
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        assert "'ide.auto_inject' must be a boolean" in str(exc_info.value)
    
    def test_invalid_preferred_type(self, temp_dir):
        """Test that non-list preferred raises error."""
        config_content = """
ide:
  preferred: cursor
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        assert "'ide.preferred' must be a list" in str(exc_info.value)
    
    def test_invalid_ide_section_type(self, temp_dir):
        """Test that non-dict ide section raises error."""
        config_content = """
ide: "not a dict"
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        assert "'ide' must be a dictionary" in str(exc_info.value)
    
    def test_multiple_errors_reported(self, temp_dir):
        """Test that multiple validation errors are all reported."""
        config_content = """
enabled: wrong
ide:
  auto_inject: "nope"
review:
  max_comments: "many"
"""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text(config_content)
        
        loader = ConfigLoader(temp_dir)
        with pytest.raises(ValueError) as exc_info:
            loader.load()
        
        error_msg = str(exc_info.value)
        assert "'enabled' must be one of" in error_msg
        assert "'ide.auto_inject'" in error_msg
        assert "'review.max_comments'" in error_msg
    
    def test_empty_config_uses_defaults(self, temp_dir):
        """Test that empty config file uses defaults."""
        config_path = temp_dir / ".codemind.yml"
        config_path.write_text("")
        
        loader = ConfigLoader(temp_dir)
        config = loader.load()
        
        assert config.enabled == "ask"
        assert config.review.max_comments == 5
    
    def test_no_config_file_uses_defaults(self, temp_dir):
        """Test that missing config file uses defaults."""
        loader = ConfigLoader(temp_dir)
        config = loader.load()
        
        assert config.enabled == "ask"
        assert config.config_path is None
