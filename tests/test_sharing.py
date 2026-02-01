"""Tests for configuration sharing."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import yaml

from codemind.sharing.export import export_config
from codemind.sharing.import_config import import_config
from codemind.cli.config import Config


class TestExport:
    """Test configuration export."""
    
    def test_export_default_if_no_config(self, tmp_path):
        output = tmp_path / "exported.yml"
        config = Config() # No path set
        
        result = export_config(output, config)
        
        assert result
        assert output.exists()
        data = yaml.safe_load(output.read_text())
        assert "enabled" in data
    
    def test_export_existing_config(self, tmp_path):
        config_file = tmp_path / ".codemind.yml"
        config_file.write_text("enabled: always\nide:\n  auto_inject: false", encoding="utf-8")
        
        output = tmp_path / "shared.yml"
        config = Config(config_path=config_file)
        
        result = export_config(output, config)
        
        assert result
        data = yaml.safe_load(output.read_text())
        assert data["enabled"] == "always"
        assert data["ide"]["auto_inject"] is False


class TestImport:
    """Test configuration import."""
    
    def test_import_from_file(self, tmp_path):
        source = tmp_path / "source.yml"
        source.write_text("enabled: never", encoding="utf-8")
        
        target = tmp_path / ".codemind.yml"
        
        result = import_config(str(source), target)
        
        assert result
        assert target.exists()
        assert target.read_text() == "enabled: never"
    
    @patch('requests.get')
    def test_import_from_url(self, mock_get, tmp_path):
        mock_response = MagicMock()
        mock_response.text = "enabled: always"
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        target = tmp_path / ".codemind.yml"
        
        result = import_config("https://example.com/config.yml", target)
        
        assert result
        assert target.read_text() == "enabled: always"
    
    def test_import_invalid_yaml(self, tmp_path):
        source = tmp_path / "bad.yml"
        source.write_text("this is not: yaml: :", encoding="utf-8")
        
        target = tmp_path / ".codemind.yml"
        
        with pytest.raises(ValueError, match="Invalid YAML"):
            import_config(str(source), target)
