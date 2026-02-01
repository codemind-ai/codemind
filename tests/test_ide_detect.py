"""Tests for IDE detection module."""

import pytest
from unittest.mock import patch, MagicMock
from codemind.ide.detect import (
    IDEType,
    DetectedIDE,
    IDEDetector,
    detect_ides,
    detect_preferred_ide,
    IDE_PATTERNS
)


class TestIDEType:
    """Tests for IDEType enum."""
    
    def test_ide_type_values(self):
        """Test IDE type enum values."""
        assert IDEType.CURSOR.value == "cursor"
        assert IDEType.CLAUDE_CODE.value == "claude-code"
        assert IDEType.WINDSURF.value == "windsurf"
        assert IDEType.VSCODE.value == "vscode"
        assert IDEType.UNKNOWN.value == "unknown"


class TestDetectedIDE:
    """Tests for DetectedIDE dataclass."""
    
    def test_cursor_display_name(self):
        """Test Cursor display name."""
        ide = DetectedIDE(
            ide_type=IDEType.CURSOR,
            window_title="Cursor - project"
        )
        assert ide.display_name == "Cursor"
    
    def test_claude_code_display_name(self):
        """Test Claude Code display name."""
        ide = DetectedIDE(
            ide_type=IDEType.CLAUDE_CODE,
            window_title="Claude - project"
        )
        assert ide.display_name == "Claude Code"
    
    def test_windsurf_display_name(self):
        """Test Windsurf display name."""
        ide = DetectedIDE(
            ide_type=IDEType.WINDSURF,
            window_title="Windsurf - project"
        )
        assert ide.display_name == "Windsurf"
    
    def test_vscode_display_name(self):
        """Test VS Code display name."""
        ide = DetectedIDE(
            ide_type=IDEType.VSCODE,
            window_title="Visual Studio Code"
        )
        assert ide.display_name == "VS Code"
    
    def test_cursor_chat_shortcut(self):
        """Test Cursor chat shortcut."""
        ide = DetectedIDE(
            ide_type=IDEType.CURSOR,
            window_title="Cursor - project"
        )
        assert ide.chat_shortcut == "ctrl+l"
    
    def test_claude_code_chat_shortcut(self):
        """Test Claude Code chat shortcut."""
        ide = DetectedIDE(
            ide_type=IDEType.CLAUDE_CODE,
            window_title="Claude - project"
        )
        assert ide.chat_shortcut == "ctrl+shift+p"
    
    def test_vscode_chat_shortcut(self):
        """Test VS Code chat shortcut."""
        ide = DetectedIDE(
            ide_type=IDEType.VSCODE,
            window_title="Visual Studio Code"
        )
        assert ide.chat_shortcut == "ctrl+shift+i"


class TestIDEPatterns:
    """Tests for IDE detection patterns."""
    
    def test_cursor_patterns(self):
        """Test Cursor detection patterns."""
        patterns = IDE_PATTERNS[IDEType.CURSOR]
        assert "Cursor" in patterns
        assert "cursor" in patterns
    
    def test_claude_code_patterns(self):
        """Test Claude Code detection patterns."""
        patterns = IDE_PATTERNS[IDEType.CLAUDE_CODE]
        assert "Claude" in patterns
        assert "claude" in patterns
    
    def test_vscode_patterns(self):
        """Test VS Code detection patterns."""
        patterns = IDE_PATTERNS[IDEType.VSCODE]
        assert "Visual Studio Code" in patterns
        assert "Code - " in patterns


class TestIDEDetector:
    """Tests for IDEDetector class."""
    
    def test_identify_cursor(self):
        """Test identifying Cursor from window title."""
        detector = IDEDetector()
        result = detector._identify_ide("Cursor - my-project")
        
        assert result is not None
        assert result.ide_type == IDEType.CURSOR
    
    def test_identify_vscode(self):
        """Test identifying VS Code from window title."""
        detector = IDEDetector()
        result = detector._identify_ide("Visual Studio Code")
        
        assert result is not None
        assert result.ide_type == IDEType.VSCODE
    
    def test_identify_unknown_window(self):
        """Test identifying unknown window."""
        detector = IDEDetector()
        result = detector._identify_ide("Notepad")
        
        assert result is None
    
    def test_detect_preferred_with_preferences(self):
        """Test detection with preferences."""
        detector = IDEDetector()
        
        # Mock detect_all to return multiple IDEs
        with patch.object(detector, 'detect_all') as mock_detect:
            mock_detect.return_value = [
                DetectedIDE(ide_type=IDEType.VSCODE, window_title="VS Code"),
                DetectedIDE(ide_type=IDEType.CURSOR, window_title="Cursor"),
            ]
            
            # Cursor should be preferred over VS Code by default
            result = detector.detect_preferred()
            
            assert result is not None
            assert result.ide_type == IDEType.CURSOR
    
    def test_detect_preferred_with_custom_preference(self):
        """Test detection with custom preferences."""
        detector = IDEDetector()
        
        with patch.object(detector, 'detect_all') as mock_detect:
            mock_detect.return_value = [
                DetectedIDE(ide_type=IDEType.CURSOR, window_title="Cursor"),
                DetectedIDE(ide_type=IDEType.VSCODE, window_title="VS Code"),
            ]
            
            # Request VS Code preference
            result = detector.detect_preferred([IDEType.VSCODE, IDEType.CURSOR])
            
            assert result is not None
            assert result.ide_type == IDEType.VSCODE
    
    def test_detect_preferred_no_match(self):
        """Test detection when no preferred IDE found."""
        detector = IDEDetector()
        
        with patch.object(detector, 'detect_all') as mock_detect:
            mock_detect.return_value = []
            
            result = detector.detect_preferred()
            
            assert result is None


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_detect_ides_function(self):
        """Test detect_ides convenience function."""
        with patch('codemind.ide.detect.IDEDetector') as MockDetector:
            mock_instance = MagicMock()
            mock_instance.detect_all.return_value = []
            MockDetector.return_value = mock_instance
            
            result = detect_ides()
            
            assert result == []
            mock_instance.detect_all.assert_called_once()
    
    def test_detect_preferred_ide_function(self):
        """Test detect_preferred_ide convenience function."""
        with patch('codemind.ide.detect.IDEDetector') as MockDetector:
            mock_instance = MagicMock()
            mock_instance.detect_preferred.return_value = None
            MockDetector.return_value = mock_instance
            
            result = detect_preferred_ide()
            
            assert result is None
            mock_instance.detect_preferred.assert_called_once()
