"""Tests for git diff extraction module."""

import pytest
from codemind.git.diff import DiffExtractor, DiffResult, FileDiff, get_diff


class TestFileDiff:
    """Tests for FileDiff dataclass."""
    
    def test_default_values(self):
        """Test FileDiff default values."""
        fd = FileDiff(path="test.py")
        assert fd.path == "test.py"
        assert fd.old_path is None
        assert fd.additions == 0
        assert fd.deletions == 0
        assert fd.is_binary is False
        assert fd.is_new is False
        assert fd.is_deleted is False
        assert fd.is_renamed is False
        assert fd.diff_text == ""
    
    def test_with_values(self):
        """Test FileDiff with custom values."""
        fd = FileDiff(
            path="new.py",
            old_path="old.py",
            additions=10,
            deletions=5,
            is_renamed=True
        )
        assert fd.path == "new.py"
        assert fd.old_path == "old.py"
        assert fd.additions == 10
        assert fd.deletions == 5
        assert fd.is_renamed is True


class TestDiffResult:
    """Tests for DiffResult dataclass."""
    
    def test_empty_result(self):
        """Test empty DiffResult."""
        result = DiffResult()
        assert result.total_files == 0
        assert result.total_additions == 0
        assert result.total_deletions == 0
        assert result.total_lines == 0
        assert result.is_empty is True
    
    def test_with_files(self):
        """Test DiffResult with files."""
        files = [
            FileDiff(path="a.py", additions=10, deletions=5),
            FileDiff(path="b.py", additions=20, deletions=3),
        ]
        result = DiffResult(
            files=files,
            total_files=2,
            total_additions=30,
            total_deletions=8
        )
        assert result.total_files == 2
        assert result.total_lines == 38
        assert result.is_empty is False


class TestDiffExtractor:
    """Tests for DiffExtractor class."""
    
    def test_parse_simple_diff(self, sample_diff):
        """Test parsing a simple diff."""
        extractor = DiffExtractor()
        result = extractor._parse_diff(sample_diff)
        
        assert result.total_files == 1
        assert len(result.files) == 1
        
        file = result.files[0]
        assert file.path == "main.py"
        assert file.additions == 3  # +import sys, +print World, +return 0
        assert file.deletions == 1  # -print Hello
    
    def test_parse_multi_file_diff(self, sample_diff_multi_file):
        """Test parsing diff with multiple files."""
        extractor = DiffExtractor()
        result = extractor._parse_diff(sample_diff_multi_file)
        
        assert result.total_files == 2
        assert len(result.files) == 2
        
        # First file
        assert result.files[0].path == "main.py"
        
        # Second file (new file)
        assert result.files[1].path == "utils.py"
        assert result.files[1].is_new is True
    
    def test_parse_empty_diff(self):
        """Test parsing empty diff."""
        extractor = DiffExtractor()
        result = extractor._parse_diff("")
        
        assert result.is_empty is True
        assert result.total_files == 0
    
    def test_parse_binary_file(self):
        """Test detection of binary files."""
        binary_diff = '''diff --git a/image.png b/image.png
new file mode 100644
Binary files /dev/null and b/image.png differ
'''
        extractor = DiffExtractor()
        result = extractor._parse_diff(binary_diff)
        
        assert result.total_files == 1
        assert result.files[0].is_binary is True
    
    def test_parse_deleted_file(self):
        """Test detection of deleted files."""
        deleted_diff = '''diff --git a/old.py b/old.py
deleted file mode 100644
index abc1234..0000000
--- a/old.py
+++ /dev/null
@@ -1,3 +0,0 @@
-def old_function():
-    pass
'''
        extractor = DiffExtractor()
        result = extractor._parse_diff(deleted_diff)
        
        assert result.total_files == 1
        assert result.files[0].is_deleted is True
        assert result.files[0].deletions == 2
    
    def test_parse_renamed_file(self):
        """Test detection of renamed files."""
        renamed_diff = '''diff --git a/old_name.py b/new_name.py
similarity index 100%
rename from old_name.py
rename to new_name.py
'''
        extractor = DiffExtractor()
        result = extractor._parse_diff(renamed_diff)
        
        assert result.total_files == 1
        assert result.files[0].path == "new_name.py"
        assert result.files[0].old_path == "old_name.py"
        assert result.files[0].is_renamed is True
    
    def test_filter_non_binary(self):
        """Test filtering binary files from result."""
        files = [
            FileDiff(path="code.py", additions=10, deletions=5, is_binary=False),
            FileDiff(path="image.png", is_binary=True),
            FileDiff(path="utils.py", additions=5, deletions=2, is_binary=False),
        ]
        result = DiffResult(
            files=files,
            total_files=3,
            total_additions=15,
            total_deletions=7
        )
        
        extractor = DiffExtractor()
        filtered = extractor.filter_non_binary(result)
        
        assert filtered.total_files == 2
        assert all(not f.is_binary for f in filtered.files)
    
    def test_size_warning(self):
        """Test size warning generation."""
        extractor = DiffExtractor(max_lines=100)
        
        result = DiffResult(total_additions=80, total_deletions=50)
        warning = extractor.check_size_warning(result)
        
        assert warning is not None
        assert "130 lines" in warning
        assert "threshold: 100" in warning
    
    def test_no_size_warning_when_under_limit(self):
        """Test no warning when under limit."""
        extractor = DiffExtractor(max_lines=100)
        
        result = DiffResult(total_additions=30, total_deletions=20)
        warning = extractor.check_size_warning(result)
        
        assert warning is None
