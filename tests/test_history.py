"""Tests for review history module."""

import pytest
import json
from pathlib import Path
from datetime import datetime
from codemind.history import (
    ReviewEntry,
    ReviewHistory,
    create_review_entry,
    get_history,
    save_review,
    get_recent_reviews,
    get_review_stats,
    clear_history
)


class TestReviewEntry:
    """Tests for ReviewEntry dataclass."""
    
    def test_create_entry(self):
        """Test creating a review entry."""
        entry = ReviewEntry(
            timestamp="2026-01-01T12:00:00",
            branch="feature/test",
            files_changed=5,
            lines_added=100,
            lines_deleted=50,
            token_estimate=500,
            prompt_hash="abc12345"
        )
        assert entry.branch == "feature/test"
        assert entry.files_changed == 5
        assert entry.lines_added == 100
        assert entry.lines_deleted == 50
    
    def test_entry_to_dict(self):
        """Test converting entry to dict."""
        entry = ReviewEntry(
            timestamp="2026-01-01T12:00:00",
            branch="main",
            files_changed=1,
            lines_added=10,
            lines_deleted=5,
            token_estimate=100,
            prompt_hash="xyz789",
            files=["test.py"]
        )
        data = entry.to_dict()
        
        assert isinstance(data, dict)
        assert data["branch"] == "main"
        assert data["files"] == ["test.py"]
    
    def test_entry_from_dict(self):
        """Test creating entry from dict."""
        data = {
            "timestamp": "2026-01-01T12:00:00",
            "branch": "develop",
            "files_changed": 3,
            "lines_added": 50,
            "lines_deleted": 20,
            "token_estimate": 200,
            "prompt_hash": "hash123",
            "files": None
        }
        entry = ReviewEntry.from_dict(data)
        
        assert entry.branch == "develop"
        assert entry.files_changed == 3


class TestReviewHistory:
    """Tests for ReviewHistory class."""
    
    def test_init_creates_directory(self, temp_dir):
        """Test that init creates directory if missing."""
        history_file = temp_dir / "subdir" / "history.json"
        history = ReviewHistory(history_file)
        
        assert history_file.parent.exists()
    
    def test_add_and_retrieve(self, temp_dir):
        """Test adding and retrieving entries."""
        history_file = temp_dir / "history.json"
        history = ReviewHistory(history_file)
        
        entry = ReviewEntry(
            timestamp="2026-01-01T12:00:00",
            branch="test",
            files_changed=1,
            lines_added=10,
            lines_deleted=5,
            token_estimate=100,
            prompt_hash="abc123"
        )
        
        history.add(entry)
        entries = history.get_all()
        
        assert len(entries) == 1
        assert entries[0].branch == "test"
    
    def test_get_recent(self, temp_dir):
        """Test getting recent entries."""
        history_file = temp_dir / "history.json"
        history = ReviewHistory(history_file)
        
        # Add multiple entries
        for i in range(10):
            entry = ReviewEntry(
                timestamp=f"2026-01-0{i+1}T12:00:00",
                branch=f"branch-{i}",
                files_changed=i,
                lines_added=i * 10,
                lines_deleted=i * 5,
                token_estimate=i * 100,
                prompt_hash=f"hash{i}"
            )
            history.add(entry)
        
        recent = history.get_recent(5)
        
        assert len(recent) == 5
        # Should be the last 5 entries
        assert recent[-1].branch == "branch-9"
    
    def test_clear(self, temp_dir):
        """Test clearing history."""
        history_file = temp_dir / "history.json"
        history = ReviewHistory(history_file)
        
        # Add entries
        for i in range(5):
            entry = ReviewEntry(
                timestamp=f"2026-01-0{i+1}T12:00:00",
                branch=f"branch-{i}",
                files_changed=i,
                lines_added=10,
                lines_deleted=5,
                token_estimate=100,
                prompt_hash=f"hash{i}"
            )
            history.add(entry)
        
        count = history.clear()
        
        assert count == 5
        assert len(history.get_all()) == 0
    
    def test_get_stats(self, temp_dir):
        """Test getting statistics."""
        history_file = temp_dir / "history.json"
        history = ReviewHistory(history_file)
        
        # Add entries
        for i in range(3):
            entry = ReviewEntry(
                timestamp=f"2026-01-0{i+1}T12:00:00",
                branch=f"branch-{i}",
                files_changed=10,
                lines_added=100,
                lines_deleted=50,
                token_estimate=500,
                prompt_hash=f"hash{i}"
            )
            history.add(entry)
        
        stats = history.get_stats()
        
        assert stats["total_reviews"] == 3
        assert stats["total_files_reviewed"] == 30
        assert stats["total_lines_changed"] == 450  # 3 * (100 + 50)
    
    def test_empty_stats(self, temp_dir):
        """Test stats on empty history."""
        history_file = temp_dir / "history.json"
        history = ReviewHistory(history_file)
        
        stats = history.get_stats()
        
        assert stats["total_reviews"] == 0
    
    def test_max_entries_limit(self, temp_dir):
        """Test that history is limited to max entries."""
        history_file = temp_dir / "history.json"
        history = ReviewHistory(history_file)
        
        # Add more than MAX_HISTORY_ENTRIES
        from codemind.history import MAX_HISTORY_ENTRIES
        
        for i in range(MAX_HISTORY_ENTRIES + 10):
            entry = ReviewEntry(
                timestamp=f"2026-01-01T12:00:{i:02d}",
                branch=f"branch-{i}",
                files_changed=1,
                lines_added=1,
                lines_deleted=1,
                token_estimate=10,
                prompt_hash=f"hash{i}"
            )
            history.add(entry)
        
        entries = history.get_all()
        
        assert len(entries) <= MAX_HISTORY_ENTRIES


class TestCreateReviewEntry:
    """Tests for create_review_entry function."""
    
    def test_creates_valid_entry(self):
        """Test creating a valid entry."""
        entry = create_review_entry(
            branch="feature/test",
            files_changed=5,
            lines_added=100,
            lines_deleted=50,
            token_estimate=500,
            prompt_content="Test prompt content",
            files=["a.py", "b.py"]
        )
        
        assert entry.branch == "feature/test"
        assert entry.files_changed == 5
        assert len(entry.prompt_hash) == 8  # First 8 chars of SHA256
        assert entry.files == ["a.py", "b.py"]
    
    def test_generates_unique_hash(self):
        """Test that different content generates different hashes."""
        entry1 = create_review_entry(
            branch="main",
            files_changed=1,
            lines_added=10,
            lines_deleted=5,
            token_estimate=100,
            prompt_content="Content A"
        )
        
        entry2 = create_review_entry(
            branch="main",
            files_changed=1,
            lines_added=10,
            lines_deleted=5,
            token_estimate=100,
            prompt_content="Content B"
        )
        
        assert entry1.prompt_hash != entry2.prompt_hash
    
    def test_timestamp_is_iso_format(self):
        """Test that timestamp is in ISO format."""
        entry = create_review_entry(
            branch="main",
            files_changed=1,
            lines_added=1,
            lines_deleted=1,
            token_estimate=10,
            prompt_content="Test"
        )
        
        # Should be parseable as ISO datetime
        datetime.fromisoformat(entry.timestamp)
