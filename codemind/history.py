"""Review history module.

Stores and retrieves past review prompts and metadata.
"""

import json
import os
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


# Default history file location
HISTORY_DIR = Path.home() / ".codemind"
HISTORY_FILE = HISTORY_DIR / "history.json"
MAX_HISTORY_ENTRIES = 50


@dataclass
class ReviewEntry:
    """A single review history entry."""
    timestamp: str
    branch: str
    files_changed: int
    lines_added: int
    lines_deleted: int
    token_estimate: int
    prompt_hash: str  # First 8 chars of content hash
    
    # Optional: stored for reference
    files: Optional[list[str]] = None
    ai_response: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> "ReviewEntry":
        return cls(**data)


class ReviewHistory:
    """Manages review history storage and retrieval."""
    
    def __init__(self, history_file: Optional[Path] = None):
        self.history_file = history_file or HISTORY_FILE
        self._ensure_dir()
    
    def _ensure_dir(self) -> None:
        """Ensure history directory exists."""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _load(self) -> list[dict]:
        """Load history from file."""
        if not self.history_file.exists():
            return []
        
        try:
            content = self.history_file.read_text(encoding="utf-8")
            return json.loads(content)
        except (json.JSONDecodeError, IOError):
            return []
    
    def _save(self, entries: list[dict]) -> None:
        """Save history to file atomically.
        
        Uses temp file + atomic rename to prevent corruption if interrupted.
        """
        # Limit entries
        entries = entries[-MAX_HISTORY_ENTRIES:]
        content = json.dumps(entries, indent=2)
        
        # Atomic write: write to temp file, then rename
        fd, temp_path = tempfile.mkstemp(
            dir=self.history_file.parent,
            prefix=".history_",
            suffix=".tmp"
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            # Atomic rename (on same filesystem)
            os.replace(temp_path, self.history_file)
        except Exception:
            # Clean up temp file on error
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
    
    def add(self, entry: ReviewEntry) -> None:
        """Add a new review entry to history."""
        entries = self._load()
        entries.append(entry.to_dict())
        self._save(entries)
    
    def get_recent(self, count: int = 10) -> list[ReviewEntry]:
        """Get most recent review entries."""
        entries = self._load()
        return [ReviewEntry.from_dict(e) for e in entries[-count:]]
    
    def get_all(self) -> list[ReviewEntry]:
        """Get all review entries."""
        entries = self._load()
        return [ReviewEntry.from_dict(e) for e in entries]
    
    def clear(self) -> int:
        """Clear all history. Returns number of entries cleared."""
        count = len(self._load())
        self._save([])
        return count
    
    def get_stats(self) -> dict:
        """Get summary statistics."""
        entries = self.get_all()
        if not entries:
            return {"total_reviews": 0}
        
        return {
            "total_reviews": len(entries),
            "total_files_reviewed": sum(e.files_changed for e in entries),
            "total_lines_changed": sum(e.lines_added + e.lines_deleted for e in entries),
            "avg_files_per_review": sum(e.files_changed for e in entries) / len(entries),
            "first_review": entries[0].timestamp,
            "last_review": entries[-1].timestamp,
        }


def create_review_entry(
    branch: str,
    files_changed: int,
    lines_added: int,
    lines_deleted: int,
    token_estimate: int,
    prompt_content: str,
    files: list[str] = None,
    ai_response: str = None
) -> ReviewEntry:
    """Create a new review entry."""
    import hashlib
    
    prompt_hash = hashlib.sha256(prompt_content.encode()).hexdigest()[:8]
    
    return ReviewEntry(
        timestamp=datetime.now().isoformat(),
        branch=branch,
        files_changed=files_changed,
        lines_added=lines_added,
        lines_deleted=lines_deleted,
        token_estimate=token_estimate,
        prompt_hash=prompt_hash,
        files=files or [],
        ai_response=ai_response
    )


# Convenience functions
_history = None

def get_history() -> ReviewHistory:
    """Get global history instance."""
    global _history
    if _history is None:
        _history = ReviewHistory()
    return _history

def save_review(
    branch: str,
    files_changed: int,
    lines_added: int,
    lines_deleted: int,
    token_estimate: int,
    prompt_content: str,
    files: list[str] = None,
    ai_response: str = None
) -> None:
    """Save a review to history."""
    entry = create_review_entry(
        branch, files_changed, lines_added, lines_deleted,
        token_estimate, prompt_content, files, ai_response
    )
    get_history().add(entry)

def get_recent_reviews(count: int = 10) -> list[ReviewEntry]:
    """Get recent reviews."""
    return get_history().get_recent(count)

def get_review_stats() -> dict:
    """Get review statistics."""
    return get_history().get_stats()

def clear_history() -> int:
    """Clear all history."""
    return get_history().clear()
