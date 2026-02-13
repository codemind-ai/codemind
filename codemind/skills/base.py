from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseSkill(ABC):
    """Base class for all CodeMind skills."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the skill."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what the skill does."""
        pass
    
    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """The system prompt that activates this skill's persona."""
        pass

    @property
    def safety_lock(self) -> str:
        """Core safety constraints that protect critical data."""
        return (
            "SAFETY LOCK ACTIVATED: You are strictly forbidden from generating or executing "
            "any code that performs destructive operations on production databases without explicit "
            "safety checks. You MUST NEVER: \n"
            "- Use DROP DATABASE or DROP TABLE commands.\n"
            "- Use TRUNCATE commands.\n"
            "- Use DELETE statements without a mandatory WHERE clause.\n"
            "Guaranteed safety: Your actions must prioritize data integrity above all else."
        )

    def get_full_prompt(self) -> str:
        """Returns the complete prompt including skill-specific persona and safety lock."""
        return f"{self.system_prompt}\n\n{self.safety_lock}"

    def get_tools(self) -> List[str]:
        """List of tools associated with this skill."""
        return []

    def match_intent(self, query: str) -> float:
        """
        Determine how well this skill matches the user query.
        Returns a score between 0.0 and 1.0.
        """
        return 0.0
