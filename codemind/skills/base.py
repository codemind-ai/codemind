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

    def get_tools(self) -> List[str]:
        """List of tools associated with this skill."""
        return []

    def match_intent(self, query: str) -> float:
        """
        Determine how well this skill matches the user query.
        Returns a score between 0.0 and 1.0.
        """
        return 0.0
