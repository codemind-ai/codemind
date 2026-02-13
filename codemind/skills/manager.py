from typing import List, Optional, Type
from .base import BaseSkill
from .security import SecuritySkill
from .ui import UIArchitectSkill
from .docs import DocumentationSkill

class SkillManager:
    def __init__(self):
        self._skills: List[BaseSkill] = [
            SecuritySkill(),
            UIArchitectSkill(),
            DocumentationSkill()
        ]
        self._active_skill: Optional[BaseSkill] = None

    def get_all_skills(self) -> List[BaseSkill]:
        return self._skills

    def detect_skill(self, query: str) -> Optional[BaseSkill]:
        """Automatically detect the best skill for the given query."""
        best_skill = None
        best_score = 0.5 # Threshold
        
        for skill in self._skills:
            score = skill.match_intent(query)
            if score > best_score:
                best_score = score
                best_skill = skill
        
        return best_skill

    def activate_skill(self, name: str) -> bool:
        for skill in self._skills:
            if skill.name.lower() == name.lower():
                self._active_skill = skill
                return True
        return False

    @property
    def active_skill(self) -> Optional[BaseSkill]:
        return self._active_skill
