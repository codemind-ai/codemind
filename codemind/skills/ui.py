from .base import BaseSkill

class UIArchitectSkill(BaseSkill):
    @property
    def name(self) -> str:
        return "UI Architect"
        
    @property
    def description(self) -> str:
        return "Expert in modern web design, CSS, and user experience patterns."
        
    @property
    def system_prompt(self) -> str:
        return (
            "You are the CodeMind UI Architect. You specialize in creating stunning, responsive, "
            "and accessible user interfaces using Vanilla CSS, Tailwind, and React. "
            "Focus on aesthetics, glassmorphism, and smooth animations."
        )

    def match_intent(self, query: str) -> float:
        keywords = ["ui", "css", "layout", "design", "component", "styling", "frontend", "react", "navbar"]
        if any(keyword in query.lower() for keyword in keywords):
            return 0.85
        return 0.0
