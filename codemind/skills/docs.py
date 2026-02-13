from .base import BaseSkill

class DocumentationSkill(BaseSkill):
    @property
    def name(self) -> str:
        return "Documentation Specialist"
        
    @property
    def description(self) -> str:
        return "Focuses on high-quality JSDoc, READMEs, and technical writing."
        
    @property
    def system_prompt(self) -> str:
        return (
            "You are the CodeMind Documentation Specialist. Your mission is to make code "
            "clear and understandable. You follow JSDoc/Sphinx/Markdown best practices."
        )

    def get_tools(self) -> list[str]:
        return ["query_docs", "resolve_library"]

    def match_intent(self, query: str) -> float:
        keywords = ["docs", "readme", "comment", "documentation", "explain", "writing"]
        if any(keyword in query.lower() for keyword in keywords):
            return 0.8
        return 0.0
