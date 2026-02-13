from .base import BaseSkill

class SecuritySkill(BaseSkill):
    @property
    def name(self) -> str:
        return "Security Guardian"
        
    @property
    def description(self) -> str:
        return "Advanced security auditing, secrets detection, and SAST analysis."
        
    @property
    def system_prompt(self) -> str:
        return (
            "You are the CodeMind Security Guardian. Your primary focus is on identifying vulnerabilities, "
            "leaked secrets, and ensuring high security standards in code. "
            "Always look for SQL injection, XSS, and hardcoded API keys."
        )

    def get_tools(self) -> list[str]:
        return ["guard_code", "scan_secrets", "audit_prompt", "scan_iac_file"]

    def match_intent(self, query: str) -> float:
        keywords = ["security", "vulnerability", "audit", "secret", "leak", "secure", "injection", "xss"]
        if any(keyword in query.lower() for keyword in keywords):
            return 0.9
        return 0.0
