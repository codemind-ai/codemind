"""Tests for MCP server functionality.

Tests Guardian security scanning, documentation fetching, and AI slop detection.
"""

import pytest
from codemind.mcp.guard import (
    Guardian, 
    QualityGuard, 
    SecurityGuard, 
    GuardType,
    GuardReport,
    RuleSeverity
)
from codemind.mcp.docs import detect_frameworks, LIBRARY_ALIASES


class TestSecurityGuard:
    """Tests for security vulnerability detection."""
    
    def test_sql_injection_fstring_detected(self):
        """Detect SQL injection via f-string."""
        code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "test.py")
        sql_issues = [i for i in issues if i.vulnerability_type == "SQL_INJECTION"]
        assert len(sql_issues) > 0, "Should detect SQL injection with f-string"
    
    def test_sql_injection_execute_detected(self):
        """Detect SQL injection via execute with string."""
        code = '''
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "test.py")
        # Check for SQL injection either via vulnerability_type or message
        sql_issues = [i for i in issues if 
                      i.vulnerability_type == "SQL_INJECTION" or 
                      "sql injection" in i.message.lower()]
        assert len(sql_issues) > 0, f"Should detect SQL injection, got: {[i.message for i in issues]}"
    
    def test_xss_innerhtml_detected(self):
        """Detect XSS via innerHTML."""
        code = '''
element.innerHTML = userInput;
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "test.js")
        xss_issues = [i for i in issues if i.vulnerability_type == "XSS"]
        assert len(xss_issues) > 0, "Should detect XSS with innerHTML"
    
    def test_xss_dangerouslySetInnerHTML_detected(self):
        """Detect potential XSS via React dangerouslySetInnerHTML."""
        code = '''
<div dangerouslySetInnerHTML={{ __html: content }} />
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "component.jsx")
        xss_issues = [i for i in issues if i.vulnerability_type == "XSS"]
        assert len(xss_issues) > 0
    
    def test_command_injection_os_system_detected(self):
        """Detect command injection via os.system."""
        code = '''
import os
os.system("rm -rf " + user_path)
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "script.py")
        cmd_issues = [i for i in issues if i.vulnerability_type == "COMMAND_INJECTION"]
        assert len(cmd_issues) > 0
    
    def test_command_injection_shell_true_detected(self):
        """Detect subprocess with shell=True."""
        code = '''
subprocess.run(user_cmd, shell=True)
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "script.py")
        cmd_issues = [i for i in issues if i.vulnerability_type == "COMMAND_INJECTION"]
        assert len(cmd_issues) > 0
    
    def test_credential_exposure_detected(self):
        """Detect hardcoded credentials."""
        code = '''
password = "SuperSecret123!"
api_key = "sk-1234567890abcdef"
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "config.py")
        cred_issues = [i for i in issues if i.vulnerability_type == "CREDENTIAL_EXPOSURE"]
        assert len(cred_issues) >= 2
    
    def test_unsafe_pickle_detected(self):
        """Detect unsafe pickle usage."""
        code = '''
import pickle
data = pickle.loads(untrusted_data)
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "loader.py")
        deser_issues = [i for i in issues if i.vulnerability_type == "UNSAFE_DESERIALIZATION"]
        assert len(deser_issues) > 0
    
    def test_unsafe_yaml_load_detected(self):
        """Detect yaml.load without SafeLoader."""
        code = '''
import yaml
config = yaml.load(file_content)
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "config.py")
        deser_issues = [i for i in issues if i.vulnerability_type == "UNSAFE_DESERIALIZATION"]
        assert len(deser_issues) > 0
    
    def test_eval_detected(self):
        """Detect dangerous eval usage."""
        code = '''
result = eval(user_expression)
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "calculator.py")
        dangerous_issues = [i for i in issues if i.vulnerability_type == "DANGEROUS_FUNCTION"]
        assert len(dangerous_issues) > 0
    
    def test_path_traversal_detected(self):
        """Detect path traversal patterns."""
        code = '''
file_path = "../../../etc/passwd"
'''
        guard = SecurityGuard()
        issues = guard.audit(code, "file_reader.py")
        path_issues = [i for i in issues if i.vulnerability_type == "PATH_TRAVERSAL"]
        assert len(path_issues) > 0


class TestQualityGuard:
    """Tests for AI slop and quality issue detection."""
    
    def test_redundant_comment_detected(self):
        """Detect AI-typical redundant comments."""
        code = '''
// This function returns the sum of two numbers
function add(a, b) {
    return a + b;
}
'''
        guard = QualityGuard()
        issues = guard.audit(code, "math.js")
        assert any("Redundant comment" in i.message for i in issues)
    
    def test_generic_variable_names_detected(self):
        """Detect generic variable names."""
        code = '''
data = fetch_response()
result = process(data)
temp = result.value
'''
        guard = QualityGuard()
        issues = guard.audit(code, "processor.py")
        generic_issues = [i for i in issues if "Generic" in i.message]
        assert len(generic_issues) >= 2
    
    def test_console_log_detected(self):
        """Detect console.log statements."""
        code = '''
console.log("Debug: user =", user);
'''
        guard = QualityGuard()
        issues = guard.audit(code, "app.js")
        assert any("Console statement" in i.message for i in issues)
    
    def test_debugger_statement_detected(self):
        """Detect debugger statements."""
        code = '''
function test() {
    debugger;
    return true;
}
'''
        guard = QualityGuard()
        issues = guard.audit(code, "test.js")
        assert any("Debugger statement" in i.message for i in issues)
    
    def test_print_statement_detected(self):
        """Detect Python print statements."""
        code = '''
print("debugging value:", x)
'''
        guard = QualityGuard()
        issues = guard.audit(code, "debug.py")
        assert any("Print statement" in i.message for i in issues)
    
    def test_todo_comment_detected(self):
        """Detect unresolved TODO comments."""
        code = '''
# TODO: implement error handling
def process():
    pass
'''
        guard = QualityGuard()
        issues = guard.audit(code, "handler.py")
        assert any("TODO" in i.message for i in issues)
    
    def test_bare_except_detected(self):
        """Detect bare except clauses."""
        code = '''
try:
    risky_operation()
except Exception:
    pass
'''
        guard = QualityGuard()
        issues = guard.audit(code, "error_handler.py")
        assert any("except" in i.message.lower() for i in issues)
    
    def test_mutable_default_argument_detected(self):
        """Detect mutable default arguments in Python."""
        code = '''
def add_item(item, items=[]):
    items.append(item)
    return items
'''
        guard = QualityGuard()
        issues = guard.audit(code, "utils.py")
        assert any("Mutable default" in i.message for i in issues)
    
    def test_var_usage_detected(self):
        """Detect 'var' usage in JavaScript."""
        code = '''
var x = 10;
'''
        guard = QualityGuard()
        issues = guard.audit(code, "legacy.js")
        assert any("var" in i.message for i in issues)


class TestGuardian:
    """Tests for the main Guardian orchestrator."""
    
    def test_safe_code_passes(self):
        """Safe code should have high score and is_safe=True."""
        code = '''
import os

def get_user(user_id: int) -> dict:
    """Retrieve user by ID using parameterized query."""
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''
        guardian = Guardian()
        report = guardian.audit(code, "repository.py")
        assert report.is_safe, "Safe code should pass security check"
        assert report.score >= 70
    
    def test_vulnerable_code_fails(self):
        """Vulnerable code should have is_safe=False."""
        code = '''
password = "admin123"
query = f"SELECT * FROM users WHERE name = '{user}'"
eval(user_input)
'''
        guardian = Guardian()
        report = guardian.audit(code, "bad_code.py")
        assert not report.is_safe, "Vulnerable code should fail security check"
        assert report.score < 50
    
    def test_score_calculation(self):
        """Score should decrease based on issue severity."""
        code_with_critical = '''
eval(user_input)
password = "secret123"
'''
        code_clean = '''
from os import environ
secret = environ.get("SECRET_KEY")
'''
        guardian = Guardian()
        
        bad_report = guardian.audit(code_with_critical, "bad.py")
        good_report = guardian.audit(code_clean, "good.py")
        
        assert bad_report.score < good_report.score
    
    def test_security_issues_property(self):
        """security_issues property should filter correctly."""
        code = '''
eval(user_data)  # Security issue
print("debug")    # Quality issue
'''
        guardian = Guardian()
        report = guardian.audit(code, "mixed.py")
        
        assert len(report.security_issues) >= 1
        assert all(i.type == GuardType.SECURITY for i in report.security_issues)
    
    def test_quality_issues_property(self):
        """quality_issues property should filter correctly."""
        code = '''
// This function adds numbers
function add(a, b) { return a + b; }
'''
        guardian = Guardian()
        report = guardian.audit(code, "math.js")
        
        quality = report.quality_issues
        assert all(i.type in (GuardType.QUALITY, GuardType.AI_SLOP) for i in quality)


class TestDocumentation:
    """Tests for documentation fetching utilities."""
    
    def test_detect_react_framework(self):
        """Detect React from imports."""
        code = '''
import { useState, useEffect } from "react";
'''
        detected = detect_frameworks(code)
        assert "react" in detected
    
    def test_detect_fastapi_framework(self):
        """Detect FastAPI from imports and decorators."""
        code = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello"}
'''
        detected = detect_frameworks(code)
        assert "fastapi" in detected
    
    def test_detect_multiple_frameworks(self):
        """Detect multiple frameworks in same code."""
        code = '''
from fastapi import FastAPI
import pytest

@app.get("/")
def read_root():
    pass

@pytest.fixture
def client():
    pass
'''
        detected = detect_frameworks(code)
        # fastapi detected via @app.get decorator
        assert "fastapi" in detected
        assert "pytest" in detected
    
    def test_library_aliases_coverage(self):
        """Common libraries should have aliases."""
        common_libs = [
            "react", "vue", "angular", "svelte",
            "fastapi", "django", "flask", "express",
            "prisma", "mongodb", "postgres", "redis",
            "typescript", "python", "node",
            "pytest", "jest", "vitest",
            "langchain", "openai"
        ]
        for lib in common_libs:
            assert lib in LIBRARY_ALIASES, f"Missing alias for {lib}"
    
    def test_library_alias_format(self):
        """All library aliases should start with /."""
        for name, lib_id in LIBRARY_ALIASES.items():
            assert lib_id.startswith("/"), f"Alias {name} doesn't start with /"
            assert "/" in lib_id[1:], f"Alias {name} should be /org/project format"


class TestRegexCaching:
    """Tests for regex pattern caching."""
    
    def test_patterns_are_cached(self):
        """Compiled patterns should be cached for performance."""
        from codemind.mcp.guard import _compile_pattern
        
        pattern1 = _compile_pattern(r"test\d+")
        pattern2 = _compile_pattern(r"test\d+")
        
        assert pattern1 is pattern2, "Same pattern should return cached object"
    
    def test_different_patterns_differ(self):
        """Different patterns should produce different compiled objects."""
        from codemind.mcp.guard import _compile_pattern
        
        pattern1 = _compile_pattern(r"test\d+")
        pattern2 = _compile_pattern(r"other\w+")
        
        assert pattern1 is not pattern2
