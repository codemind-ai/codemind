"""AST-based analysis engine."""

import ast
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from pathlib import Path

@dataclass
class Finding:
    """A security or quality finding from AST analysis."""
    type: str
    message: str
    severity: str
    line: int
    column: int
    suggestion: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

class PythonASTAnalyzer(ast.NodeVisitor):
    """Python-specific AST analyzer."""
    
    def __init__(self, code: str):
        self.code = code
        self.findings: List[Finding] = []
        self.lines = code.splitlines()
        self.tainted_vars = set()

    def analyze(self) -> List[Finding]:
        try:
            tree = ast.parse(self.code)
            self.visit(tree)
        except SyntaxError:
            # If valid code fails to parse, we can't do AST analysis
            pass
        return self.findings

    def _is_external_call(self, n):
        if isinstance(n, ast.Call):
            # Check for common external sources
            if isinstance(n.func, ast.Attribute) and n.func.attr in {'get', 'post', 'urlopen', 'read', 'readlines'}:
                return True
            if isinstance(n.func, ast.Name) and n.func.id in {'open'}:
                return True
        if isinstance(n, ast.Attribute):
            return self._is_external_call(n.value)
        return False

    def _get_involved_vars(self, n):
        vars = set()
        for node in ast.walk(n):
            if isinstance(node, ast.Name):
                vars.add(node.id)
        return vars

    def visit_Call(self, node: ast.Call):
        # 1. Detect SQL Injection (format/f-string in cursor.execute)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if len(node.args) > 0:
                first_arg = node.args[0]
                is_unsafe = False
                
                # f-string: cursor.execute(f"...")
                if isinstance(first_arg, ast.JoinedStr):
                    is_unsafe = True
                
                # .format(): cursor.execute("...".format(...))
                elif isinstance(first_arg, ast.Call):
                    if isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format':
                        is_unsafe = True
                
                if is_unsafe:
                    self.findings.append(Finding(
                        type="SQL_INJECTION",
                        message="Potential SQL injection: using string formatting in execute(). Use parameterized queries.",
                        severity="CRITICAL",
                        line=node.lineno,
                        column=node.col_offset,
                        suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021-Injection"
                    ))

        # 2. Detect shell execution
        shell_funcs = {
            'os': ['system', 'popen'],
            'subprocess': ['run', 'call', 'check_call', 'check_output', 'Popen']
        }
        
        func_name = None
        module_name = None
        
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            
        if module_name in shell_funcs and func_name in shell_funcs[module_name]:
            # Check for shell=True in subprocess
            is_shell_true = False
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    is_shell_true = True
            
            if module_name == 'os' or is_shell_true:
                self.findings.append(Finding(
                    type="COMMAND_INJECTION",
                    message=f"Potential command injection: unsafe shell execution via {module_name}.{func_name}.",
                    severity="CRITICAL",
                    line=node.lineno,
                    column=node.col_offset,
                    suggestion="Set shell=False and pass arguments as a list.",
                    cwe_id="CWE-78",
                    owasp_category="A03:2021-Injection"
                ))

        # 3. Detect eval/exec
        if func_name in ['eval', 'exec'] and module_name is None:
            self.findings.append(Finding(
                type="UNSAFE_EXECUTION",
                message=f"Dangerous use of {func_name}(). This can lead to arbitrary code execution.",
                severity="CRITICAL",
                line=node.lineno,
                column=node.col_offset,
                suggestion="Avoid eval/exec; use safer alternatives like ast.literal_eval() for data.",
                cwe_id="CWE-94",
                owasp_category="A03:2021-Injection"
            ))

        # 4. Detect yaml.load without safe loader
        if module_name == 'yaml' and func_name == 'load':
            is_unsafe = True
            for keyword in node.keywords:
                if keyword.arg == 'Loader' and isinstance(keyword.value, ast.Attribute):
                    if keyword.value.attr in ['SafeLoader', 'FullLoader']:
                        is_unsafe = False
            
            if is_unsafe:
                self.findings.append(Finding(
                    type="UNSAFE_DESERIALIZATION",
                    message="Potentially unsafe yaml.load() call. Use yaml.safe_load() or specify SafeLoader.",
                    severity="HIGH",
                    line=node.lineno,
                    column=node.col_offset,
                    suggestion="Use yaml.safe_load(data) instead.",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021-Software and Data Integrity Failures"
                ))

        # 5. Detect absolute path traversal in open()
        if func_name == 'open' and module_name is None:
            if len(node.args) > 0:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    if first_arg.value.startswith('/') or first_arg.value.startswith('C:\\'):
                        self.findings.append(Finding(
                            type="PATH_TRAVERSAL",
                            message="Hardcoded absolute path in open(). This may cause path traversal issues.",
                            severity="MEDIUM",
                            line=node.lineno,
                            column=node.col_offset,
                            suggestion="Use relative paths or sanitize input via os.path.basename().",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021-Broken Access Control"
                        ))
        
        # 6. Detect AI/LLM calls with potentially injected content
        ai_libs = {'openai', 'anthropic', 'langchain', 'ollama'}
        if module_name in ai_libs or (func_name and any(ai in func_name.lower() for ai in ai_libs)):
             # Check messages/prompt arguments
             for keyword in node.keywords:
                 if keyword.arg in ['messages', 'prompt', 'input']:
                     if isinstance(keyword.value, ast.JoinedStr):
                         self.findings.append(Finding(
                            type="PROMPT_INJECTION",
                            message="Critical AI Security: Direct user input formatting in LLM call.",
                            severity="CRITICAL",
                            line=node.lineno,
                            column=node.col_offset,
                            suggestion="Separate system instructions from user data using distinct roles or delimiters.",
                            cwe_id="CWE-116",
                            owasp_category="A03:2021-Injection"
                         ))


        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # 1. Track tainted variables from external sources
        if self._is_external_call(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        # 2. Detect prompt construction with user input or tainted data
        prompt_vars = {'prompt', 'query', 'payload', 'message', 'instruction'}
        for target in node.targets:
            if isinstance(target, ast.Name) and any(p in target.id.lower() for p in prompt_vars):
                is_unsafe_fmt = False
                if isinstance(node.value, ast.JoinedStr):
                    is_unsafe_fmt = True
                elif isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'format':
                        is_unsafe_fmt = True
                elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    is_unsafe_fmt = True
                
                if is_unsafe_fmt:
                    self.findings.append(Finding(
                        type="PROMPT_INJECTION",
                        message=f"Potential prompt injection: constructing '{target.id}' using string formatting.",
                        severity="HIGH",
                        line=node.lineno,
                        column=node.col_offset,
                        suggestion="Use a secure template engine or clear XML-like delimiters for user input within the prompt.",
                        cwe_id="CWE-116",
                        owasp_category="A03:2021-Injection"
                    ))
                
                # Check for tainted data involvement (Indirect Injection Risk)
                involved = self._get_involved_vars(node.value)
                if involved.intersection(self.tainted_vars) or self._is_external_call(node.value):
                    self.findings.append(Finding(
                        type="INDIRECT_INJECTION_RISK",
                        message=f"Indirect Injection Risk: Feeding potential external data into '{target.id}'.",
                        severity="HIGH",
                        line=node.lineno,
                        column=node.col_offset,
                        suggestion="Treat data from external sources as untrusted. Sanitize and wrap in clear delimiters.",
                        cwe_id="CWE-116",
                        owasp_category="A03:2021-Injection"
                    ))

                # Detect Persona Shift/Jailbreak keywords in assigned strings
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    evasion_words = {'dan mode', 'developer mode', 'ignore all previous', 'disregard prior'}
                    if any(w in node.value.value.lower() for w in evasion_words):
                        self.findings.append(Finding(
                            type="JAILBREAK_ATTEMPT",
                            message=f"Detected jailbreak/evasion phrase in '{target.id}'.",
                            severity="CRITICAL",
                            line=node.lineno,
                            column=node.col_offset,
                            suggestion="Remove instructions that attempt to bypass safety filters.",
                            cwe_id="CWE-116",
                            owasp_category="A03:2021-Injection"
                        ))
        self.generic_visit(node)







    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in ['pickle', 'marshal', 'shelve']:
                self.findings.append(Finding(
                    type="UNSAFE_DESERIALIZATION",
                    message=f"Unsafe deserialization library '{alias.name}' imported.",
                    severity="MEDIUM",
                    line=node.lineno,
                    column=node.col_offset,
                    suggestion="Use safer formats like JSON or XML for untrusted data.",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021-Software and Data Integrity Failures"
                ))
        self.generic_visit(node)

class ASTAnalyzer:
    """Main entry point for AST-based analysis."""
    
    def __init__(self):
        # In a full implementation, we would initialize tree-sitter here for other languages
        pass

    def analyze(self, code: str, language: str = "python") -> List[Finding]:
        l = language.lower()
        if l == "python":
            analyzer = PythonASTAnalyzer(code)
            return analyzer.analyze()
        
        if l in ["javascript", "typescript", "js", "ts"]:
            return self._analyze_js_ts(code)
        
        return []

    def _analyze_js_ts(self, code: str) -> List[Finding]:
        """Basic security analysis for JS/TS."""
        findings = []
        import re
        
        # 1. React: dangerouslySetInnerHTML
        danger_pattern = re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*(.*?)\s*\}\}')
        for match in danger_pattern.finditer(code):
            findings.append(Finding(
                type="XSS",
                message="Use of dangerouslySetInnerHTML detected. This can lead to XSS vulnerabilities.",
                severity="HIGH",
                line=code.count('\n', 0, match.start()) + 1,
                column=match.start(),
                suggestion="Sanitize HTML content using DOMPurify before setting it.",
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection"
            ))

        # 2. innerHTML / outerHTML
        dom_pattern = re.compile(r'\.(innerHTML|outerHTML)\s*=\s*([^;]+)')
        for match in dom_pattern.finditer(code):
            findings.append(Finding(
                type="XSS",
                message=f"Direct assignment to {match.group(1)} detected. Potential XSS.",
                severity="MEDIUM",
                line=code.count('\n', 0, match.start()) + 1,
                column=match.start(),
                suggestion="Use textContent or innerText instead of innerHTML for user-controlled data.",
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection"
            ))

        # 3. eval()
        eval_pattern = re.compile(r'\beval\s*\(')
        for match in eval_pattern.finditer(code):
            findings.append(Finding(
                type="UNSAFE_EXECUTION",
                message="Use of eval() detected in JavaScript. Highly dangerous.",
                severity="CRITICAL",
                line=code.count('\n', 0, match.start()) + 1,
                column=match.start(),
                suggestion="Use JSON.parse() for data or safe alternates.",
                cwe_id="CWE-94",
                owasp_category="A03:2021-Injection"
            ))
            
        return findings
