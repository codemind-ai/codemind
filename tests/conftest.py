"""Pytest fixtures for codemind tests."""

import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def sample_diff():
    """Sample git diff output for testing."""
    return '''diff --git a/main.py b/main.py
index abc1234..def5678 100644
--- a/main.py
+++ b/main.py
@@ -1,5 +1,7 @@
 import os
+import sys
 
 def main():
-    print("Hello")
+    print("Hello World")
+    return 0
'''


@pytest.fixture
def sample_diff_multi_file():
    """Sample diff with multiple files."""
    return '''diff --git a/main.py b/main.py
index abc1234..def5678 100644
--- a/main.py
+++ b/main.py
@@ -1,3 +1,4 @@
 import os
+import sys
 
 def main():
diff --git a/utils.py b/utils.py
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/utils.py
@@ -0,0 +1,5 @@
+def helper():
+    pass
+
+def format_text(text):
+    return text.strip()
'''


@pytest.fixture
def sample_ai_response_clean():
    """Sample AI response with no issues."""
    return '''## 🚨 Critical
None

## ⚠️ Issues
None

## 💡 Suggestions
None
'''


@pytest.fixture
def sample_ai_response_with_issues():
    """Sample AI response with various issues."""
    return '''## 🚨 Critical
- SQL injection vulnerability in `database.py` line 42
- Hardcoded password in `config.py` L15

## ⚠️ Issues
- Missing error handling in `main.py` line 10
- Unused import `os` in utils.py

## 💡 Suggestions
- Consider using f-strings instead of .format()
- Add type hints for better readability
'''


@pytest.fixture
def sample_ai_response_invalid_format():
    """Sample AI response with invalid format."""
    return '''Here are some issues I found:
1. The code could be improved
2. Consider refactoring this function
'''
