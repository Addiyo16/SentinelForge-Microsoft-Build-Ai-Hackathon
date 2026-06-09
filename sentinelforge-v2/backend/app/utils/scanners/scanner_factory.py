"""
SentinelForge — Scanner Factory
Instantiates and routes to the correct AST scanner engine for a given language.
"""

from app.utils.scanners.base_scanner import BaseScanner
from app.utils.scanners.python_scanner import PythonScanner
from app.utils.scanners.js_scanner import JavascriptScanner
from app.utils.scanners.java_scanner import JavaScanner
from app.utils.scanners.go_scanner import GoScanner
from app.utils.scanners.cpp_scanner import CppScanner
from app.utils.scanners.yaml_scanner import YamlScanner


def get_scanner(lang: str) -> BaseScanner:
    """
    Factory method to retrieve a code scanner for the specified language.
    Supported: 'python', 'javascript', 'typescript', 'java', 'go', 'c', 'c++', 'yaml'
    """
    l = lang.lower().strip()
    if l == "python":
        return PythonScanner()
    elif l in ("javascript", "typescript", "js", "ts"):
        return JavascriptScanner()
    elif l == "java":
        return JavaScanner()
    elif l == "go":
        return GoScanner()
    elif l in ("c", "c++", "cpp", "c_cpp"):
        return CppScanner()
    elif l in ("yaml", "yml"):
        return YamlScanner()
    else:
        # Default fallback is CppScanner which uses generic_fallback
        return CppScanner()
