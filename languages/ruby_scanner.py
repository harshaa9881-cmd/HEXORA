# languages/ruby_scanner.py
from core.result_builder import ResultBuilder

class RubyScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        """
        Ruby AST support in Python is limited, so we use heuristics + regex-style
        scanning until a full tree-sitter grammar is available.
        """
        findings = []
        lines = code.splitlines()

        for i, l in enumerate(lines, start=1):

            # Detect eval
            if "eval(" in l:
                findings.append(ResultBuilder.make_finding(
                    filename, i, l,
                    "ruby_eval_rce", "critical", "CWE-95", 9.8,
                    "A03: Injection",
                    "Ruby eval() is dangerous",
                    "Avoid eval(); use safe parsing.",
                    "ruby"
                ))

            # Detect system()
            if "system(" in l or "`" in l:
                findings.append(ResultBuilder.make_finding(
                    filename, i, l,
                    "ruby_system_rce", "critical", "CWE-78", 9.8,
                    "A03: Injection",
                    "Untrusted input flows to shell in Ruby system call.",
                    "Use Open3 with argument arrays.",
                    "ruby"
                ))

        return findings