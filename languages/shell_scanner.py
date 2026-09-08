# languages/shell_scanner.py
from core.result_builder import ResultBuilder

class ShellScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []
        lines = code.splitlines()

        for i, l in enumerate(lines, start=1):
            if "rm -rf /" in l:
                findings.append(ResultBuilder.make_finding(
                    filename, i, l,
                    "dangerous_rm", "critical", "CWE-489", 9.8,
                    "A05: Security Misconfiguration",
                    "Dangerous rm usage",
                    "Avoid destructive wildcard commands",
                    "shell"
                ))

        return findings