# languages/config_scanner.py
from core.result_builder import ResultBuilder

class ConfigScanner:

    SENSITIVE_KEYS = [
        "password", "passwd", "secret", "token", "apikey", "api_key",
        "access_key", "private_key"
    ]

    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []
        lines = code.splitlines()

        for i, line in enumerate(lines, start=1):
            lower = line.lower()
            for key in self.SENSITIVE_KEYS:
                if key in lower and "=" in line:
                    findings.append(ResultBuilder.make_finding(
                        filename, i, line,
                        "config_hardcoded_secret", "critical", "CWE-798", 9.8,
                        "A07: Identification & Authentication",
                        "Hardcoded credentials found in config file.",
                        "Replace with environment variable.",
                        "config"
                    ))

        return findings