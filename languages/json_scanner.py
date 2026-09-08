# languages/json_scanner.py
import json
from core.result_builder import ResultBuilder

class JsonScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []
        try:
            data = json.loads(code)
        except:
            return []

        # Detect exposed API keys
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, str) and ("apikey" in key.lower() or "token" in key.lower()):
                    if len(val) > 20:
                        findings.append(ResultBuilder.make_finding(
                            filename, 1, f"{key}: {val}",
                            "json_api_key_exposed", "critical", "CWE-798", 9.8,
                            "A07: Identification & Authentication",
                            "API key exposed in config",
                            "Use environment variables",
                            "json"
                        ))
        return findings