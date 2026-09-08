# languages/yaml_scanner.py
import yaml
from core.result_builder import ResultBuilder

class YamlScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []
        try:
            data = yaml.safe_load(code)
        except:
            return []

        # Detect privileged Docker/K8s configs
        if isinstance(data, dict):
            if "securityContext" in data:
                sc = data["securityContext"]
                if sc.get("privileged") is True:
                    findings.append(ResultBuilder.make_finding(
                        filename, 1, "privileged: true",
                        "k8s_privileged_container", "high", "CWE-250", 7.5,
                        "A05: Security Misconfiguration",
                        "Privileged containers are dangerous",
                        "Remove privileged flag",
                        "yaml"
                    ))
        return findings