# core/rule_engine.py
import json
from pathlib import Path
import re
from core.result_builder import ResultBuilder

class RuleEngine:

    def __init__(self, rulepack_dir: Path):
        self.rulepack_dir = rulepack_dir

        self.rules = []
        self.sources = {}
        self.sinks = {}
        self.sanitizers = {}
        self.severity_map = {}
        self.owasp_map = {}

        self._load_all_rulepacks()

    # ------------------------------------------------------------
    # Load all rulepacks from rulepacks/ directory
    # ------------------------------------------------------------
    def _load_json(self, name):
        p = self.rulepack_dir / name
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    def _load_all_rulepacks(self):
        # Load primary rulepacks
        cwe_rules = self._load_json("cwe_rules.json")
        crypto_rules = self._load_json("crypto_rules.json")
        dangerous_api = self._load_json("dangerous_api_rules.json")

        self.sources = self._load_json("sources.json")
        self.sinks = self._load_json("sinks.json")
        self.sanitizers = self._load_json("sanitizers.json")
        self.severity_map = self._load_json("severity_map.json")
        self.owasp_map = self._load_json("owasp_2025.json")

        self._merge_rules(cwe_rules)
        self._merge_rules(crypto_rules)
        self._merge_rules(dangerous_api)

    # ------------------------------------------------------------
    def _merge_rules(self, rule_dict):
        for rid, r in rule_dict.items():
            if "pattern" not in r:
                continue
            compiled = re.compile(r["pattern"])
            self.rules.append({
                "id": rid,
                "pattern": compiled,
                "severity": r.get("severity", "low"),
                "languages": r.get("languages", []),
                "cwe": r.get("cwe", "CWE-0"),
                "cvss": r.get("cvss", 0),
                "owasp": r.get("owasp", "N/A"),
                "description": r.get("description", ""),
                "remediation": r.get("remediation", "")
            })

    # ------------------------------------------------------------
    def apply_rules(self, code: str, filename: str, lang: str):
        findings = []

        for rule in self.rules:

            # Skip language mismatch
            langs = rule["languages"]
            if langs and lang not in langs:
                continue

            for m in rule["pattern"].finditer(code):
                line_no = code.count("\n", 0, m.start()) + 1
                snippet = code.splitlines()[line_no - 1]

                findings.append(ResultBuilder.make_finding(
                    filename,
                    line_no,
                    snippet,
                    rule["id"],
                    rule["severity"],
                    rule["cwe"],
                    rule["cvss"],
                    rule["owasp"],
                    rule["description"],
                    rule["remediation"],
                    lang
                ))

        return findings