# core/compliance_mapper.py
import json
from pathlib import Path

class ComplianceMapper:

    def __init__(self, rulepack_dir: Path):
        self.rulepack_dir = rulepack_dir
        self.map = self._load("compliance_map.json")

    def _load(self, fname):
        p = self.rulepack_dir / fname
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    def map_compliance(self, cwe):
        return self.map.get(cwe, {})