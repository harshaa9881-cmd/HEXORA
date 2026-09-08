# core/recommendation_engine.py
import json
from pathlib import Path

class RecommendationEngine:

    def __init__(self, kb_path: Path):
        with open(kb_path, "r", encoding="utf-8") as f:
            self.kb = json.load(f)

    def recommend(self, cwe):
        return self.kb.get(cwe, {
            "explanation": "No explanation available.",
            "fix": "No remediation available."
        })