# reports/json_renderer.py

import json

class JSONRenderer:
    @staticmethod
    def render(findings, dependencies, meta):

        for f in findings:
            if f.get("type") == "secret":
                f["category"] = "Hardcoded Secret"
                f["severity"] = "critical"

        return json.dumps({
            "findings": findings,
            "dependencies": dependencies,
            "meta": meta
        }, indent=2)