# reports/sarif_renderer.py

import json, uuid

class SARIFRenderer:

    @staticmethod
    def render(findings, dependencies, meta):

        rules_map = {}
        sarif_results = []

        for f in findings:

            rule_id = f.get("rule", "HEXORA_RULE")
            severity = f.get("severity", "medium")

            level = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note"
            }.get(severity, "warning")

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f.get("category", ""),
                    "shortDescription": { "text": f.get("description", "") },
                    "fullDescription": { "text": f.get("remediation", "") }
                }

            result = {
                "ruleId": rule_id,
                "ruleIndex": 0,
                "level": level,
                "message": { "text": f.get("description", "") },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file")},
                        "region": {"startLine": f.get("line_no") or 1}
                    }
                }],
                "partialFingerprints": {
                    "fingerprintId": str(uuid.uuid4())
                }
            }

            sarif_results.append(result)

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Hexora SAST",
                        "version": "2.0",
                        "informationUri": "https://hexora.security",
                        "rules": list(rules_map.values())
                    }
                },
                "results": sarif_results
            }]
        }

        return json.dumps(sarif, indent=2)