# core/result_builder.py

class ResultBuilder:

    SEVERITY_MAP = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",

        # NEW enterprise category
        "secret": "critical"
    }

    def normalize(self, finding):
        f = dict(finding)

        # Convert secret findings
        if f.get("type") == "secret":
            f["category"] = "Hardcoded Secret"
            f["severity"] = "critical"
            f.setdefault("rule", "Secret Exposure Detected")
            f.setdefault("description", "A sensitive credential or token was detected in the source code.")
            f.setdefault("remediation", "Remove the secret and rotate the exposed key immediately.")

        # Ensure severity exists
        sev = f.get("severity", "medium")
        f["severity"] = self.SEVERITY_MAP.get(sev, "medium")

        # Normalize other fields
        f.setdefault("category", "General")
        f.setdefault("rule", "Unknown Rule")
        f.setdefault("file", "Unknown")
        f.setdefault("line_no", None)
        f.setdefault("line", "")

        return f

    def build(self, findings):
        return [self.normalize(f) for f in findings]