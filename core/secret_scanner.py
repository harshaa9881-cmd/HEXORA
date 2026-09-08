import re
import base64

class SecretScanner:
    """
    Detects hardcoded secrets in any text file.
    Supports: AWS, GCP, Azure, OAuth, API Keys, Passwords, Tokens.
    """

    def __init__(self):
        # Regex signatures for enterprise-level detection
        self.patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'(?i)aws(.{0,20})?(secret|access)?.{0,3}['"\']([A-Za-z0-9/+=]{40})['"\']',
            "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
            "Google OAuth Refresh Token": r'ya29\.[0-9A-Za-z\-_]+',
            "Azure Connection String": r'Endpoint=sb:\/\/.*\.servicebus\.windows\.net\/;SharedAccessKeyName=.*;SharedAccessKey=.*',
            "Slack Token": r'xox[baprs]-[0-9A-Za-z-]{10,48}',
            "Stripe Key": r'sk_live_[0-9a-zA-Z]{24}',
            "JWT": r'eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9._-]+?\.[a-zA-Z0-9._-]+',
            "Basic Auth Password": r'(?i)(password|pwd|pass)["\']?\s*[:=]\s*["\'](.{4,})["\']',
        }

    def scan_text(self, text):
        findings = []

        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings.append({
                    "type": "secret",
                    "name": name,
                    "value": str(matches[0])[:80] + "...",
                    "severity": "critical"
                })

        # Base64 secret detection
        for token in re.findall(r'[A-Za-z0-9+/=]{20,}', text):
            try:
                decoded = base64.b64decode(token).decode()
                if any(x in decoded.lower() for x in ["key", "secret", "token", "password"]):
                    findings.append({
                        "type": "secret",
                        "name": "Base64-Encoded Secret",
                        "value": token[:50] + "...",
                        "severity": "high"
                    })
            except Exception:
                pass

        return findings