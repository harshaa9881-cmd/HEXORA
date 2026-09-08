# core/taint_engine.py
from core.result_builder import ResultBuilder
import re

class TaintEngine:

    def __init__(self, sources, sinks, sanitizers):
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers

    def _is_source(self, line, lang):
        return any(s in line for s in self.sources.get(lang, []))

    def _is_sink(self, line, lang):
        return any(s in line for s in self.sinks.get(lang, []))

    def _is_sanitized(self, line, lang):
        return any(s in line for s in self.sanitizers.get(lang, []))

    def analyze(self, code: str, filename: str, lang: str):
        tainted = set()
        findings = []

        lines = code.splitlines()

        for i, line in enumerate(lines, start=1):

            # Detect tainted assignment
            if self._is_source(line, lang):
                match = re.match(r"(\w+)\s*=", line.strip())
                if match:
                    tainted.add(match.group(1))

            # Propagation
            for var in list(tainted):
                if var in line and not self._is_sanitized(line, lang):
                    if self._is_sink(line, lang):
                        findings.append(ResultBuilder.make_finding(
                            filename, i, line,
                            "taint_flow_detected",
                            "critical",
                            "CWE-20",
                            9.1,
                            "A03: Injection",
                            "User input reaches dangerous sink.",
                            "Validate/sanitize inputs or use safe APIs.",
                            lang
                        ))

        return findings