#!/usr/bin/env python3
# ======================================================
# Hexora Enterprise Static Scanner v2
# Multi-Language | AST | Taint | Rulepacks | Dependency
# With Parallel Scanning + Secret Detection
# ======================================================

from __future__ import annotations
import os, sys, json, time, traceback
from pathlib import Path

# ---------- NEW ENTERPRISE ADDITIONS ----------
from core.parallel_engine import ParallelEngine
from core.secret_scanner import SecretScanner

# ---------- Core Engine Imports ----------
from core.ast_manager import ASTManager
from core.rule_engine import RuleEngine
from core.taint_engine import TaintEngine
from core.file_manager import FileManager
from core.result_builder import ResultBuilder
from core.dependency_scanner import DependencyScanner
from core.compliance_mapper import ComplianceMapper

# ---------- Language Scanners ----------
from languages.python_scanner import PythonScanner
from languages.javascript_scanner import JavaScriptScanner
from languages.typescript_scanner import TypeScriptScanner
from languages.php_scanner import PHPScanner
from languages.java_scanner import JavaScanner
from languages.go_scanner import GoScanner
from languages.csharp_scanner import CSharpScanner
from languages.ruby_scanner import RubyScanner
from languages.shell_scanner import ShellScanner
from languages.json_scanner import JSONScanner
from languages.yaml_scanner import YAMLScanner
from languages.config_scanner import ConfigScanner

# ---------- Safe Logging ----------
LOG_FILE = Path("logs/scanner_v2.log")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def log(msg: str):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except:
        pass
    print(line, file=sys.stderr, flush=True)

# ---------- Language Mapping ----------
LANG_SCANNERS = {
    "python": PythonScanner(),
    "javascript": JavaScriptScanner(),
    "typescript": TypeScriptScanner(),
    "php": PHPScanner(),
    "java": JavaScanner(),
    "go": GoScanner(),
    "csharp": CSharpScanner(),
    "ruby": RubyScanner(),
    "shell": ShellScanner(),
    "json": JSONScanner(),
    "yaml": YAMLScanner(),
    "config": ConfigScanner(),
}

# =====================================================
# MAIN SCANNER ENGINE
# =====================================================

class HexoraScannerV2:

    def __init__(self, src: Path, rulepack_dir: Path, out_json: Path):
        self.src = src
        self.rulepack_dir = rulepack_dir
        self.out_json = out_json

        log(f"Loading rulepacks from: {rulepack_dir}")
        self.rule_engine = RuleEngine(rulepack_dir)
        self.dep_scanner = DependencyScanner()
        self.ast_mgr = ASTManager()
        self.file_mgr = FileManager()
        self.compliance = ComplianceMapper(rulepack_dir)
        self.secret = SecretScanner()

        sources = self.rule_engine.sources
        sinks = self.rule_engine.sinks
        sanitizers = self.rule_engine.sanitizers
        self.taint = TaintEngine(sources, sinks, sanitizers)

        log("Hexora Scanner V2 initialized.")

    # --------------------------------------------------
    def scan_file(self, item):
        """Parallel-safe scanning function."""

        fpath, lang = item
        findings = []

        try:
            code = self.file_mgr.read_file(fpath)
            if not code.strip():
                return []

            # 1. AST → Language-specific rules
            ast = self.ast_mgr.get_ast(lang, code)

            if lang in LANG_SCANNERS:
                try:
                    lang_findings = LANG_SCANNERS[lang].scan_ast(code, str(fpath), self.ast_mgr)
                    findings.extend(lang_findings)
                except Exception as ex:
                    log(f"[WARN] Language scanner {lang} failed: {ex}")

            # 2. Regex + rulepack rules
            findings.extend(self.rule_engine.apply_rules(code, str(fpath), lang))

            # 3. Taint analysis
            findings.extend(self.taint.analyze(code, str(fpath), lang))

            # 4. Secret scanning (enterprise)
            findings.extend(self.secret.scan_text(code))

        except Exception as e:
            log(f"[ERROR] Scanning failed: {fpath} – {e}")
            log(traceback.format_exc())

        return findings

    # --------------------------------------------------
    def scan(self):
        all_files = self.file_mgr.collect_files(self.src)
        parallel = ParallelEngine(workers=12)

        # Run parallel scan
        results = parallel.run_parallel(all_files, self.scan_file)

        # Merge all results
        findings = [item for sub in results for item in (sub or [])]

        # Dependency scanning
        try:
            dependencies = self.dep_scanner.scan_dependencies(self.src)
        except Exception as e:
            log(f"[ERROR] Dependency scanner failed: {e}")
            dependencies = []

        # Compliance mapping
        for f in findings:
            f["compliance"] = self.compliance.map_compliance(f.get("cwe"))

        meta = {
            "total_findings": len(findings),
            "total_dependencies": len(dependencies),
            "total_files": len(all_files),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "src": str(self.src),
        }

        out = {
            "findings": findings,
            "dependencies": dependencies,
            "meta": meta
        }

        # Write JSON
        try:
            self.out_json.parent.mkdir(parents=True, exist_ok=True)
            self.out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")
            log(f"JSON output written: {self.out_json}")
        except Exception as e:
            log(f"[ERROR] Failed writing JSON: {e}")

        return out

# =====================================================
# CLI ENTRYPOINT
# =====================================================

def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="Source directory to scan")
    ap.add_argument("--rules", required=True, help="Rulepack directory")
    ap.add_argument("--out", required=True, help="Output JSON file")
    args = ap.parse_args()

    src = Path(args.src)
    rule_dir = Path(args.rules)
    out_json = Path(args.out)

    log(f"Scanner_v2 started src={src}")

    try:
        scanner = HexoraScannerV2(src, rule_dir, out_json)
        scanner.scan()
    except Exception as e:
        log(f"[FATAL] Scanner failed: {e}")
        log(traceback.format_exc())
        sys.exit(1)

    log("Scanner_v2 completed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()