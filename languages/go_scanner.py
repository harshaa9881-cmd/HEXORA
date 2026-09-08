# languages/go_scanner.py
from core.result_builder import ResultBuilder

class GoScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []
        tree = ast_mgr.parse("go", code)
        if not tree:
            return []

        root = tree.root_node

        def walk(node):
            # Detect os/exec.Command concatenation
            if node.type == "call_expression":
                text = ast_mgr.node_text(node, code)
                if "exec.Command" in text and "+" in text:
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "go_cmd_injection", "critical", "CWE-78", 9.8,
                        "A03: Injection",
                        "Avoid command concatenation",
                        "Pass args separately to exec.Command",
                        "go"
                    ))

            for child in node.children:
                walk(child)

        walk(root)
        return findings