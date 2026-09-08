# languages/csharp_scanner.py
from core.result_builder import ResultBuilder

class CSharpScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []

        tree = ast_mgr.parse("csharp", code)
        if not tree:
            return []

        root = tree.root_node

        def walk(node):
            if node.type == "invocation_expression":
                text = ast_mgr.node_text(node, code)
                if "Process.Start" in text and "+" in text:
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "csharp_rce", "critical", "CWE-78", 9.8,
                        "A03: Injection",
                        "Do not concatenate commands",
                        "Use ProcessStartInfo with arguments array",
                        "csharp"
                    ))

            for child in node.children:
                walk(child)

        walk(root)
        return findings