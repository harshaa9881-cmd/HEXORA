# languages/java_scanner.py
from core.result_builder import ResultBuilder

class JavaScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []

        tree = ast_mgr.parse("java", code)
        if not tree:
            return []

        root = tree.root_node

        def walk(node):
            # Detect Runtime.getRuntime().exec()
            if node.type == "method_invocation":
                text = ast_mgr.node_text(node, code)
                if "Runtime.getRuntime().exec" in text:
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "java_rce", "critical", "CWE-78", 9.8,
                        "A03: Injection",
                        "Avoid executing system commands",
                        "Use ProcessBuilder with sanitization",
                        "java"
                    ))

            for child in node.children:
                walk(child)

        walk(root)
        return findings