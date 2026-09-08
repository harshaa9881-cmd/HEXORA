# languages/php_scanner.py
from core.result_builder import ResultBuilder

class PHPScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []
        tree = ast_mgr.parse("php", code)
        if not tree:
            return []

        root = tree.root_node

        def walk(node):
            # Detect eval()
            if node.type == "function_call":
                fn = node.child_by_field_name("name")
                if fn and ast_mgr.node_text(fn, code) == "eval":
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "php_eval_rce", "critical", "CWE-95", 9.8,
                        "A03: Injection",
                        "Avoid eval()",
                        "Use safe templating / avoid dynamic eval",
                        "php"
                    ))

            for child in node.children:
                walk(child)

        walk(root)
        return findings