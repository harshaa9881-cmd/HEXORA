# languages/javascript_scanner.py
from core.result_builder import ResultBuilder

class JavaScriptScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []

        tree = ast_mgr.parse("javascript", code)
        if not tree:
            return []

        root = tree.root_node

        def walk(node):
            # Detect eval()
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                name = ast_mgr.node_text(fn, code)
                if name == "eval":
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "js_eval_rce", "critical", "CWE-95", 9.8,
                        "A03: Injection",
                        "Avoid eval() in JS",
                        "Use JSON.parse or safer functions",
                        "javascript"
                    ))

            # Detect innerHTML assignment
            if node.type == "assignment_expression":
                target = ast_mgr.node_text(node.child_by_field_name("left"), code)
                if "innerHTML" in target:
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "js_dom_xss", "high", "CWE-79", 6.1,
                        "A03: Injection",
                        "innerHTML leads to DOM XSS",
                        "Use textContent or DOMPurify",
                        "javascript"
                    ))

            for child in node.children:
                walk(child)

        walk(root)
        return findings