# languages/python_scanner.py
from core.result_builder import ResultBuilder

class PythonScanner:
    def scan_ast(self, code: str, filename: str, ast_mgr):
        findings = []

        tree = ast_mgr.parse("python", code)
        if not tree:
            return []

        root = tree.root_node

        def walk(node):
            # Detect eval()
            if node.type == "call":
                text = ast_mgr.node_text(node.child_by_field_name("function"), code)
                if text.strip() == "eval":
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "python_eval_rce", "critical", "CWE-78", 9.8,
                        "A03: Injection",
                        "Use ast.literal_eval instead of eval()",
                        "Avoid eval() with untrusted input",
                        "python"
                    ))

            # Detect exec()
            if node.type == "call":
                text = ast_mgr.node_text(node.child_by_field_name("function"), code)
                if text.strip() == "exec":
                    line = node.start_point[0] + 1
                    snippet = code.splitlines()[line - 1][:200]
                    findings.append(ResultBuilder.make_finding(
                        filename, line, snippet,
                        "python_exec_rce", "critical", "CWE-78", 9.8,
                        "A03: Injection",
                        "Use subprocess.run() with args array",
                        "Avoid exec()",
                        "python"
                    ))

            # Recursion
            for child in node.children:
                walk(child)

        walk(root)
        return findings