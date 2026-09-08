# core/ast_manager.py
import traceback
from pathlib import Path
from tree_sitter import Language, Parser

LOG_FILE = Path("logs/ast_errors.log")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

class ASTManager:

    def __init__(self):
        self.parsers = {}
        self._load_all_parsers()

    # Load all tree-sitter .so files
    def _load_all_parsers(self):
        parser_dir = Path("parsers")
        for so in parser_dir.glob("*.so"):
            lang_name = so.stem
            try:
                language = Language(str(so), lang_name)
                parser = Parser()
                parser.set_language(language)
                self.parsers[lang_name] = parser
            except Exception as e:
                self._log_err(f"Failed to load parser {so}: {e}")

    # Load AST safely
    def get_ast(self, lang, code: str):
        if lang not in self.parsers:
            return None
        try:
            parser = self.parsers[lang]
            return parser.parse(bytes(code, "utf8"))
        except Exception as e:
            self._log_err(f"AST parse error [{lang}]: {e}")
            return None

    def _log_err(self, msg):
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")