# core/file_manager.py
import os
from pathlib import Path

IGNORE_DIRS = {
    "node_modules", "vendor", "__pycache__", "dist", "build", ".git",
    "bin", "obj", ".next", ".nuxt", ".vscode", ".idea"
}

EXT_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".rb": "ruby",
    ".sh": "shell",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".ini": "config",
    ".conf": "config",
    ".properties": "config",
    ".env": "config"
}

class FileManager:

    def collect_files(self, root: Path):
        files = []
        for p in root.rglob("*"):

            # Skip directories
            if p.is_dir():
                if p.name in IGNORE_DIRS:
                    continue
                else:
                    continue

            # Skip large/binary
            if not self._is_text_file(p):
                continue

            lang = self._detect_lang(p)
            if lang:
                files.append((p, lang))

        return files

    def _is_text_file(self, path: Path):
        try:
            data = path.open("rb").read(2048)
            return b"\x00" not in data
        except:
            return False

    def _detect_lang(self, p: Path):
        return EXT_LANG_MAP.get(p.suffix.lower(), None)

    def read_file(self, path: Path):
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except:
            return ""