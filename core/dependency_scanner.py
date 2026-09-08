# core/dependency_scanner.py
from pathlib import Path
import json

class DependencyScanner:

    def scan_dependencies(self, root: Path):
        deps = []

        for f in root.rglob("*"):

            try:
                if f.name == "package.json":
                    data = json.loads(f.read_text())
                    deps.append({"file": str(f), "package_json": list(data.get("dependencies", {}).keys())})

                elif f.name == "requirements.txt":
                    pkgs = [line.split("==")[0].strip() for line in f.read_text().splitlines() if line.strip()]
                    deps.append({"file": str(f), "requirements": pkgs})

                elif f.name == "composer.json":
                    data = json.loads(f.read_text())
                    deps.append({"file": str(f), "composer": list(data.get("require", {}).keys())})

                elif f.name in ("Pipfile.lock", "poetry.lock"):
                    deps.append({"file": str(f), "python_lockfile": True})

                elif f.name == "go.mod":
                    pkgs = []
                    for line in f.read_text().splitlines():
                        if line.startswith("require"):
                            parts = line.split()
                            if len(parts) >= 2:
                                pkgs.append(parts[1])
                    deps.append({"file": str(f), "gomod": pkgs})

            except Exception:
                continue

        return deps