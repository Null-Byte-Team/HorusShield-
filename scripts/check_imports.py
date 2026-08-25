#!/usr/bin/env python3
"""
CI helper: import every module under backend/ and report any that fail.

Unlike `python -m compileall` (which only checks syntax), this actually
executes each module's top-level code, catching broken imports, missing
dependencies, and import-time errors that only show up at runtime.

Modules that are entry points with real side effects when *run* (not
imported) are safe here because HorusShield guards all of that behind
`if __name__ == "__main__":` — see backend/app.py.
"""

import importlib
import os
import sys
import traceback

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

# Keep test-only/CI-only env vars sane before importing config.py etc.
os.environ.setdefault("HORUS_ENV", "development")
os.environ.setdefault("HORUS_HEADLESS", "true")
os.environ.setdefault("HORUS_SECRET_KEY", "ci-import-check-secret")
os.environ.setdefault("HORUS_DB_PATH", "/tmp/horus_import_check.db")

sys.path.insert(0, BACKEND_DIR)

SKIP_DIRS = {"__pycache__", ".git"}
SKIP_FILES = set()  # add module names here (without .py) if one is intentionally not import-safe


def find_modules():
    modules = []
    for root, dirs, files in os.walk(BACKEND_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if not f.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(root, f), BACKEND_DIR)
            mod_name = rel[:-3].replace(os.sep, ".")
            if mod_name.endswith("__init__"):
                mod_name = mod_name[: -len(".__init__")] or None
            if mod_name and mod_name not in SKIP_FILES:
                modules.append(mod_name)
    return sorted(modules)


def main():
    modules = find_modules()
    failures = []
    print(f"Checking {len(modules)} module(s) under backend/ ...\n")
    for mod in modules:
        try:
            importlib.import_module(mod)
            print(f"  ✅ {mod}")
        except Exception as e:
            failures.append((mod, e))
            print(f"  ❌ {mod}: {e}")

    if failures:
        print(f"\n{len(failures)} module(s) failed to import:\n")
        for mod, e in failures:
            print(f"── {mod} ──")
            traceback.print_exception(type(e), e, e.__traceback__)
            print()
        sys.exit(1)

    print(f"\n✅ All {len(modules)} modules imported successfully")


if __name__ == "__main__":
    main()
