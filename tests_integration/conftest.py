"""conftest for integration tests — sets up harness import path before collection.

These tests need the harness on sys.path to import `cli` and `tools.terminal_tool`.
"""
import sys
import os

_harness_dir = os.path.expanduser("~/.hermes/hermes-agent")
_project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Harness must be first for `import cli` / `from tools.terminal_tool`.
if _harness_dir not in sys.path:
    sys.path.insert(0, _harness_dir)
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)
