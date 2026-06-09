"""Integration tests for pending_command visibility across the plugin + harness boundary.

These tests exercise the real CLI callback and thread-local pending command flow,
using the same stubbing pattern as the upstream harness tests.

NOTE: Run with the harness venv python so prompt_toolkit and other CLI
dependencies are available:
    /home/brak/.hermes/hermes-agent/venv/bin/python3 -m pytest tests/test_integration.py
"""
import json
import os
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Import ordering: harness first (for cli + tools.terminal_tool), then plugin.
# The harness dir is removed from sys.path after imports so test_tools.py
# (which expects `tools` == the plugin's tools.py) is not affected when both
# files are collected together.
# ---------------------------------------------------------------------------

_harness_dir = os.path.expanduser("~/.hermes/hermes-agent")
_project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Temporarily prepend harness so `import cli` / `from tools.terminal_tool`
# resolve to the harness packages.
sys.path.insert(0, _harness_dir)

# Snapshot sys.modules entries that the plugin's test_tools.py needs.
# After we import harness modules, `tools` in sys.modules will point to the
# harness tools package — save and restore so test_tools.py still works.
_saved_modules = {}
_conflict_keys = [k for k in sys.modules if k == "tools" or k.startswith("tools.")]
for _k in _conflict_keys:
    _saved_modules[_k] = sys.modules[_k]

# Remove conflicting `tools` entries so the harness `tools/` package is
# imported fresh. The plugin's `tools.py` may already be in sys.modules
# from test_tools.py or conftest.py.
for _k in _conflict_keys:
    del sys.modules[_k]

import cli as _cli_mod
from cli import HermesCLI
from tools.terminal_tool import (
    set_sudo_pending_command,
    get_sudo_pending_command,
    set_sudo_password_callback as _set_sudo_cb,
)

# Remove harness from sys.path and restore saved sys.modules entries so
# test_tools.py (which does `from tools import ...`) is not broken.
sys.path.remove(_harness_dir)
# Unregister harness tools* modules that shadow the plugin's tools.py.
for _k in _conflict_keys:
    if _k in sys.modules:
        del sys.modules[_k]
# Restore any saved entries (e.g. if plugin tools was already imported).
for _k, _v in _saved_modules.items():
    sys.modules[_k] = _v
# Ensure project root is first for plugin imports.
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)
elif sys.path[0] != _project_dir:
    sys.path.remove(_project_dir)
    sys.path.insert(0, _project_dir)
# ---------------------------------------------------------------------------
# Load plugin tools by path to avoid any residual shadowing.
# ---------------------------------------------------------------------------

import importlib.util

_plugin_tools_spec = importlib.util.spec_from_file_location(
    "_hermes_sudo_tools", os.path.join(_project_dir, "tools.py")
)
_plugin_mod = importlib.util.module_from_spec(_plugin_tools_spec)
_plugin_tools_spec.loader.exec_module(_plugin_mod)
_handle_sudo_authorize = _plugin_mod._handle_sudo_authorize
_reset_state = _plugin_mod._reset_state
_plugin_state = _plugin_mod  # for accessing _pending_command etc.

# ---------------------------------------------------------------------------
# Helpers — mirror the harness test stubs
# ---------------------------------------------------------------------------


class _FakeBuffer:
    def __init__(self, text="", cursor_position=None):
        self.text = text
        self.cursor_position = len(text) if cursor_position is None else cursor_position

    def reset(self, append_to_history=False):
        self.text = ""
        self.cursor_position = 0


def _make_cli_stub():
    cli = HermesCLI.__new__(HermesCLI)
    cli._approval_state = None
    cli._approval_deadline = 0
    cli._approval_lock = threading.Lock()
    cli._sudo_state = None
    cli._sudo_deadline = 0
    cli._modal_input_snapshot = None
    cli._invalidate = MagicMock()
    cli._app = SimpleNamespace(invalidate=MagicMock(), current_buffer=_FakeBuffer())
    return cli


# ---------------------------------------------------------------------------
# Thread-local pending command storage
# ---------------------------------------------------------------------------


class TestPendingCommandThreadLocal:
    """Verify the harness thread-local pending command storage works correctly."""

    def test_set_and_get_pending_command(self):
        set_sudo_pending_command("sudo apt update")
        assert get_sudo_pending_command() == "sudo apt update"
        set_sudo_pending_command(None)
        assert get_sudo_pending_command() is None

    def test_pending_command_is_thread_local(self):
        """Pending command must not leak to other threads."""
        set_sudo_pending_command("sudo rm -rf /tmp")

        worker_saw = []

        def worker():
            worker_saw.append(get_sudo_pending_command())

        t = threading.Thread(target=worker)
        t.start()
        t.join(timeout=2)

        assert worker_saw == [None]
        assert get_sudo_pending_command() == "sudo rm -rf /tmp"
        set_sudo_pending_command(None)


# ---------------------------------------------------------------------------
# CLI callback captures pending command in _sudo_state
# ---------------------------------------------------------------------------


class TestCliCallbackCapturesPendingCommand:
    """Verify CLI._sudo_password_callback reads pending_command into _sudo_state."""

    def test_callback_stores_pending_command_in_state(self):
        cli = _make_cli_stub()
        result = {}

        with patch.object(_cli_mod, "_cprint"):
            _set_sudo_cb(cli._sudo_password_callback)

            def _run_callback():
                set_sudo_pending_command("sudo ls /root")
                result["value"] = cli._sudo_password_callback()

            thread = threading.Thread(target=_run_callback, daemon=True)
            thread.start()

            deadline = time.time() + 2
            while cli._sudo_state is None and time.time() < deadline:
                time.sleep(0.01)

            assert cli._sudo_state is not None
            assert cli._sudo_state.get("pending_command") == "sudo ls /root"

            cli._sudo_state["response_queue"].put("password123")
            thread.join(timeout=2)

        assert result.get("value") == "password123"
        set_sudo_pending_command(None)

    def test_callback_stores_none_when_no_pending_command(self):
        cli = _make_cli_stub()
        result = {}

        with patch.object(_cli_mod, "_cprint"):
            _set_sudo_cb(cli._sudo_password_callback)

            def _run_callback():
                result["value"] = cli._sudo_password_callback()

            thread = threading.Thread(target=_run_callback, daemon=True)
            thread.start()

            deadline = time.time() + 2
            while cli._sudo_state is None and time.time() < deadline:
                time.sleep(0.01)

            assert cli._sudo_state is not None
            assert cli._sudo_state.get("pending_command") is None

            cli._sudo_state["response_queue"].put("password123")
            thread.join(timeout=2)

        assert result.get("value") == "password123"

    def test_callback_with_long_pending_command(self):
        """Pending command is captured even when very long."""
        cli = _make_cli_stub()
        result = {}
        long_cmd = "sudo apt install -y " + "pkg " * 50

        with patch.object(_cli_mod, "_cprint"):
            _set_sudo_cb(cli._sudo_password_callback)

            def _run_callback():
                set_sudo_pending_command(long_cmd)
                result["value"] = cli._sudo_password_callback()

            thread = threading.Thread(target=_run_callback, daemon=True)
            thread.start()

            deadline = time.time() + 2
            while cli._sudo_state is None and time.time() < deadline:
                time.sleep(0.01)

            assert cli._sudo_state is not None
            assert cli._sudo_state.get("pending_command") == long_cmd

            cli._sudo_state["response_queue"].put("testpw")
            thread.join(timeout=2)

        assert result.get("value") == "testpw"
        set_sudo_pending_command(None)


# ---------------------------------------------------------------------------
# Plugin handler wires pending_command into state
# ---------------------------------------------------------------------------


class TestPluginHandlerPendingCommand:
    """Verify _handle_sudo_authorize stores and returns pending_command."""

    def test_nopasswd_includes_pending_command(self):
        _reset_state()
        orig = _plugin_state._sudo_nopasswd_works
        _plugin_state._sudo_nopasswd_works = lambda: True
        try:
            result = json.loads(_handle_sudo_authorize(
                scope="once",
                pending_command="sudo systemctl restart nginx",
            ))
            assert result["success"] is True
            assert result.get("pending_command") == "sudo systemctl restart nginx"
            assert _plugin_state._pending_command == "sudo systemctl restart nginx"
        finally:
            _plugin_state._sudo_nopasswd_works = orig
            set_sudo_pending_command(None)

    def test_nopasswd_without_pending_command(self):
        _reset_state()
        orig = _plugin_state._sudo_nopasswd_works
        _plugin_state._sudo_nopasswd_works = lambda: True
        try:
            result = json.loads(_handle_sudo_authorize(scope="once"))
            assert result["success"] is True
            assert "pending_command" not in result
            assert _plugin_state._pending_command is None
        finally:
            _plugin_state._sudo_nopasswd_works = orig

    def test_reset_clears_pending_command(self):
        _plugin_state._pending_command = "sudo rm -rf /important"
        _reset_state()
        assert _plugin_state._pending_command is None
