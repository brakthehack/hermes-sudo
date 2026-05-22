"""Core implementation for hermes-sudo plugin.

State management, sudo detection, tool handler, and lifecycle hooks.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state (guarded by _lock)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_sudo_scope: Optional[str] = None   # None | "once" | "session"
_sudo_consumed: bool = False

_PREFIX_TOKENS = frozenset({
    # Note: "command" intentionally excluded. "command -v" is informational,
    # not execution. Agents use bare "sudo", not "command sudo".
    "exec", "nohup", "nice", "env", "ionice", "stdbuf",
    "chrt", "schedtool", "setsid", "taskset", "time",
})


def _reset_state() -> None:
    """Reset all module state. Caller must hold _lock or call from session end."""
    global _sudo_scope, _sudo_consumed
    _sudo_scope = None
    _sudo_consumed = False


# ---------------------------------------------------------------------------
# sudo detection — "does this command contain a real sudo invocation?"
# ---------------------------------------------------------------------------

def _command_has_real_sudo(command: str) -> bool:
    """Return True if *command* contains a real (unquoted, command-position) sudo.

    Handles: ``sudo cmd``, ``VAR=val sudo cmd``, ``cmd1 && sudo cmd2``,
    ``cmd1; sudo cmd2``, ``cmd1 | sudo cmd2``, ``cmd1 || sudo cmd2``.

    Does NOT flag: ``echo "sudo"``, ``rg 'sudo' file``, ``PATH=/usr/bin/sudo``,
    ``man sudo``.

    Also handles subshells (``(sudo cmd)``), command substitution
    (``$(sudo cmd)``), prefix commands (``nohup sudo cmd``),
    and heredoc bodies (``cat <<EOF\nsudo\nEOF``).
    """
    i = 0
    n = len(command)
    cmd_start = True
    env_pending = False  # True after KEY=val at command-start (quoted value is not a command)
    prefix_active = False  # True after a prefix command (nohup, time, etc.) before the real command

    def _skip_heredoc(delim: str, allow_tabs: bool) -> None:
        """Skip heredoc body starting at position *i*. Updates *i* in-place."""
        nonlocal i
        while i < n:
            nl = command.find("\n", i)
            if nl == -1:
                i = n
                return
            line_start = nl + 1
            scan = line_start
            if allow_tabs:
                while scan < n and command[scan] == "\t":
                    scan += 1
            if command[scan:scan + len(delim)] == delim:
                rest = scan + len(delim)
                if rest >= n or command[rest] == "\n":
                    i = rest + 1 if rest < n and command[rest] == "\n" else n
                    return
            i = nl + 1

    while i < n:
        c = command[i]

        # Newline resets to command-start (check before whitespace — \n isspace() is True).
        if c == "\n":
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Whitespace is neutral.
        if c.isspace():
            i += 1
            continue

        # Comment only at command-start, skip to end of line.
        if c == "#" and cmd_start:
            nl = command.find("\n", i)
            if nl == -1:
                return False
            i = nl + 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Two-character chain operators (check before single-char).
        if i + 1 < n:
            two = command[i : i + 2]
            if two in ("&&", "||"):
                i += 2
                cmd_start = True
                env_pending = False
                prefix_active = False
                continue

        # Single-character command separators / terminators.
        if c in ";|":
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Background operator (``&`` — not ``&&`` which was caught above).
        if c == "&" and not (i > 0 and command[i - 1] == ">"):
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Parenthesised subshell — recurse into content to find sudo.
        if c == "(":
            # Check for $(( arithmetic )) — skip entirely.
            prev_is_dollar = i > 0 and command[i - 1] == "$"
            if prev_is_dollar and i + 1 < n and command[i + 1] == "(":
                # $(( ... )) — skip to closing )).
                i += 2
                depth = 1
                while i < n and depth > 0:
                    if i + 1 < n and command[i] == ")" and command[i + 1] == ")":
                        depth -= 1
                        i += 2
                    elif command[i] == "(":
                        depth += 1
                        i += 1
                    elif command[i] == ")":
                        depth -= 1
                        i += 1
                    else:
                        i += 1
                cmd_start = False
                env_pending = False
                prefix_active = False
                continue

            # $(command substitution) or (subshell) — recurse.
            depth = 1
            start = i + 1
            i += 1
            while i < n and depth > 0:
                if command[i] == "(":
                    depth += 1
                elif command[i] == ")":
                    depth -= 1
                if depth > 0:
                    i += 1
            content = command[start:i]
            i += 1  # past closing )
            if _command_has_real_sudo(content):
                return True
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        # Quoted strings — check for quoted sudo at command-start.
        if c in "'\"":
            quote = c
            i += 1
            content_parts: list[str] = []
            while i < n:
                if command[i] == "\\" and i + 1 < n:
                    # In double quotes, \ escapes only $, `, ", \, newline.
                    # In single quotes, backslash is literal.
                    if quote == '"' and command[i + 1] in "$`\"\\\n":
                        content_parts.append(command[i + 1])
                        i += 2
                    elif quote == "'":
                        content_parts.append("\\")
                        i += 1
                    else:
                        content_parts.append(command[i])
                        i += 1
                elif command[i] == quote:
                    content = "".join(content_parts)
                    # Quoted "sudo" at command-start is a real sudo (but not after KEY=val).
                    if cmd_start and not env_pending and content == "sudo":
                        return True
                    i += 1
                    break
                else:
                    content_parts.append(command[i])
                    i += 1
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        # Read an unquoted token.
        start = i
        while i < n:
            c2 = command[i]
            if c2.isspace() or c2 in ";&|\"'#\n()":
                break
            if c2 == "\\" and i + 1 < n:
                if command[i + 1] == "\n":
                    break  # backslash-newline is line continuation — token ends here
                i += 2
            else:
                i += 1
        token = command[start:i]

        # Avoid infinite loop when a break-set char (like # at non-cmd-start)
        # falls through to the token reader and produces an empty token.
        if start == i:
            i += 1
            continue

        if cmd_start and token == "sudo":
            return True

        # Heredoc: skip body to avoid false positives.
        heredoc_idx = token.find("<<")
        if heredoc_idx >= 0 and not (heredoc_idx + 2 < len(token) and token[heredoc_idx + 2] == '<'):
            delim_part = token[heredoc_idx + 2:]
            tab_prefix = False
            if delim_part.startswith("-"):
                tab_prefix = True
                delim_part = delim_part[1:]
            if delim_part and delim_part[0] in "'\"":
                delim_part = delim_part[1:-1]
            elif delim_part.startswith("\\"):
                delim_part = delim_part[1:]

            if delim_part:
                _skip_heredoc(delim_part, tab_prefix)
                cmd_start = True
                env_pending = False
                prefix_active = False
                continue
            else:
                # << followed by space — read the delimiter as the next word.
                while i < n and command[i].isspace():
                    i += 1
                if i < n and command[i] in "'\"":
                    quote = command[i]
                    i += 1
                    dstart = i
                    while i < n and command[i] != quote:
                        i += 1
                    delim_part = command[dstart:i]
                    i += 1  # skip closing quote
                else:
                    dstart = i
                    while i < n and not command[i].isspace() and command[i] not in ";|()\n&":
                        i += 1
                    delim_part = command[dstart:i]
                if delim_part:
                    _skip_heredoc(delim_part, tab_prefix)
                cmd_start = True
                env_pending = False
                prefix_active = False
                continue

        # KEY=val at command-start is an env assignment — still at
        # command-start after it (e.g. DEBUG=1 sudo cmd).
        if cmd_start and "=" in token and not token.startswith("-"):
            env_pending = True
            prefix_active = False
            # cmd_start stays True
        # Prefix commands that execute their arguments — still at
        # command-start after them (e.g. nohup sudo cmd).
        elif cmd_start and token in _PREFIX_TOKENS:
            env_pending = False
            prefix_active = True
            # cmd_start stays True
        # Options and numeric args after a prefix — keep cmd_start active.
        elif cmd_start and prefix_active and (token.startswith("-") or token.isdigit()):
            # cmd_start and prefix_active both stay True
            pass
        else:
            cmd_start = False
            env_pending = False
            prefix_active = False

    return False


# ---------------------------------------------------------------------------
# sudo probe helpers
# ---------------------------------------------------------------------------

def _sudo_nopasswd_works() -> bool:
    """Return True if ``sudo -n true`` succeeds (NOPASSWD or valid timestamp).

    Only probes the local terminal backend — non-local envs have no host sudo.
    """
    terminal_env = os.getenv("TERMINAL_ENV", "local").strip().lower() or "local"
    if terminal_env != "local":
        return False

    try:
        probe = subprocess.run(
            ["sudo", "-n", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        return probe.returncode == 0
    except Exception:
        return False


def _sudo_timestamp_valid() -> bool:
    """Return True if a valid sudo timestamp exists (``sudo -nv`` succeeds)."""
    terminal_env = os.getenv("TERMINAL_ENV", "local").strip().lower() or "local"
    if terminal_env != "local":
        return False

    try:
        probe = subprocess.run(
            ["sudo", "-nv"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        return probe.returncode == 0
    except Exception:
        return False


def _run_sudo_v() -> int:
    """Run ``sudo -v`` to authenticate the user via PAM on /dev/tty.

    Returns the process exit code (0 = success).
    """
    try:
        proc = subprocess.run(
            ["sudo", "-v"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,
            timeout=60,
            check=False,
        )
        return proc.returncode
    except subprocess.TimeoutExpired:
        return 1
    except Exception:
        return 1


def _run_sudo_k() -> None:
    """Run ``sudo -k`` to invalidate cached credentials. Best-effort."""
    try:
        subprocess.run(
            ["sudo", "-k"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tool handler: sudo_authorize
# ---------------------------------------------------------------------------

def _handle_sudo_authorize(
    scope: str = "once",
    **kwargs: Any,
) -> str:
    """Handle the sudo_authorize tool call.

    Authenticates the user via ``sudo -v`` (system PAM prompt on /dev/tty)
    and sets the authorization scope.

    Args:
        scope: "once" (one command) or "session" (until session ends).

    Returns:
        JSON result string.
    """
    global _sudo_scope, _sudo_consumed

    scope = scope.strip().lower() if isinstance(scope, str) else "once"
    if scope not in ("once", "session"):
        return json.dumps({
            "error": f"Invalid scope '{scope}'. Must be 'once' or 'session'.",
        })

    # Check if NOPASSWD or existing timestamp already gives us access.
    if _sudo_nopasswd_works():
        with _lock:
            _sudo_scope = scope
            _sudo_consumed = False
        logger.info("sudo_authorize: already have sudo access (NOPASSWD or existing timestamp) — scope=%s", scope)
        return json.dumps({
            "success": True,
            "scope": scope,
            "message": (
                f"sudo authorized for {scope}. "
                "Existing sudo credentials are valid — no password prompt needed."
            ),
        })

    # Run sudo -v to authenticate via PAM on /dev/tty.
    logger.info("sudo_authorize: running sudo -v for scope=%s", scope)
    rc = _run_sudo_v()
    if rc != 0:
        logger.warning("sudo_authorize: sudo -v failed (exit code %d)", rc)
        return json.dumps({
            "error": (
                "sudo authentication failed. Check your password and try again. "
                "Make sure the hermes terminal has access to /dev/tty."
            ),
        })

    with _lock:
        _sudo_scope = scope
        _sudo_consumed = False

    logger.info("sudo_authorize: authorized for scope=%s", scope)
    return json.dumps({
        "success": True,
        "scope": scope,
        "message": (
            f"sudo authorized for {scope}. "
            f"{'The agent may run one sudo command, then must re-authorize.' if scope == 'once' else 'The agent may run sudo commands for the remainder of this session.'}"
        ),
    })


# ---------------------------------------------------------------------------
# Hook: pre_tool_call (for terminal)
# ---------------------------------------------------------------------------

def _on_pre_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **kwargs: Any,
) -> Optional[Dict[str, str]]:
    """Pre-tool-call hook — gates sudo commands behind prior authorization.

    Returns ``None`` to pass through, or ``{"action": "block", "message": "..."}``
    to block the tool call and instruct the agent to call ``sudo_authorize``.
    """
    if tool_name != "terminal":
        return None

    command = args.get("command", "") if isinstance(args, dict) else ""
    if not isinstance(command, str) or not command:
        return None

    if not _command_has_real_sudo(command):
        return None

    # NOPASSWD gate — when the user has passwordless sudo AND has not opted
    # out via HERMES_SUDO_ALLOW_NOPASSWD=false, pass through without auth.
    allow_nopasswd = os.environ.get("HERMES_SUDO_ALLOW_NOPASSWD", "true").strip().lower()
    if allow_nopasswd in ("1", "true", "yes", "on") and _sudo_nopasswd_works():
        logger.debug("hermes-sudo: NOPASSWD sudo detected — passing through")
        return None

    with _lock:
        scope = _sudo_scope
        consumed = _sudo_consumed

    if scope is None:
        return {
            "action": "block",
            "message": (
                "sudo requires prior authorization. Call sudo_authorize(scope='once') "
                "to authorize one command, or sudo_authorize(scope='session') for "
                "session-wide authorization."
            ),
        }

    if scope == "session":
        # Verify the timestamp is still valid. If expired, try re-auth.
        if not _sudo_timestamp_valid():
            logger.info("hermes-sudo: session timestamp expired — attempting re-auth via sudo -v")
            rc = _run_sudo_v()
            if rc != 0:
                with _lock:
                    _reset_state()
                return {
                    "action": "block",
                    "message": (
                        "sudo session authorization expired and re-authentication failed. "
                        "Call sudo_authorize(scope='session') to re-authorize."
                    ),
                }
            logger.info("hermes-sudo: session re-auth succeeded")
        return None  # pass through

    if scope == "once":
        if consumed:
            return {
                "action": "block",
                "message": (
                    "sudo authorization for a single command has been consumed. "
                    "Call sudo_authorize(scope='once') to authorize the next sudo command."
                ),
            }

        # Verify timestamp is still valid.
        if not _sudo_timestamp_valid():
            with _lock:
                _reset_state()
            return {
                "action": "block",
                "message": (
                    "sudo timestamp expired before the authorized command ran. "
                    "Call sudo_authorize(scope='once') to re-authorize."
                ),
            }
        return None  # pass through

    # Unknown scope — should not happen.
    return None


# ---------------------------------------------------------------------------
# Hook: post_tool_call (for terminal)
# ---------------------------------------------------------------------------

def _on_post_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **kwargs: Any,
) -> None:
    global _sudo_consumed

    """Post-tool-call hook — consumes once-scoped authorization and clears timestamp.

    For "once" scope: marks the authorization as consumed and runs ``sudo -k``
    to invalidate cached credentials so the agent cannot piggyback on the
    still-valid timestamp window.
    """
    if tool_name != "terminal":
        return

    command = args.get("command", "") if isinstance(args, dict) else ""
    if not isinstance(command, str) or not command:
        return

    if not _command_has_real_sudo(command):
        return

    with _lock:
        scope = _sudo_scope

    if scope == "once":
        with _lock:
            _sudo_consumed = True
        logger.debug("hermes-sudo: once-scoped authorization consumed — clearing timestamp")
        _run_sudo_k()


# ---------------------------------------------------------------------------
# Hook: on_session_end
# ---------------------------------------------------------------------------

def _on_session_end(
    session_id: str = "",
    completed: bool = True,
    interrupted: bool = False,
    **kwargs: Any,
) -> None:
    """Session-end hook — clear any remaining sudo timestamp and reset state.

    Best-effort only; swallows all exceptions so the session teardown never
    fails because of this plugin.
    """
    with _lock:
        scope = _sudo_scope
        _reset_state()

    if scope is not None:
        logger.info("hermes-sudo: session ended — clearing sudo timestamp (scope was %s)", scope)
        _run_sudo_k()
