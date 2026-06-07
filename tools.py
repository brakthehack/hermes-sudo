"""Core implementation for hermes-sudo plugin.

State management, sudo detection, tool handler, and lifecycle hooks.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Audit log path
# ---------------------------------------------------------------------------

_AUDIT_LOG = os.path.join(
    os.environ.get("HOME", "/tmp"),
    ".hermes",
    "logs",
    "sudo-audit.log",
)


def _log_audit(level: str, command: str, user: str = "agent") -> None:
    """Write a line to the audit log. Best-effort; failures are silently ignored."""
    try:
        os.makedirs(os.path.dirname(_AUDIT_LOG), exist_ok=True)
        ts = datetime.now().isoformat(timespec="seconds")
        safe_cmd = command.replace("\n", "\\n")
        with open(_AUDIT_LOG, "a") as f:
            f.write(f"[{ts}] [{level}] user={user} cmd={safe_cmd}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Destructive command triggers for the "confirm" scope
# ---------------------------------------------------------------------------

_CONFIRM_TRIGGERS = frozenset({
    "rm", "dd", "mkfs", "fdisk", "format", "shutdown", "reboot", "poweroff",
    "halt", "init", "chmod", "chown",
})


def _command_needs_confirm(command: str) -> bool:
    """Return True if the command uses a destructive tool that warrants a confirmation prompt.

    Only triggers when the dangerous tool is used as a command (first word
    after a command boundary), not when it appears as an argument or string
    value (e.g. ``echo rm`` or ``grep -r rm`` are safe).

    Matches both bare tool names (``mkfs``) and variants (``mkfs.ext4``).
    """
    return _scan_for_confirm(command, len(command))


def _is_confirm_trigger(token: str) -> bool:
    """Check if a token matches a confirm trigger."""
    for trigger in _CONFIRM_TRIGGERS:
        if token == trigger or token.startswith(trigger + "."):
            return True
    return False


def _scan_for_confirm(command: str, n: int) -> bool:
    """Scan a command string for destructive triggers.

    Handles prefix commands, env assignments, subshells, command substitutions,
    backslash-newline continuations, and chain operators.
    """
    i = 0
    cmd_start = True
    env_pending = False
    prefix_active = False

    while i < n:
        c = command[i]

        # Newline resets command context
        if c == "\n":
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        if c.isspace():
            i += 1
            continue

        # Skip comments (only at command start)
        if c == "#" and cmd_start:
            nl = command.find("\n", i)
            i = nl + 1 if nl != -1 else n
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Backslash-newline continuation: skip the backslash and newline
        if c == "\\" and i + 1 < n and command[i + 1] == "\n":
            i += 2
            continue

        # Chain operators
        if i + 1 < n:
            two = command[i : i + 2]
            if two in ("&&", "||"):
                i += 2
                cmd_start = True
                env_pending = False
                prefix_active = False
                continue

        # Command separators
        if c in ";|":
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Background operator (but not 2>&1)
        if c == "&" and not (i > 0 and command[i - 1] == ">"):
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        # Arithmetic expansion $(( )) — skip
        if c == "$" and i + 1 < n and command[i + 1] == "(":
            if i + 2 < n and command[i + 2] == "(":
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
            # Command substitution $(...)
            i += 1
            depth = 1
            start = i
            while i < n and depth > 0:
                if command[i] == "(":
                    depth += 1
                elif command[i] == ")":
                    depth -= 1
                if depth > 0:
                    i += 1
            content = command[start:i]
            i += 1
            if _scan_for_confirm(content, len(content)):
                return True
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        # Backtick command substitution
        if c == "`":
            i += 1
            start = i
            while i < n and command[i] != "`":
                i += 1
            content = command[start:i]
            if i < n:
                i += 1  # skip closing backtick
            if _scan_for_confirm(content, len(content)):
                return True
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        # Subshell ( ... )
        if c == "(":
            prev_is_dollar = i > 0 and command[i - 1] == "$"
            if prev_is_dollar:
                # $( was handled above; this shouldn't be reached but guard anyway
                i += 1
                cmd_start = False
                continue
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
            if i < n:
                i += 1  # skip closing )
            if _scan_for_confirm(content, len(content)):
                return True
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        # Skip quoted strings
        if c in "'\"":
            quote = c
            i += 1
            while i < n and command[i] != quote:
                if command[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            if i < n:
                i += 1  # skip closing quote
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        # Unquoted token
        start = i
        while i < n:
            c2 = command[i]
            if c2.isspace() or c2 in ";|&()\"'#\n":
                break
            if c2 == "\\" and i + 1 < n and command[i + 1] == "\n":
                break
            i += 1
        token = command[start:i]

        if not token:
            i += 1
            continue

        # Strip leading backslashes for escaped commands
        stripped_token = token.lstrip("\\")

        if cmd_start:
            if stripped_token == "sudo":
                # After sudo, the next token is the real command
                cmd_start = True
                env_pending = False
                prefix_active = False
                continue
            # Check env assignment: VAR=value (no spaces, no leading dash)
            if "=" in stripped_token and not stripped_token.startswith("-"):
                env_pending = True
                prefix_active = False
                continue
            # Check prefix command
            if stripped_token in _PREFIX_TOKENS:
                env_pending = False
                prefix_active = True
                continue
            # Check if it's a trigger
            if _is_confirm_trigger(stripped_token):
                return True
            cmd_start = False
            env_pending = False
            prefix_active = False
        elif env_pending:
            # This token follows an env assignment; it could be sudo, prefix, or the real command
            env_pending = False
            if stripped_token == "sudo":
                cmd_start = True
                prefix_active = False
                continue
            if stripped_token in _PREFIX_TOKENS:
                prefix_active = True
                continue
            if _is_confirm_trigger(stripped_token):
                return True
            cmd_start = False
            prefix_active = False
        elif prefix_active:
            # After prefix command, flags or the real command
            if stripped_token.startswith("-") or stripped_token.isdigit():
                continue
            prefix_active = False
            if stripped_token == "sudo":
                cmd_start = True
                continue
            if _is_confirm_trigger(stripped_token):
                return True
            cmd_start = False
        else:
            # Not at command start, not after sudo/env/prefix — just an argument
            pass

    return False


# ---------------------------------------------------------------------------
# Module-level state (guarded by _lock)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_sudo_scope: Optional[str] = None   # None | "once" | "session" | "confirm"
_sudo_consumed: bool = False
_sudo_batch_remaining: int = 0

_PREFIX_TOKENS = frozenset({
    "command", "exec", "nohup", "nice", "env", "ionice", "stdbuf",
    "chrt", "schedtool", "setsid", "taskset", "time",
})


def _reset_state() -> None:
    """Reset all module state. Caller must hold _lock or call from session end."""
    global _sudo_scope, _sudo_consumed, _sudo_batch_remaining
    _sudo_scope = None
    _sudo_consumed = False
    _sudo_batch_remaining = 0


# ---------------------------------------------------------------------------
# sudo detection
# ---------------------------------------------------------------------------

def _command_has_real_sudo(command: str) -> bool:
    """Return True if *command* contains a real (unquoted, command-position) sudo."""
    i = 0
    n = len(command)
    cmd_start = True
    env_pending = False
    prefix_active = False
    command_prefix_name = ""  # track which prefix command is active

    def _skip_heredoc(delim: str, allow_tabs: bool) -> None:
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

        if c == "\n":
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        if c.isspace():
            i += 1
            continue

        if c == "#" and cmd_start:
            nl = command.find("\n", i)
            if nl == -1:
                return False
            i = nl + 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        if i + 1 < n:
            two = command[i : i + 2]
            if two in ("&&", "||"):
                i += 2
                cmd_start = True
                env_pending = False
                prefix_active = False
                continue

        if c in ";|":
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        if c == "&" and not (i > 0 and command[i - 1] == ">"):
            i += 1
            cmd_start = True
            env_pending = False
            prefix_active = False
            continue

        if c == "(":
            prev_is_dollar = i > 0 and command[i - 1] == "$"
            if prev_is_dollar and i + 1 < n and command[i + 1] == "(":
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
            i += 1
            if _command_has_real_sudo(content):
                return True
            cmd_start = False
            env_pending = False
            prefix_active = False
            continue

        if c in "'\"":
            quote = c
            i += 1
            content_parts: list[str] = []
            while i < n:
                if command[i] == "\\" and i + 1 < n:
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

        start = i
        while i < n:
            c2 = command[i]
            if c2.isspace() or c2 in ";&|\"'#\n()":
                break
            if c2 == "\\" and i + 1 < n:
                if command[i + 1] == "\n":
                    break
                i += 2
            else:
                i += 1
        token = command[start:i]

        if start == i:
            i += 1
            continue

        if cmd_start and token.lstrip("\\") == "sudo":
            return True

        heredoc_idx = token.find("<<")
        if heredoc_idx == 0 and not token.startswith("<<<"):
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
                while i < n and command[i].isspace():
                    i += 1
                if i < n and command[i] in "'\"":
                    quote = command[i]
                    i += 1
                    dstart = i
                    while i < n and command[i] != quote:
                        i += 1
                    delim_part = command[dstart:i]
                    i += 1
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

        if cmd_start and "=" in token and not token.startswith("-"):
            env_pending = True
            prefix_active = False
            command_prefix_name = ""
        elif cmd_start and token in _PREFIX_TOKENS:
            env_pending = False
            prefix_active = True
            command_prefix_name = token
        elif cmd_start and prefix_active and token.startswith("-"):
            # "command -v" / "command -V" are informational lookups, not execution
            if command_prefix_name == "command" and token in ("-v", "-V"):
                cmd_start = False
                env_pending = False
                prefix_active = False
                command_prefix_name = ""
            continue
        elif cmd_start and prefix_active and token.isdigit():
            pass
        else:
            cmd_start = False
            env_pending = False
            prefix_active = False
            command_prefix_name = ""

    return False


# ---------------------------------------------------------------------------
# sudo probe helpers
# ---------------------------------------------------------------------------

def _sudo_nopasswd_works() -> bool:
    terminal_env = os.getenv("TERMINAL_ENV", "local").strip().lower() or "local"
    if terminal_env != "local":
        return False
    try:
        probe = subprocess.run(
            ["sudo", "-n", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3, check=False,
        )
        return probe.returncode == 0
    except Exception:
        return False


def _sudo_timestamp_valid() -> bool:
    terminal_env = os.getenv("TERMINAL_ENV", "local").strip().lower() or "local"
    if terminal_env != "local":
        return False
    try:
        probe = subprocess.run(
            ["sudo", "-nv"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3, check=False,
        )
        return probe.returncode == 0
    except Exception:
        return False


def _find_tty_path() -> Optional[str]:
    """Walk the process tree upward to find a TTY.

    In Hermes Agent, the main CLI process owns the terminal while tool
    handlers run in child processes with no controlling TTY.  We scan
    from the current process up the parent chain or, failing that, scan
    all visible processes for one that has both a TTY and 'hermes' in
    its cmdline (the Hermes CLI).  Returns an absolute path like
    '/dev/pts/0' or None.
    """
    import stat as _st

    def _tty_nr_to_path(tty_nr: int) -> Optional[str]:
        if tty_nr == 0:
            return None
        major = (tty_nr >> 8) & 0xFFF
        minor = (tty_nr & 0xFF) | ((tty_nr >> 12) & 0xFFF00)
        for pty_root in ("/dev/pts", "/dev"):
            try:
                for entry in os.listdir(pty_root):
                    full = os.path.join(pty_root, entry)
                    try:
                        st = os.stat(full)
                        if not _st.S_ISCHR(st.st_mode):
                            continue
                        if os.major(st.st_rdev) == major and os.minor(st.st_rdev) == minor:
                            return full
                    except OSError:
                        continue
            except PermissionError:
                continue
        return f"/dev/pts/{minor}"  # best guess

    # Try walking up the parent chain first
    pid = os.getpid()
    seen: set[int] = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                parts = f.read().split(")")
                tail = parts[1].strip().split()
                ppid = int(tail[1])
                tty_nr = int(tail[4])
            tty_path = _tty_nr_to_path(tty_nr)
            if tty_path is not None:
                return tty_path
            pid = ppid
        except (FileNotFoundError, IndexError, ValueError, PermissionError):
            break

    # Fallback: scan all processes for a Hermes-owned TTY
    for proc in os.listdir("/proc"):
        if not proc.isdigit():
            continue
        try:
            with open(f"/proc/{proc}/cmdline") as f:
                cmdline = f.read().replace("\x00", " ")
            if not cmdline or "hermes" not in cmdline:
                continue
        except (FileNotFoundError, PermissionError):
            continue
        try:
            with open(f"/proc/{proc}/stat") as f:
                parts = f.read().split(")")
                tail = parts[1].strip().split()
                tty_nr = int(tail[4])
            tty_path = _tty_nr_to_path(tty_nr)
            if tty_path is not None:
                return tty_path
        except (FileNotFoundError, IndexError, ValueError, PermissionError):
            continue

    return None


def _run_sudo_cache() -> bool:
    """Prompt for sudo password and store it in the terminal tool's password cache.

    The terminal tool already handles piping the password via ``sudo -S`` on every
    ``sudo`` command — it looks up ``_get_cached_sudo_password()``.  We just need
    to populate that cache.

    This avoids all TTY / ``requiretty`` issues: the password is piped on stdin
    by the terminal tool's environment runner, which works without any TTY.
    """
    try:
        from tools.terminal_tool import (
            _prompt_for_sudo_password,
            _set_cached_sudo_password,
        )
    except ImportError:
        return False

    password = _prompt_for_sudo_password(timeout_seconds=45)
    if not password:
        return False

    _set_cached_sudo_password(password)
    # Kick sudo -v in the background so the kernel timestamp is also valid.
    # This is best-effort — the password-pipe path in the terminal tool works
    # even if sudo -v fails.
    try:
        subprocess.run(
            ["sudo", "-S", "-v"],
            input=password + "\n",
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except Exception:
        pass
    del password

    return True


def _run_sudo_k() -> None:
    """Invalidate sudo credentials and log the action."""
    try:
        subprocess.run(
            ["sudo", "-k"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
    except Exception:
        pass
    _log_audit("KILL", "sudo -k", user="agent")


# ---------------------------------------------------------------------------
# Tool handler: sudo_authorize
# ---------------------------------------------------------------------------

def _handle_sudo_authorize(
    scope: str = "once",
    count: int = 0,
    **kwargs: Any,
) -> str:
    global _sudo_scope, _sudo_consumed, _sudo_batch_remaining
    scope = scope.strip().lower() if isinstance(scope, str) else "once"

    # --- Status query ---
    if scope == "status":
        with _lock:
            cur_scope = _sudo_scope
            cur_consumed = _sudo_consumed
            cur_batch = _sudo_batch_remaining
        nopasswd = _sudo_nopasswd_works()
        result: Dict[str, Any] = {
            "scope": cur_scope or "none",
            "consumed": cur_consumed,
            "nopasswd": nopasswd,
        }
        if cur_scope == "batch":
            result["batch_remaining"] = cur_batch
        if nopasswd and cur_scope is None:
            result["message"] = "sudo NOPASSWD is configured — no password prompt needed."
        elif cur_scope is None:
            result["message"] = "No active sudo authorization. Call sudo_authorize to authorize."
        return json.dumps(result)

    # --- Validate scope ---
    if scope not in ("once", "confirm", "session", "batch"):
        return json.dumps({"error": f"Invalid scope '{scope}'. Must be 'once', 'confirm', 'session', or 'batch'."})

    if scope == "batch":
        if not isinstance(count, int) or count < 1:
            return json.dumps({"error": "Batch scope requires a positive integer 'count' parameter."})
        if count > 100:
            return json.dumps({"error": "Batch count limited to 100. Use 'session' for unlimited."})

    # --- NOPASSWD fast path ---
    if _sudo_nopasswd_works():
        with _lock:
            _sudo_scope = scope
            _sudo_consumed = False
            _sudo_batch_remaining = count if scope == "batch" else 0
        logger.info("sudo_authorize: NOPASSWD sudo detected — scope=%s", scope)
        msg = _scope_message(scope, count)
        return json.dumps({
            "success": True,
            "scope": scope,
            "message": msg + " sudo NOPASSWD is configured — no password prompt needed.",
        })

    # --- Password prompt ---
    logger.info("sudo_authorize: prompting for password (scope=%s)", scope)
    ok = _run_sudo_cache()
    if not ok:
        logger.warning("sudo_authorize: password prompt failed or was skipped")
        return json.dumps({
            "error": "sudo authentication failed. Check your password and try again.",
        })

    with _lock:
        _sudo_scope = scope
        _sudo_consumed = False
        _sudo_batch_remaining = count if scope == "batch" else 0

    _log_audit("AUTHORIZE", f"scope={scope}" + (f" count={count}" if scope == "batch" else ""), user="human")
    logger.info("sudo_authorize: authorized for scope=%s", scope)
    return json.dumps({
        "success": True,
        "scope": scope,
        "message": _scope_message(scope, count),
    })


def _scope_message(scope: str, count: int = 0) -> str:
    if scope == "batch":
        return (
            f"sudo authorized for {count} commands (batch). "
            f"Destructive commands (rm, dd, mkfs, etc.) will be blocked and need explicit approval."
        )
    return (
        f"sudo authorized for {scope}. "
        + {
            "once": "The agent may run one sudo command, then must re-authorize.",
            "confirm": "The agent may run one sudo command. Destructive commands (rm, dd, mkfs, etc.) will be blocked and need explicit approval.",
            "session": "The agent may run sudo commands for the remainder of this session.",
        }[scope]
    )


# ---------------------------------------------------------------------------
# Hook: pre_tool_call
# ---------------------------------------------------------------------------

def _on_pre_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **kwargs: Any,
) -> Optional[Dict[str, str]]:
    if tool_name != "terminal":
        return None

    command = args.get("command", "") if isinstance(args, dict) else ""
    if not isinstance(command, str) or not command:
        return None

    if not _command_has_real_sudo(command):
        return None

    with _lock:
        scope = _sudo_scope
        consumed = _sudo_consumed

    # NOPASSWD fast path: only bypass scope checks when no explicit scope is set.
    # When a scope IS set, the user wants scope enforcement regardless of whether
    # sudo credentials happen to be cached — otherwise confirm/once/session
    # scopes are silently disabled for any user with valid sudo credentials.
    if scope is None:
        allow_nopasswd = os.environ.get("HERMES_SUDO_ALLOW_NOPASSWD", "true").strip().lower()
        if allow_nopasswd in ("1", "true", "yes", "on") and _sudo_nopasswd_works():
            logger.debug("hermes-sudo: NOPASSWD sudo detected — passing through")
            _log_audit("EXEC", command, user="agent-nopasswd")
            return None

    if scope is None:
        return {
            "action": "block",
            "message": (
                "sudo requires prior authorization. Call sudo_authorize(scope='once') "
                "to authorize one command, sudo_authorize(scope='confirm') for "
                "confirmation on destructive commands, or sudo_authorize(scope='session') for "
                "session-wide authorization."
            ),
        }

    if scope == "session":
        if not _sudo_timestamp_valid():
            logger.info("hermes-sudo: session timestamp expired — attempting re-auth via password cache")
            ok = _run_sudo_cache()
            if not ok:
                with _lock:
                    _reset_state()
                return {
                    "action": "block",
                    "message": "sudo session authorization expired and re-authentication failed. Call sudo_authorize(scope='session') to re-authorize.",
                }
            logger.info("hermes-sudo: session re-auth succeeded")
        _log_audit("EXEC", command, user="agent-session")
        return None

    if scope == "batch":
        if _sudo_batch_remaining <= 0:
            return {
                "action": "block",
                "message": "sudo batch authorization has been exhausted. Call sudo_authorize(scope='batch' count=N) to authorize more commands.",
            }

        if not _sudo_timestamp_valid():
            with _lock:
                _reset_state()
            return {
                "action": "block",
                "message": "sudo timestamp expired. Call sudo_authorize(scope='batch' count=N) to re-authorize.",
            }

        if _command_needs_confirm(command):
            return {
                "action": "block",
                "message": (
                    "This sudo command uses a potentially destructive tool.\n\n"
                    f"{command}\n\n"
                    "Call sudo_authorize(scope='once') to authorize it without further confirmation."
                ),
            }

        _log_audit("EXEC", command, user=f"agent-batch-remaining={_sudo_batch_remaining}")
        return None

    if scope in ("once", "confirm"):
        if consumed:
            return {
                "action": "block",
                "message": f"sudo authorization for a single command has been consumed. Call sudo_authorize(scope='{scope}') to authorize the next sudo command.",
            }

        if not _sudo_timestamp_valid():
            with _lock:
                _reset_state()
            return {
                "action": "block",
                "message": f"sudo timestamp expired. Call sudo_authorize(scope='{scope}') to re-authorize.",
            }

        if scope == "confirm" and _command_needs_confirm(command):
            return {
                "action": "block",
                "message": (
                    "This sudo command uses a potentially destructive tool.\n\n"
                    f"{command}\n\n"
                    "Call sudo_authorize(scope='once') to authorize it without further confirmation."
                ),
            }

        _log_audit("EXEC", command, user=f"agent-{scope}")
        return None

    return None


# ---------------------------------------------------------------------------
# Hook: post_tool_call
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
    global _sudo_consumed, _sudo_batch_remaining

    if tool_name != "terminal":
        return

    command = args.get("command", "") if isinstance(args, dict) else ""
    if not isinstance(command, str) or not command:
        return

    if not _command_has_real_sudo(command):
        return

    with _lock:
        scope = _sudo_scope

    if scope in ("once", "confirm"):
        with _lock:
            _sudo_consumed = True
        logger.debug("hermes-sudo: %s-scoped authorization consumed — clearing timestamp", scope)
        _run_sudo_k()

    if scope == "batch":
        with _lock:
            _sudo_batch_remaining -= 1
            remaining = _sudo_batch_remaining
        logger.debug("hermes-sudo: batch authorization decremented — %d remaining", remaining)
        if remaining <= 0:
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
    with _lock:
        scope = _sudo_scope
        _reset_state()

    if scope is not None:
        logger.info("hermes-sudo: session ended — clearing sudo timestamp (scope was %s)", scope)
        _run_sudo_k()
