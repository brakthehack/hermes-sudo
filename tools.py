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
    i = 0
    n = len(command)
    at_cmd_start = True
    after_sudo = False
    while i < n:
        c = command[i]
        if c.isspace() or c == "\n":
            i += 1
            continue
        # Skip comments (only at command start)
        if c == "#" and at_cmd_start:
            nl = command.find("\n", i)
            i = nl + 1 if nl != -1 else n
            at_cmd_start = True
            continue
        # Command separators and operators reset to command-start
        if c in ";|&)":
            i += 1
            at_cmd_start = True
            continue
        # Skip parenthesised groups
        if c == "(":
            depth = 1
            i += 1
            while i < n and depth > 0:
                if command[i] == "(":
                    depth += 1
                elif command[i] == ")":
                    depth -= 1
                i += 1
            at_cmd_start = False
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
            i += 1 if i < n else 0
            at_cmd_start = False
            continue
        # Unquoted token
        start = i
        while i < n and not command[i].isspace() and command[i] not in ";|&()\"'#":
            i += 1
        token = command[start:i]
        if at_cmd_start:
            if token == "sudo":
                after_sudo = True
                at_cmd_start = False
                continue
            # Check if token starts with a confirm trigger (catches mkfs.ext4, etc.)
            for trigger in _CONFIRM_TRIGGERS:
                if token == trigger or token.startswith(trigger + "."):
                    return True
        elif after_sudo:
            after_sudo = False
            for trigger in _CONFIRM_TRIGGERS:
                if token == trigger or token.startswith(trigger + "."):
                    return True
        at_cmd_start = False
    return False


# ---------------------------------------------------------------------------
# Module-level state (guarded by _lock)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_sudo_scope: Optional[str] = None   # None | "once" | "session" | "confirm"
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
# sudo detection
# ---------------------------------------------------------------------------

def _command_has_real_sudo(command: str) -> bool:
    """Return True if *command* contains a real (unquoted, command-position) sudo."""
    i = 0
    n = len(command)
    cmd_start = True
    env_pending = False
    prefix_active = False

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

        if cmd_start and token == "sudo":
            return True

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
        elif cmd_start and token in _PREFIX_TOKENS:
            env_pending = False
            prefix_active = True
        elif cmd_start and prefix_active and (token.startswith("-") or token.isdigit()):
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
                ppid = int(tail[2])
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


def _run_sudo_v() -> int:
    """Authenticate via ``sudo -v``.

    Strategy (tried in order):

    1. **Direct /dev/tty read + sudo -S** — Opens ``/dev/tty`` directly
       and writes the prompt + reads the password using raw termios ops.
       Does NOT use ``getpass.getpass()`` (which writes to ``sys.stdout``,
       captured by Hermes's tool output) and does NOT give ``sudo`` the
       TTY directly (Hermes writes to it concurrently, garbling the prompt).
       The password is piped via stdin to ``sudo -S -v`` and zeroed in
       memory immediately after use.

    2. **/dev/tty + sudo -v** — direct ``/dev/tty`` open passed to sudo.
       Works in normal terminals outside Hermes.

    3. **PTY scan + sudo -v** — find the Hermes CLI's PTY via ``/proc``.

    4. **No-TTY fallback** — ``sudo -v`` with DEVNULL stdin.
    """
    # Strategy 1: direct /dev/tty read + sudo -S (works inside Hermes main loop)
    try:
        import termios as _termios
        tty_fd = os.open("/dev/tty", os.O_RDWR)
        # Write prompt directly to /dev/tty (bypasses Hermes's stdout capture)
        prompt = "[sudo] password for %s: " % os.getlogin()
        os.write(tty_fd, prompt.encode())
        # Disable echo
        old_attrs = _termios.tcgetattr(tty_fd)
        new_attrs = _termios.tcgetattr(tty_fd)
        new_attrs[3] = new_attrs[3] & ~_termios.ECHO
        _termios.tcsetattr(tty_fd, _termios.TCSAFLUSH, new_attrs)
        # Read password character by character until newline
        password_chars: list[bytes] = []
        while True:
            b = os.read(tty_fd, 1)
            if not b or b in (b"\n", b"\r"):
                break
            if b == b"\x03":  # Ctrl-C
                raise KeyboardInterrupt
            if b == b"\x7f" or b == b"\x08":  # Backspace
                if password_chars:
                    password_chars.pop()
                continue
            password_chars.append(b)
        # Restore terminal settings
        _termios.tcsetattr(tty_fd, _termios.TCSAFLUSH, old_attrs)
        # Write newline after password entry
        os.write(tty_fd, b"\n")
        os.close(tty_fd)

        password = b"".join(password_chars).decode("utf-8", errors="replace")
        proc = subprocess.run(
            ["sudo", "-S", "-v"],
            input=password + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        # Zero the password from memory immediately
        password = "\x00" * len(password)
        return proc.returncode
    except (OSError, EOFError, KeyboardInterrupt, subprocess.TimeoutExpired):
        pass
    except Exception as _ex:
        # termios.error or similar — attempt cleanup
        try:
            _termios.tcsetattr(tty_fd, _termios.TCSAFLUSH, old_attrs)  # type: ignore
        except Exception:
            pass
        try:
            os.close(tty_fd)  # type: ignore
        except Exception:
            pass

    # Strategy 2: direct /dev/tty
    try:
        tty_fd = os.open("/dev/tty", os.O_RDWR)
        proc = subprocess.run(
            ["sudo", "-v"],
            stdin=tty_fd,
            stdout=tty_fd,
            stderr=tty_fd,
            timeout=60,
            close_fds=False,
            check=False,
        )
        os.close(tty_fd)
        return proc.returncode
    except OSError:
        pass

    # Strategy 3: find Hermes CLI PTY via /proc scan
    tty_path = _find_tty_path()
    if tty_path is not None:
        tty_fd = None
        try:
            tty_fd = os.open(tty_path, os.O_RDWR)
            proc = subprocess.run(
                ["sudo", "-v"],
                stdin=tty_fd,
                stdout=tty_fd,
                stderr=tty_fd,
                timeout=60,
                close_fds=False,
                check=False,
            )
            os.close(tty_fd)
            return proc.returncode
        except OSError:
            if tty_fd is not None:
                try:
                    os.close(tty_fd)
                except OSError:
                    pass

    # Strategy 4: no-TTY fallback
    try:
        proc = subprocess.run(
            ["sudo", "-v"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,
            timeout=60, check=False,
        )
        return proc.returncode
    except Exception:
        return 1


def _run_sudo_k() -> None:
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


# ---------------------------------------------------------------------------
# Tool handler: sudo_authorize
# ---------------------------------------------------------------------------

def _handle_sudo_authorize(
    scope: str = "once",
    **kwargs: Any,
) -> str:
    global _sudo_scope, _sudo_consumed
    scope = scope.strip().lower() if isinstance(scope, str) else "once"
    if scope not in ("once", "confirm", "session"):
        return json.dumps({"error": f"Invalid scope '{scope}'. Must be 'once', 'confirm', or 'session'."})

    if _sudo_nopasswd_works():
        with _lock:
            _sudo_scope = scope
            _sudo_consumed = False
        logger.info("sudo_authorize: already have sudo access (NOPASSWD or existing timestamp) — scope=%s", scope)
        return json.dumps({
            "success": True,
            "scope": scope,
            "message": f"sudo authorized for {scope}. Existing sudo credentials are valid — no password prompt needed.",
        })

    logger.info("sudo_authorize: running sudo -v for scope=%s", scope)
    rc = _run_sudo_v()
    if rc != 0:
        logger.warning("sudo_authorize: sudo -v failed (exit code %d)", rc)
        return json.dumps({
            "error": "sudo authentication failed. Check your password and try again. Make sure the hermes terminal has access to /dev/tty.",
        })

    with _lock:
        _sudo_scope = scope
        _sudo_consumed = False

    _log_audit("AUTHORIZE", f"scope={scope}", user="human")
    logger.info("sudo_authorize: authorized for scope=%s", scope)
    return json.dumps({
        "success": True,
        "scope": scope,
        "message": f"sudo authorized for {scope}. "
        + {
            "once": "The agent may run one sudo command, then must re-authorize.",
            "confirm": "The agent may run one sudo command. Destructive commands (rm, dd, mkfs, etc.) will be blocked and need explicit approval.",
            "session": "The agent may run sudo commands for the remainder of this session.",
        }[scope],
    })


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

    allow_nopasswd = os.environ.get("HERMES_SUDO_ALLOW_NOPASSWD", "true").strip().lower()
    if allow_nopasswd in ("1", "true", "yes", "on") and _sudo_nopasswd_works():
        logger.debug("hermes-sudo: NOPASSWD sudo detected — passing through")
        _log_audit("EXEC", command, user="agent-nopasswd")
        return None

    with _lock:
        scope = _sudo_scope
        consumed = _sudo_consumed

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
            logger.info("hermes-sudo: session timestamp expired — attempting re-auth via sudo -v")
            rc = _run_sudo_v()
            if rc != 0:
                with _lock:
                    _reset_state()
                return {
                    "action": "block",
                    "message": "sudo session authorization expired and re-authentication failed. Call sudo_authorize(scope='session') to re-authorize.",
                }
            logger.info("hermes-sudo: session re-auth succeeded")
        _log_audit("EXEC", command, user="agent-session")
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
    global _sudo_consumed

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
