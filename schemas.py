"""Tool schema for sudo_authorize."""

SUDO_AUTHORIZE_SCHEMA = {
    "name": "sudo_authorize",
    "description": (
        "Authorize the agent to run sudo commands. "
        "Opens a standard system password prompt on your terminal — "
        "the same prompt you'd see running 'sudo' yourself.\n\n"
        "When you know the exact command you want to run, pass it via the "
        "'command' parameter (without 'sudo' prefix — the plugin adds it). "
        "The command is shown in the password prompt so the user knows what "
        "they are authorizing.\n\n"
        "If you don't know the command yet, call without 'command' to just "
        "authorize, then run sudo commands via the terminal tool.\n\n"
        "Scopes:\n"
        "- once (default) — one sudo command, then must re-authorize\n"
        "- confirm — one sudo command; destructive operations (rm, dd, "
        "mkfs, etc.) are blocked and require explicit re-authorization\n"
        "- batch — up to N sudo commands; destructive operations are blocked "
        "and require explicit re-authorization. Requires 'count' parameter.\n"
        "- session — authorized for all sudo commands until session ends\n\n"
        "Use scope='status' to check current authorization state.\n\n"
        "Your password goes directly from your keyboard to sudo — "
        "the agent never sees, stores, or handles it."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "enum": ["once", "confirm", "batch", "session", "status"],
                "description": (
                    "'once' (default) — one sudo command, then re-authorize. "
                    "'confirm' — one sudo command, but destructive commands "
                    "(rm, dd, mkfs, etc.) are blocked and need explicit approval. "
                    "'batch' — up to N sudo commands (requires count), destructive "
                    "commands are blocked and need explicit approval. "
                    "'session' — authorized for all sudo commands until session ends. "
                    "'status' — check current authorization state."
                ),
            },
            "count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": (
                    "Required when scope='batch'. Maximum number of sudo commands "
                    "to authorize. Destructive commands still require explicit approval."
                ),
            },
            "command": {
                "type": "string",
                "description": (
                    "The command to run with sudo (without 'sudo' prefix). "
                    "When provided, the plugin runs the command directly after "
                    "authorization. The command is shown in the password prompt "
                    "so the user knows exactly what they are authorizing. "
                    "Example: 'apt update' (not 'sudo apt update')."
                ),
            },
        },
        "required": [],
    },
}
