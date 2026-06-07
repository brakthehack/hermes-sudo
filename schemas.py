"""Tool schema for sudo_authorize."""

SUDO_AUTHORIZE_SCHEMA = {
    "name": "sudo_authorize",
    "description": (
        "Authorize the agent to run sudo commands. "
        "Opens a standard system password prompt on your terminal — "
        "the same prompt you'd see running 'sudo' yourself.\n\n"
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
        },
        "required": [],
    },
}
