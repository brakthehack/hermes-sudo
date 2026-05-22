"""Tool schema for sudo_authorize."""

SUDO_AUTHORIZE_SCHEMA = {
    "name": "sudo_authorize",
    "description": (
        "Authorize the agent to run sudo commands. "
        "Opens a standard system password prompt on your terminal — "
        "the same prompt you'd see running 'sudo' yourself. "
        "By default, ONE command is authorized. "
        "Use scope='session' for session-wide authorization.\\n\\n"
        "Your password goes directly from your keyboard to sudo — "
        "the agent never sees, stores, or handles it."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "enum": ["once", "session"],
                "description": (
                    "'once' (default) — one sudo command, then must re-authorize. "
                    "'session' — authorized for all sudo commands until the conversation ends."
                ),
            },
        },
        "required": [],
    },
}
