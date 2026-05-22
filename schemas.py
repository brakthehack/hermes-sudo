"""Tool schema for sudo_authorize."""

SUDO_AUTHORIZE_SCHEMA = {
    "name": "sudo_authorize",
    "description": (
        "Authorize the hermes agent to run sudo commands. "
        "Opens a system password prompt on your terminal (not inline) to authenticate via sudo. "
        "By default, authorization is for ONE command only — the agent must re-authorize "
        "for each subsequent sudo command. Use scope='session' for session-wide authorization.\n\n"
        "This tool NEVER sees or stores your password. It delegates authentication to sudo -v "
        "which prompts through the system PAM stack on /dev/tty."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "enum": ["once", "session"],
                "description": (
                    "How long the authorization lasts. "
                    "'once' (default) — one sudo command only, then must re-authorize. "
                    "'session' — authorized for all sudo commands until the session ends."
                ),
            },
        },
        "required": [],
    },
}
