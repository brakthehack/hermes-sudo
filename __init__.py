"""hermes-sudo plugin — secure sudo for Hermes Agent.

Your agent can run sudo commands. Your password never leaves your keyboard.
"""

from __future__ import annotations

import logging

try:
    from . import schemas as _schemas
    from . import tools as _tools
except ImportError:
    _schemas = None
    _tools = None

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    ctx.register_tool(
        name="sudo_authorize",
        toolset="hermes_sudo",
        schema=_schemas.SUDO_AUTHORIZE_SCHEMA,
        handler=_tools._handle_sudo_authorize,
        emoji="🔐",
    )

    ctx.register_hook("pre_tool_call", _tools._on_pre_tool_call)
    ctx.register_hook("post_tool_call", _tools._on_post_tool_call)
    ctx.register_hook("on_session_end", _tools._on_session_end)

    logger.info("hermes-sudo plugin registered: sudo_authorize tool + 3 hooks")
