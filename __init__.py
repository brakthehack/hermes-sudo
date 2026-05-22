"""hermes-sudo plugin — secure ephemeral sudo access via system PAM.

Provides:
- ``sudo_authorize`` tool — authenticate via system password prompt
- ``pre_tool_call`` hook — gate terminal sudo commands
- ``post_tool_call`` hook — consume once-scoped authorization
- ``on_session_end`` hook — clear timestamps on session teardown
"""

from __future__ import annotations

import logging
import sys
import os

try:
    from . import schemas as _schemas
    from . import tools as _tools
except ImportError:
    # Standalone import (e.g. pytest from project root)
    _schemas = None
    _tools = None

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    """Register the sudo_authorize tool and lifecycle hooks.

    Called once by the plugin loader when the plugin is enabled via
    ``plugins.enabled`` in config.yaml.
    """
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
