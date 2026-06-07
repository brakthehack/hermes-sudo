#!/usr/bin/env bash
# Install (or reinstall) hermes-sudo plugin.
#
# Copies the source tree into ~/.hermes/plugins/hermes-sudo/, clears
# bytecode caches so the plugin system picks up the latest code on
# the next session, and ensures the plugin is enabled.
#
# Usage:
#   bash install.sh              # normal install
#   bash install.sh --force      # force overwrite even if installed

set -euo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$HOME/.hermes/plugins/hermes-sudo"
FORCE="${1:-}"

echo ""
echo "  ╭─────────────────────────────╮"
echo "  │   hermes-sudo installer     │"
echo "  ╰─────────────────────────────╯"
echo ""

# ─── Safety check ──────────────────────────────────────────────

if [ -d "$PLUGIN_DIR" ] && [ "$FORCE" != "--force" ]; then
    echo "  Plugin already installed at:"
    echo "    $PLUGIN_DIR"
    echo ""
    echo "  Re-run with '--force' to overwrite."
    exit 0
fi

# ─── Copy source files ─────────────────────────────────────────

echo "  Copying plugin files..."
mkdir -p "$PLUGIN_DIR"

cp "$THIS_DIR"/*.py      "$PLUGIN_DIR/" 2>/dev/null
cp "$THIS_DIR"/*.yaml    "$PLUGIN_DIR/" 2>/dev/null || true
cp "$THIS_DIR"/*.md      "$PLUGIN_DIR/" 2>/dev/null || true
cp "$THIS_DIR"/*.toml    "$PLUGIN_DIR/" 2>/dev/null || true

# Tests (optional, nice for debugging)
if [ -d "$THIS_DIR/tests" ]; then
    cp -r "$THIS_DIR/tests" "$PLUGIN_DIR/"
fi

# ─── Clear bytecode caches ─────────────────────────────────────

echo "  Clearing Python bytecode caches..."
find "$PLUGIN_DIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# ─── Enable the plugin ─────────────────────────────────────────

echo "  Enabling plugin..."
hermes plugins enable hermes-sudo 2>/dev/null || true

# ─── Done ──────────────────────────────────────────────────────

echo ""
echo "  ✓ hermes-sudo installed to:"
echo "    $PLUGIN_DIR"
echo ""
echo "  Start a new session (/reset) and ask your agent to do"
echo "  something with sudo. The agent will call sudo_authorize."
echo "  Your password goes directly from your keyboard to your"
echo "  system's PAM — the agent never sees it."
echo ""
