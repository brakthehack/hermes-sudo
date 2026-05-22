#!/usr/bin/env bash
# Register hermes-sudo as an official Hermes Agent plugin.
#
# Usage:
#   bash register.sh                        # interactive (default)
#   bash register.sh --publish             # also attempt to publish to hub
#   bash register.sh --help                # this message
#
# Requirements:
#   - Hermes Agent installed
#   - Git installed
#   - A GitHub account (for publish flow)
#
# What this does:
#   1. Checks that Hermes Agent is available
#   2. Offers to install via `hermes plugins install <git-url>`
#   3. Offers to set HERMES_SUDO_ALLOW_NOPASSWD if desired
#   4. Shows the after-install guide
#   5. Optionally publishes to the skills hub

set -euo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="hermes-sudo"
GIT_REMOTE="${GIT_REMOTE:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}::${NC} $1"; }
ok()    { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
err()   { echo -e "${RED}✗${NC} $1" >&2; }

usage() {
  sed -n '/^#\s*$/,/^[^#]/p' "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \?//'
  exit 0
}

# Parse args
PUBLISH=false
for arg in "$@"; do
  case "$arg" in
    --help|-h) usage ;;
    --publish) PUBLISH=true ;;
  esac
done

echo ""
echo "  ╭─────────────────────────────╮"
echo "  │   hermes-sudo registration   │"
echo "  ╰─────────────────────────────╯"
echo ""

# Step 1: Check dependencies
info "Checking dependencies..."

if ! command -v hermes &>/dev/null; then
  err "hermes not found on PATH. Is Hermes Agent installed?"
  info "Install: curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash"
  exit 1
fi
ok "Hermes Agent found: $(hermes --version 2>/dev/null || echo 'present')"

if ! command -v git &>/dev/null; then
  err "git not found. Please install git first."
  exit 1
fi
ok "Git found"

# Step 2: Determine install source
if [ -n "$GIT_REMOTE" ]; then
  INSTALL_SOURCE="$GIT_REMOTE"
elif git -C "$THIS_DIR" remote get-url origin &>/dev/null; then
  INSTALL_SOURCE="$(git -C "$THIS_DIR" remote get-url origin)"
  info "Using remote: $INSTALL_SOURCE"
else
  # No remote configured — use the local path
  INSTALL_SOURCE="$THIS_DIR"
  warn "No git remote configured. Installing from local path: $INSTALL_SOURCE"
  warn "Run 'git remote add origin <url>' and push to GitHub for 'hermes plugins install <url>' to work."
  echo ""
  read -r -p "Install from local path? [Y/n] " REPLY
  if [[ "$REPLY" =~ ^[Nn] ]]; then
    info "Aborted."
    exit 0
  fi
fi

# Step 3: Install via hermes plugins
info "Installing plugin: $INSTALL_SOURCE"

if [ -d "$HOME/.hermes/plugins/hermes-sudo" ]; then
  warn "Plugin already installed at ~/.hermes/plugins/hermes-sudo"
  read -r -p "Reinstall? [y/N] " REPLY
  if [[ ! "$REPLY" =~ ^[Yy] ]]; then
    info "Skipping install."
  else
    rm -rf "$HOME/.hermes/plugins/hermes-sudo"
    hermes plugins install "$INSTALL_SOURCE" 2>&1 || true
  fi
else
  # Symlink for local installs; clone for remote
  if [[ "$INSTALL_SOURCE" == "$THIS_DIR" ]]; then
    ln -sfn "$THIS_DIR" "$HOME/.hermes/plugins/hermes-sudo"
    ok "Symlinked to ~/.hermes/plugins/hermes-sudo"
  else
    hermes plugins install "$INSTALL_SOURCE" 2>&1 || {
      err "Plugin install failed. Check the URL and try again."
      exit 1
    }
  fi
fi

# Step 4: Post-install notes
echo ""
info "After-install summary:"
cat "$THIS_DIR/after-install.md" 2>/dev/null || echo "  (see README.md for usage)"

# Step 5: Optional NOPASSWD config
echo ""
if hermes config get HERMES_SUDO_ALLOW_NOPASSWD &>/dev/null; then
  CURRENT=$(hermes config get HERMES_SUDO_ALLOW_NOPASSWD 2>/dev/null || echo "true")
  info "HERMES_SUDO_ALLOW_NOPASSWD is currently: $CURRENT"
  read -r -p "Change? (true=allow passwordless sudo, false=require auth always) [Enter to keep] " REPLY
  if [ -n "$REPLY" ] && [[ "$REPLY" =~ ^(true|false|1|0|yes|no)$ ]]; then
    export HERMES_SUDO_ALLOW_NOPASSWD="$REPLY"
    ok "Set HERMES_SUDO_ALLOW_NOPASSWD=$REPLY (add to ~/.hermes/.env to persist)"
  fi
fi

# Step 6: Publish to skills hub (optional)
if $PUBLISH; then
  echo ""
  if [ -n "$GIT_REMOTE" ] || git -C "$THIS_DIR" remote get-url origin &>/dev/null; then
    info "Publishing to skills hub..."
    hermes skills publish "$THIS_DIR" 2>&1 || warn "Publish failed (may need auth)"
  else
    warn "No git remote — can't publish. Set GIT_REMOTE or push to GitHub first."
  fi
fi

# Done
echo ""
ok "Registration complete!"
echo ""
info "Start a new session (/reset) and ask your agent to do something with sudo."
info "The agent will call sudo_authorize and prompt you on your terminal."
echo ""
