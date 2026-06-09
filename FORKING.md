# Forking Hermes Agent for hermes-sudo

The hermes-sudo plugin requires changes to the Hermes Agent core to display the
sudo command in the password prompt. These changes are small and non-breaking.

## What changes are needed

Nine files in the Hermes Agent need to be patched:

| File | Change |
|------|--------|
| `tools/terminal_tool.py` | Add `set_sudo_pending_command` / `get_sudo_pending_command` thread-local functions |
| `cli.py` | Capture pending command in `_sudo_password_callback`, clear buffer, show command in `_get_sudo_display` with bold style |
| `tui_gateway/server.py` | Pass `pending_command` in `sudo.request` payload |
| `ui-tui/src/components/appOverlays.tsx` | Pass `sub={overlay.sudo.pendingCommand}` to `MaskedPrompt` |
| `ui-tui/src/components/maskedPrompt.tsx` | Render `sub` as bold accent text |
| `ui-tui/src/gatewayTypes.ts` | Add `pending_command?: string` to `sudo.request` payload type |
| `ui-tui/src/types.ts` | Add `pendingCommand?: string` to `SudoReq` interface |

## How to apply

### Option A: Fork and patch

1. Fork `hermes-agent` on GitHub
2. Apply the patches (see `patches/` directory in this repo)
3. Install your fork:
   ```bash
   hermes install --source git+https://github.com/<you>/hermes-agent.git
   ```
4. Install the plugin normally:
   ```bash
   bash install.sh
   ```

### Option B: Manual patch

If you don't want to fork, apply the patches directly to your installed agent:

```bash
# Apply patches to your installed agent
cd ~/.hermes/hermes-agent
git apply /path/to/hermes-sudo/patches/*.patch

# Clear bytecode caches
find . -name "*.pyc" -delete
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null

# Restart the gateway
systemctl --user restart hermes-gateway
```

Then install the plugin normally:
```bash
cd /path/to/hermes-sudo
bash install.sh
```

## Verifying the patch

After applying, the sudo password prompt should show:

```
╭─ 🔐 Sudo Password Required ─────────────────────────────────╮
│                                                             │
│ Command: apt update                                         │
│                                                             │
│ Enter password below (hidden), or press Enter to skip       │
│                                                             │
╰─────────────────────────────────────────────────────────────╯
```

The command line is rendered in bold red so it stands out.

## Upstream

These changes are minimal and non-breaking. Consider opening a PR against the
Hermes Agent repo so the plugin works out of the box.
