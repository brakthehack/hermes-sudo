# hermes-sudo

**Your agent runs `sudo` commands. Your password stays with you.**

hermes-sudo lets your Hermes agent run `sudo` commands without ever seeing your password. Authentication happens through your system's normal `sudo` prompt — the same one you see in a terminal. No stdin piping, no secret storage.

## Quick start

```bash
hermes plugins enable hermes-sudo
```

That's it. Next time your agent needs `sudo`, it'll prompt you through the tool `sudo_authorize` first.

## How it works

| Step | What happens |
|------|-------------|
| 1. Agent needs `sudo` | The agent calls `sudo_authorize` |
| 2. You authenticate | A standard password prompt appears on your terminal |
| 3. Command runs | The agent executes one `sudo` command |
| 4. Credentials wiped | `sudo -k` clears the timestamp — no piggybacking |

## Two scopes

- **`once`** (default) — authorize one command. The agent must re-authorize for each subsequent `sudo`.
- **`session`** — authorize for the whole conversation. `sudo -k` runs when the session ends.

## Safety details

| Concern | How it's handled |
|---------|-----------------|
| Password exposure | `sudo -v` prompts on `/dev/tty` — agent never reads your input |
| Batch abuse | `once` scope + `sudo -k` after each command prevents cascading |
| NOPASSWD users | Works transparently — no authorization prompt needed |
| Session cleanup | `sudo -k` runs automatically when the session ends |

## Configuration

| Env var | Default | Effect |
|---------|---------|--------|
| `HERMES_SUDO_ALLOW_NOPASSWD` | `true` | Set to `false` to require explicit authorization even if you have passwordless sudo |

## Requirements

- Hermes Agent (CLI mode only — `/dev/tty` required)
- `sudo` with PAM authentication
- Linux / macOS
