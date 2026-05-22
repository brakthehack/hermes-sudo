# hermes-sudo

**Your agent runs `sudo` commands. Your password stays with you.**

hermes-sudo lets your Hermes Agent run `sudo` commands without ever seeing your password. Authentication happens through your system's normal `sudo` prompt — the same one you see in a terminal.

## Quick start

```bash
hermes plugins enable hermes-sudo
```

That's it. The next time your agent needs `sudo`, it will call the `sudo_authorize` tool and prompt you.

## Why this is secure

| Property | How it's enforced |
|----------|------------------|
| **Agent never sees your password** | Authentication uses `sudo -v` on `/dev/tty`. Your password goes directly from your keyboard to the system PAM stack — the agent process never reads, stores, or forwards it. |
| **Can't batch sudo commands** | Default scope is `once`: one `sudo` command per authorization. After it runs, `sudo -k` immediately invalidates the credential cache. |
| **Destructive commands blocked** | Scope `confirm` catches dangerous tools (`rm`, `dd`, `mkfs`, etc.) and asks you before they run. |
| **Session ends cleanly** | When the conversation ends, `sudo -k` runs automatically — no lingering credentials. |
| **Audit trail** | Every `sudo` invocation is logged to `~/.hermes/logs/sudo-audit.log` with timestamp and command. |
| **No stdin piping** | Uses `sudo -v` (validate), not `sudo -S` (stdin). Your password is never in the command pipeline. |

## Scopes

| Scope | Commands per auth | Destructive ops |
|-------|-----------------|-----------------|
| `once` | 1 | Allowed (re-authorize for more) |
| `confirm` | 1 | **Blocked** — you must explicitly authorize `rm`, `dd`, `mkfs`, and similar |
| `session` | Unlimited until session ends | Allowed |

## Configuration

| Env var | Default | Effect |
|---------|---------|--------|
| `HERMES_SUDO_ALLOW_NOPASSWD` | `true` | Set to `false` to require explicit authorization even if you already have passwordless sudo |

## Requirements

- Hermes Agent (CLI mode — needs `/dev/tty`)
- `sudo` with PAM authentication
- Linux or macOS
