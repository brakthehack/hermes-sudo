# Welcome to hermes-sudo 🛡️

**Your agent now has secure, audited sudo access.**

## What changed

| What | Where |
|------|-------|
| Plugin installed | `~/.hermes/plugins/hermes-sudo/` |
| Tools added | `sudo_authorize` (and lifecycle hooks) |
| Audit log | `~/.hermes/logs/sudo-audit.log` |

## Try it

Start a new session (`/reset` or `hermes`) and ask your agent to do something that needs `sudo`:

```
> check the system logs
```

The agent will call `sudo_authorize`, a password prompt appears on your terminal, and one `sudo` command runs.

## Pick your scope

When the agent asks for authorization, you can choose:

- **`once`** (default) — one command, then `sudo -k` clears credentials
- **`confirm`** — one command, but `rm -rf`, `dd`, `mkfs`, `shutdown`, and similar destructive tools are blocked and need explicit re-authorization
- **`session`** — authorize for the whole conversation

## Need to opt out?

```bash
hermes plugins remove hermes-sudo
```

## Audit trail

Review everything that ran:

```bash
cat ~/.hermes/logs/sudo-audit.log
```
