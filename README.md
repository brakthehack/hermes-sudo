# hermes-sudo

**Secure ephemeral sudo access for [hermes-agent](https://github.com/NousResearch/hermes-agent).**

Authenticates using the **system's PAM stack** (`sudo -v` on `/dev/tty`) — the agent never sees or handles your password. Default: authorize one command at a time. Supports session-scoped authorization.

## How it works

Most agent sudo solutions pipe the password through stdin (`sudo -S`), exposing it to the agent process. This plugin takes a different approach:

1. **`sudo_authorize`** calls `sudo -v` to authenticate the user via the system's PAM prompt on `/dev/tty` (the same prompt you'd see running `sudo` in a terminal). Your password goes directly from your keyboard to `sudo` — hermes never touches it.
2. After successful authentication, `sudo` commands work using the system's **timestamp mechanism** (credential cache). The existing terminal tool already detects valid timestamps and skips `-S` password injection, so the plugin just needs to ensure a valid timestamp exists.

## Installation

```bash
hermes plugins enable hermes-sudo
```

Or add to `~/.hermes/cli-config.yaml`:

```yaml
plugins:
  enabled:
    - hermes-sudo
```

The plugin is a **user plugin** — it lives at `~/.hermes/plugins/hermes-sudo/`. To develop or inspect, clone this repo and symlink:

```bash
git clone <this-repo> ~/.hermes/plugins/hermes-sudo
```

## Usage

### Authorize a single command (default)

```json
{
  "name": "sudo_authorize",
  "arguments": { "scope": "once" }
}
```

- A system password prompt appears on your terminal.
- The agent may run **one** `sudo` command, then must re-authorize.
- After the command runs, `sudo -k` clears the credential cache.

### Authorize for the session

```json
{
  "name": "sudo_authorize",
  "arguments": { "scope": "session" }
}
```

- The agent may run any number of `sudo` commands until the session ends.
- If the sudo timestamp expires during the session, the plugin attempts silent re-authentication automatically. If that fails, the agent is blocked and must call `sudo_authorize` again.

## Tool reference

### `sudo_authorize`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | `string` (`"once"` \| `"session"`) | `"once"` | Duration of authorization |

Returns: `{"success": true, "scope": "once|session", "message": "…"}` or `{"error": "…"}`.

## Security model

- **Password not stored** — authentication goes through `sudo -v` on `/dev/tty`. The tool handler never reads, sends, or stores the password.
- **One-command default** — scope=`"once"` prevents the agent from running a series of sudo commands after a single authorization. Each command requires explicit re-authorization.
- **Timestamp cleared** — after "once" scope is consumed, `sudo -k` invalidates the credential cache so the agent cannot exploit a still-valid timestamp window.
- **Session teardown** — `sudo -k` runs at session end regardless of scope.
- **NOPASSWD bypass** — when the user has passwordless sudo configured, commands pass through without an `sudo_authorize` call (opt-in management via `HERMES_SUDO_ALLOW_NOPASSWD`, default: allow).

## Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `HERMES_SUDO_ALLOW_NOPASSWD` | `true` | When `false`, require explicit `sudo_authorize` even if the user has NOPASSWD sudo configured. |

## Limitations

- **CLI mode only** — relies on `/dev/tty` for the PAM prompt. Gateway/API modes do not have a controlling terminal.
- **`env sudo`** — commands like `env -i sudo whoami` (where sudo is an argument to another command) are not detected as sudo invocations. This is an acceptable edge case — agents do not normally proxy through `env`.
