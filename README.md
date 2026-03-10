# bash-guard

A [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that evaluates Bash commands for safety before execution. It acts as a `PermissionRequest` hook, applying a multi-stage evaluation system to automatically allow safe commands, block dangerous ones, and defer ambiguous cases to an LLM judge.

## Installation

```bash
uv tool install .
```

Then register the hooks with Claude Code:

```bash
bash-guard install
```

This adds `bash-guard` as a `PermissionRequest` hook in `~/.claude/settings.json`. A backup (`settings.json.bak`) is created automatically.

To remove:

```bash
bash-guard uninstall
```

## How it works

Every Bash command and Read file path is evaluated through a multi-stage pipeline:

```
stdin JSON → RULE_DENY → RULE_ALLOW → RULE_ASK → LLM_JUDGE → stdout JSON
```

| Stage | Method | Speed | Description |
|-------|--------|-------|-------------|
| RULE_DENY | Regex deny list | Instant | Blocks known-dangerous commands (e.g. `sudo`, `rm -rf /`, `curl \| bash`) |
| RULE_ALLOW | Regex allow list | Instant | Permits known-safe commands (e.g. `ls`, `git status`, `make`) |
| RULE_ASK | Regex ask list | Instant | Prompts user confirmation for commands that need review (e.g. `ssh`, `systemctl`) |
| LLM_JUDGE | LLM judge | ~2-5s | Calls `claude -p` with haiku to evaluate ambiguous commands |

For the `Read` tool, only RULE_DENY rules are checked (e.g. `.env` files are blocked). If no deny rule matches, the read is allowed.

Unknown tools (not `Bash` or `Read`) are passed through without evaluation.

## Deny rules (RULE_DENY)

| Rule | Pattern |
|------|---------|
| `rm-rf-root` | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` |
| `sudo` | Any command starting with `sudo` |
| `fork-bomb` | `:(){ :\|:& };:` pattern |
| `mkfs` | `mkfs` / `mkfs.ext4` etc. |
| `dd-zero` | `dd if=/dev/zero` or `/dev/urandom` |
| `pipe-to-shell` | `curl \| bash`, `wget \| sh` |
| `force-push-main` | `git push --force` to `main`/`master` (allows `--force-with-lease`) |
| `env-write` | Writing to `.env` files via `>`, `>>`, `tee` |
| `env-files` | Reading `.env` / `.env.*` files (Read tool) |

## Allow rules (RULE_ALLOW)

Common development commands are auto-approved, including:

- File operations: `ls`, `cat`, `head`, `tail`, `find`, `grep`, `cp`, `mv`, `mkdir`, `touch`, `rm`, `trash`
- Git: `status`, `log`, `diff`, `add`, `commit`, `push` (with `--force-with-lease`), etc.
- Build tools: `make`, `cargo`, `go build`, `npm`, `node`, `python`, `uv`
- Utilities: `echo`, `pwd`, `which`, `date`, `sort`, `sed`, `awk`, `curl`, `docker`, `tar`, `zip`

See [`src/bash_guard/rules/allow.toml`](src/bash_guard/rules/allow.toml) for the full list.

## Ask rules (RULE_ASK)

Commands that prompt user confirmation without LLM evaluation:

- `ssh` — remote connections
- `systemctl` — system service management
- `crontab -e` / `crontab -r` — crontab editing/removal

See [`src/bash_guard/rules/ask.toml`](src/bash_guard/rules/ask.toml) for the full list.

## CLI usage

### Hook mode (default)

Reads JSON from stdin and writes the hook response to stdout. This is how Claude Code invokes it:

```bash
echo '{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s","cwd":"/tmp"}' | bash-guard
```

### Test mode

Evaluate a command without the full hook protocol:

```bash
bash-guard --test "ls -la"
# ALLOW [RULE_ALLOW]: Allowed by rule: ls

bash-guard --test "sudo rm -rf /"
# DENY [RULE_DENY]: Blocked by deny rule: rm-rf-root
```

### Debug output

Add `--explain` to print the decision reason to stderr:

```bash
bash-guard --test "ls -la" --explain
```

### Hook management

```bash
bash-guard install    # Add hooks to ~/.claude/settings.json
bash-guard uninstall  # Remove hooks from ~/.claude/settings.json
```

## LLM judge (LLM_JUDGE)

When a command matches neither deny, allow, nor ask rules, `bash-guard` invokes:

```
claude -p "<prompt>" --model claude-haiku-4-5-20251001
```

The LLM evaluates the command and responds with `ALLOW`, `DENY`, or `ASK`. On timeout (15s) or error, the decision falls back to `ASK`, which prompts the user for manual approval.

## Project structure

```
src/bash_guard/
├── cli.py           # Entry point, argparse
├── evaluator.py     # Multi-stage evaluation engine
├── hook_io.py       # stdin/stdout JSON handling
├── rule_engine.py   # TOML rule loading and regex matching
├── llm_judge.py     # LLM_JUDGE: claude subprocess
├── installer.py     # Hook install/uninstall
└── rules/
    ├── deny.toml      # RULE_DENY patterns
    ├── allow.toml     # RULE_ALLOW patterns
    ├── ask.toml       # RULE_ASK patterns
    └── llm_prompt.txt # LLM_JUDGE prompt template
```

## Development

```bash
# Run tests
uv run pytest tests/ -v

# Test a command locally
uv run bash-guard --test "your-command-here"
```

Requires Python 3.11+ (uses `tomllib` from the standard library). Zero external runtime dependencies.
