# claude-sentinel

A [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that evaluates tool permission requests before execution. It acts as a `PermissionRequest` hook, applying a multi-stage evaluation system to automatically allow safe commands, block dangerous ones, and defer ambiguous cases to an LLM judge.

## Installation

```bash
uv tool install .
```

Then register the hooks with Claude Code:

```bash
claude-sentinel install
```

This adds `claude-sentinel` as a `PermissionRequest` hook in `~/.claude/settings.json`. A backup (`settings.json.bak`) is created automatically.

To remove:

```bash
claude-sentinel uninstall
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

For the `Read` tool, only RULE_DENY rules are checked (see [Read deny rules](#read-deny-rules-rule_deny) below). If no deny rule matches, the read is allowed.

Read-only tools with no side effects (`Grep`, `Glob`, `WebFetch`, `WebSearch`) are auto-allowed without evaluation.

Other tools (e.g. `Write`, `Edit`, MCP tools) are passed through without evaluation (Claude Code default behavior applies).

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

## Read deny rules (RULE_DENY)

Sensitive files blocked from the `Read` tool:

| Category | Rule | Pattern |
|----------|------|---------|
| Env/config | `env-files` | `.env`, `.env.*` |
| Env/config | `envrc` | `.envrc` |
| Env/config | `secrets-files` | `secrets.{yml,yaml,json,toml}` |
| Env/config | `terraform-vars` | `terraform.tfvars`, `terraform.tfvars.json` |
| SSH/keys | `ssh-dir` | `.ssh/*` |
| SSH/keys | `gnupg-dir` | `.gnupg/*` |
| SSH/keys | `private-key-files` | `*.pem`, `*.key` (excludes `*.pub.pem`) |
| SSH/keys | `keystore-files` | `*.p12`, `*.pfx`, `*.jks`, `*.keystore` |
| Cloud | `aws-dir` | `.aws/*` |
| Cloud | `gcloud-dir` | `.config/gcloud/*` |
| Cloud | `azure-dir` | `.azure/*` |
| Cloud | `credentials-json` | `credentials.json`, `client_secret.json`, `service[-_]account*.json` |
| Cloud | `terraform-rc` | `.terraformrc` |
| Container | `docker-config` | `.docker/config.json` |
| Container | `kube-config` | `.kube/config` |
| Dev tools | `netrc` | `.netrc` |
| Dev tools | `npmrc` | `.npmrc` |
| Dev tools | `pypirc` | `.pypirc` |
| Dev tools | `gh-hosts` | `.config/gh/hosts.yml` |
| Dev tools | `maven-settings` | `.m2/settings.xml` |
| Dev tools | `gradle-properties` | `.gradle/gradle.properties` |
| Dev tools | `boto-config` | `.boto`, `.s3cfg` |
| Database | `pgpass` | `.pgpass` |
| Database | `mycnf` | `.my.cnf` |
| Other | `htpasswd` | `.htpasswd` |
| Other | `vault-token` | `.vault-token` |

See [`src/claude_sentinel/rules/deny.toml`](src/claude_sentinel/rules/deny.toml) for exact regex patterns.

## Auto-allow tools (AUTO_ALLOW)

Read-only tools with no side effects are automatically allowed without rule evaluation:

- `Grep` — content search
- `Glob` — file pattern matching
- `WebFetch` — fetch web content
- `WebSearch` — web search

## Allow rules (RULE_ALLOW)

Common development commands are auto-approved, including:

- File operations: `ls`, `cat`, `head`, `tail`, `find`, `grep`, `cp`, `mv`, `mkdir`, `touch`, `rm`, `trash`
- Git: `status`, `log`, `diff`, `add`, `commit`, `push` (with `--force-with-lease`), etc.
- Build tools: `make`, `cargo`, `go build`, `npm`, `node`, `python`, `uv`
- Utilities: `echo`, `pwd`, `which`, `date`, `sort`, `sed`, `awk`, `curl`, `docker`, `tar`, `zip`

See [`src/claude_sentinel/rules/allow.toml`](src/claude_sentinel/rules/allow.toml) for the full list.

## Ask rules (RULE_ASK)

Commands that prompt user confirmation without LLM evaluation:

- `ssh` — remote connections
- `systemctl` — system service management
- `crontab -e` / `crontab -r` — crontab editing/removal

See [`src/claude_sentinel/rules/ask.toml`](src/claude_sentinel/rules/ask.toml) for the full list.

## CLI usage

### Hook mode (default)

Reads JSON from stdin and writes the hook response to stdout. This is how Claude Code invokes it:

```bash
echo '{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s","cwd":"/tmp"}' | claude-sentinel
```

### Test mode

Evaluate a command without the full hook protocol:

```bash
claude-sentinel --test "ls -la"
# ALLOW [RULE_ALLOW]: Allowed by rule: ls

claude-sentinel --test "sudo rm -rf /"
# DENY [RULE_DENY]: Blocked by deny rule: rm-rf-root
```

### Debug output

Add `--explain` to print the decision reason to stderr:

```bash
claude-sentinel --test "ls -la" --explain
```

### List rules

Display all loaded rules:

```bash
claude-sentinel rules                          # Show all rules
claude-sentinel rules --kind deny              # Deny rules only
claude-sentinel rules --type Read              # Read tool rules only
claude-sentinel rules --kind deny --type Read  # Combined filter
claude-sentinel rules --json                   # JSON Lines output
```

### Hook management

```bash
claude-sentinel install    # Add hooks to ~/.claude/settings.json
claude-sentinel uninstall  # Remove hooks from ~/.claude/settings.json
```

## LLM judge (LLM_JUDGE)

When a command matches neither deny, allow, nor ask rules, `claude-sentinel` invokes:

```
claude -p "<prompt>" --model claude-haiku-4-5-20251001
```

The LLM evaluates the command and responds with `ALLOW`, `DENY`, or `ASK`. On timeout (15s) or error, the decision falls back to `ASK`, which prompts the user for manual approval.

## Project structure

```
src/claude_sentinel/
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
uv run claude-sentinel --test "your-command-here"
```

Requires Python 3.11+ (uses `tomllib` from the standard library). Zero external runtime dependencies.
