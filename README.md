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

Every Bash command and file path (Read/Write/Edit/MultiEdit) is evaluated through a multi-stage pipeline:

```
stdin JSON → RULE_DENY → RULE_ASK → RULE_ALLOW → LLM_JUDGE → stdout JSON
```

| Stage | Method | Speed | Description |
|-------|--------|-------|-------------|
| RULE_DENY | Regex deny list | Instant | Blocks known-dangerous commands (e.g. `sudo`, `rm -rf /`, `curl \| bash`) |
| RULE_ASK | Regex ask list | Instant | Prompts user confirmation for commands that need review (e.g. `ssh`, `systemctl`) |
| RULE_ALLOW | Regex allow list | Instant | Permits known-safe commands (e.g. `ls`, `git status`, `make`) |
| LLM_JUDGE | LLM judge | ~2-5s | Calls `claude -p` with haiku to evaluate ambiguous commands |

### Compound Bash commands

Bash commands are not matched as a single string. A small in-house splitter (no external dependency) walks the command, tracks quoting and escaping, and finds **every individual command** inside pipelines (`|`, `|&`), lists (`&&`, `||`, `;`, `&`, newline), command substitutions (`$(…)`, `` `…` ``), process substitutions (`<(…)`, `>(…)`), subshells (`(…)`), and parameter expansions (`${…}`). Each segment is evaluated independently against DENY → ASK → ALLOW, and the overall decision is the strictest result:

```
deny  >  ask  >  llm  >  allow
```

So `cd infra && terraform apply -auto-approve` is split into `cd infra` (allow) and `terraform apply -auto-approve` (ask), and the result is **ask** — the dangerous segment cannot be hidden behind a permissive prefix. If even one segment matches no rule, the command falls through to the LLM judge with the full original string for context.

The splitter only models what it needs to find command boundaries; constructs it does not handle (heredocs `<<EOF`, ANSI-C quoting `$'…'`, `case` statements, unbalanced quotes/parens) resolve to **ask** by design — a parser limitation can never silently *allow* a dangerous command, only force an extra confirmation prompt.

For file tools (`Read`, `Write`, `Edit`, `MultiEdit`), sensitive path deny rules are checked. If no deny rule matches, the operation is allowed. These rules are evaluated purely by the hook and are **not** written to `settings.json`. The installer adds these tools to `permissions.allow` so Claude Code does not prompt for confirmation, while the hook dynamically blocks access to sensitive paths.

Read-only tools with no side effects (`Grep`, `Glob`, `WebFetch`, `WebSearch`, Slack read/search tools) are auto-allowed without evaluation.

Tools with external impact (e.g. Slack send/schedule/canvas tools) require user confirmation (ASK).

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

## Sensitive path deny rules (RULE_DENY)

Sensitive files blocked from `Read`, `Write`, `Edit`, and `MultiEdit` tools:

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
- `Search` — search
- `WebFetch` — fetch web content
- `WebSearch` — web search
- `mcp__claude_ai_Slack__slack_read_*` — Slack read tools
- `mcp__claude_ai_Slack__slack_search_*` — Slack search tools

Additionally, file tools are added to `permissions.allow` and evaluated by the hook with sensitive path deny rules:

- `Read` — file reading
- `Write` — file writing
- `Edit` — file editing
- `MultiEdit` — multi-edit

## Allow rules (RULE_ALLOW)

Common development commands are auto-approved, including:

- File operations: `ls`, `cat`, `head`, `tail`, `find`, `grep`, `cp`, `mv`, `mkdir`, `touch`, `rm` (non-recursive only; `rm -r`/`rm -rf` require confirmation), `trash`
- Git: `status`, `log`, `diff`, `add`, `commit`, `revert`, `push` (with `--force-with-lease`), etc. (destructive ops like `reset --hard`, `checkout --`, `clean` require confirmation)
- Build tools: `make` (safe targets with hyphenated variants like `build-*`, `type-*`, `generate-*`; excludes `deploy`/`publish`/`release`/`push`/`tf-*`/`terraform-*`), `cargo` (safe subcommands only), `go build`, `node`, `bun` (excludes `bun x`), `python`, `uv` (excludes `publish`)
- Package managers: `npm`/`yarn`/`pnpm` (safe subcommands only, excludes `publish`; `run` allows `test`/`build`/`lint`/`cli`/etc., excludes `deploy`/`publish`/`release`/`push`)
- Containers: `docker` (safe subcommands only, excludes `push`; `docker compose exec`/`run` require confirmation)
- Network: `curl`/`wget` (excludes pipe-to-shell, POST/PUT/DELETE/PATCH methods, and `--data` flags)
- Cloud: `aws` read operations (`list`, `describe`, `get`, `show`, `wait`), `gcloud` read operations (including `logging read` and `logging tail`)
- Utilities: `echo`, `pwd`, `which`, `date`, `sort`, `sed` (excludes `sed -i`), `awk`, `tar`, `zip`, `env`, `printenv`

See [`src/claude_sentinel/rules/allow.toml`](src/claude_sentinel/rules/allow.toml) for the full list.

## Ask rules (RULE_ASK)

Commands that prompt user confirmation without LLM evaluation:

- `rm -r` / `rm -rf` / `rm --recursive` — recursive file deletion
- `git reset --hard` — discard uncommitted changes
- `git checkout -- <path>` — discard file changes
- `git clean` — delete untracked files
- `sed -i` / `sed --in-place` — in-place file editing
- `osascript` — AppleScript execution (GUI control, keystrokes)
- `docker compose exec` / `docker compose run` — arbitrary command execution in containers
- `bun x` — arbitrary package execution (same as `npx`)
- `xargs rm` / `xargs kill` / etc. — piped destructive commands
- `eval` / `source` / `.` — indirect command execution from variables or files
- `ssh` — remote connections
- `systemctl` — system service management
- `crontab -e` / `crontab -r` — crontab editing/removal
- `deploy` — any command containing "deploy"
- `make deploy` / `make tf-*` / `make terraform-*` — infrastructure targets
- `terraform apply` / `destroy` — infrastructure mutations
- `pulumi up` / `destroy` — infrastructure mutations
- `kubectl apply` / `delete` / `create` etc. — Kubernetes mutations
- `helm install` / `upgrade` / `uninstall` / `rollback` — Helm mutations
- `npm publish` / `cargo publish` / `uv publish` / `gem push` / `twine upload` — package publishing
- `docker push` — container registry push
- `gh pr create` / `merge` / `close`, `gh issue create`, `gh release create`, `gh repo create` etc. — GitHub mutations
- `gh api ... -X POST/PUT/DELETE/PATCH` — GitHub API mutations
- `git push --force` (non-main; `--force-with-lease` is allowed)
- `curl`/`wget` with `-X POST/PUT/DELETE/PATCH` or `--data` flags — HTTP mutations
- `gcloud ... create/delete/deploy/update` etc. — Google Cloud mutations
- `aws ...` — AWS CLI (catch-all; read ops are allowed by ALLOW rules)
- `npm run`/`yarn run`/`pnpm run` with `migrate`/`migration` — database migrations
- `make publish` / `release` / `push` — external-impact make targets
- Slack send/schedule/canvas tools (TOOL_ASK)

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

Requires Python 3.11+ (uses `tomllib` from the standard library). The only runtime dependency is `claude-agent-sdk` (used by the LLM judge stage); the rule engine and the bash splitter have zero external dependencies.

## Platform support

Works on macOS, Linux, and Windows.

- **Sensitive path rules** match both Unix (`/`) and Windows (`\`) path separators
- **Logs** are stored in `~/.local/share/claude-sentinel/logs/` on Unix, `%LOCALAPPDATA%\claude-sentinel\logs\` on Windows (override with `CLAUDE_SENTINEL_LOG_DIR`)
- **Settings** are read from `~/.claude/settings.json` on all platforms
