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

### Prefix-option normalization

Rules are matched twice for each segment: once against the original command, then against a **prefix-option-stripped** form. This lets a single rule like `^\s*git\s+(diff|status|...)` match all of `git diff`, `git -c color.ui=never diff`, `git --no-pager diff`, and `git -C /tmp/repo diff` without enumerating every wrapper. Stripping is whitelist-only — for each known program (git, npm, yarn, pnpm, bun, uv, cargo, go, make, docker, gh, kubectl, aws, gcloud) only documented prefix options like `-c`, `-C`, `--no-pager`, `--silent`, `-q`, `-R`, `-j`, `--config`, `--region` are removed. An unknown option halts stripping (safe fallback), and options after the subcommand (`git push --force`, `npm run test --silent`) are never touched. The same normalization is applied to ALLOW, ASK, and DENY matching, so prefix options cannot be used to slip past confirmation rules either.

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

- Shell: Bash comments (`#`), shell constructs (`for`, `while`, `if`, `case`, `do`/`done`, `then`/`else`/`fi`, `esac`), `pushd`/`popd`, `zsh`/`bash`/`sh` invocations
- File operations: `ls`, `cat`, `head`, `tail`, `find`, `grep`, `cp`, `mv`, `mkdir`, `touch`, `rm` (non-recursive only; `rm -r`/`rm -rf` require confirmation), `trash`
- Git: `status`, `log`, `diff`, `add`, `commit`, `revert`, `push` (with `--force-with-lease`), etc. (destructive ops like `reset --hard`, `checkout --`, `clean` require confirmation)
- Build tools: `make` (safe targets with hyphenated variants like `build-*`, `type-*`, `generate-*`, `start-*`, `stop-*`, `status-*`, `cli-*`, `web-*`, `zip-*`; excludes `deploy`/`publish`/`release`/`push`/`upgrade`/`tf-*`/`terraform-*`), `cargo` (safe subcommands only), `go build`, `node`, `bun` (excludes `bun x`), `python`, `uv` (excludes `publish`)
- Package managers: `npm`/`yarn`/`pnpm` (safe subcommands only, excludes `publish`; `run` allows `test`/`build`/`lint`/`cli`/etc., excludes `deploy`/`publish`/`release`/`push`); `npx`/`pnpx`/`bunx` for safe dev tools (`prettier`, `tsc`, `eslint`, `biome`, `prisma`, `vitest`, `jest`, `playwright`, `shadcn`, `next`, `vite`, etc.; unknown packages require confirmation)
- Containers: `docker` (safe subcommands only, excludes `push`; `docker compose exec`/`run` require confirmation)
- Database: `sqlite3`
- Network: `curl`/`wget` (excludes pipe-to-shell, POST/PUT/DELETE/PATCH methods, and `--data` flags)
- Cloud: `aws` read operations (`list`, `describe`, `get`, `show`, `wait`), `gcloud` read operations (including `logging read` and `logging tail`)
- macOS: `launchctl` read operations (`list`, `print`, `blame`), `plutil` read (`-p`, `-lint`), `sample` (process profiling), `defaults read`
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
- `npx` / `pnpx` / `bunx` — arbitrary package execution (safe dev tools like `prettier`, `tsc`, `eslint` are auto-allowed)
- `bun x` — arbitrary package execution
- `xargs rm` / `xargs kill` / etc. — piped destructive commands
- `eval` / `source` / `.` — indirect command execution from variables or files
- `pkill` / `killall` / `kill` — process termination
- `ssh` — remote connections
- `systemctl` — system service management
- `launchctl load` / `unload` / `bootstrap` etc. — macOS service mutations
- `crontab -e` / `crontab -r` — crontab editing/removal
- `deploy` — any command containing "deploy"
- `make deploy` / `make tf-*` / `make terraform-*` — infrastructure targets
- `make publish` / `release` / `push` — external-impact make targets (with hyphenated variants)
- `make upgrade` — upgrade targets (with hyphenated variants)
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

### Analyze logs

Aggregate logged command patterns that fell through to `LLM_JUDGE` (i.e. matched no existing rule) — these are the actionable improvement targets. By default all decisions (`allow` / `ask` / `deny`) the LLM made are surfaced, so `allow`-judged patterns can become ALLOW rules and `ask`-judged ones become ASK rules. No LLM call.

```bash
claude-sentinel analyze                        # default: stage=LLM_JUDGE, decision=all, last 30d, top 20
claude-sentinel analyze --since 7d -n 50       # narrower window, top 50
claude-sentinel analyze --decision ask         # only patterns the LLM judged "ask"
claude-sentinel analyze --stage RULE_ASK       # patterns hitting an existing ASK rule
claude-sentinel analyze --include-covered      # also show patterns existing rules already match
claude-sentinel analyze --json                 # JSON Lines for scripting (includes per-pattern decisions tally)
```

### Suggest rules

Ask an LLM (Sonnet 4.6) to propose ALLOW/ASK `[[rules]]` candidates for the uncovered patterns. The prompt now passes the per-pattern decision tally (allow/ask/deny) so the LLM can choose the right section: patterns it consistently allowed become ALLOW rules, ask/destructive ones become ASK rules, deny-judged ones are flagged in Notes for human review. Output is TOML fragments on stdout (progress on stderr).

```bash
claude-sentinel suggest                        # top 20 uncovered patterns → TOML suggestions
claude-sentinel suggest --since 7d -n 10       # narrower window
claude-sentinel suggest --include-covered      # re-suggest even for patterns already covered
claude-sentinel suggest --quiet                # suppress stderr progress lines
```

### Apply suggestions

Append validated rules from `suggest` output to `allow.toml` / `ask.toml`. Reads stdin (or `--input FILE`), validates each entry (regex compiles, name is not a duplicate), and appends a timestamped block. `deny.toml` is never written to automatically — proposed DENY entries are reported and skipped.

```bash
claude-sentinel suggest | claude-sentinel apply             # pipeline
claude-sentinel apply --input suggestions.txt               # file input
claude-sentinel apply --dry-run < suggestions.txt           # validate only
```

After applying, review the diff before committing:

```bash
git diff src/claude_sentinel/rules/
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
├── cli.py                # Entry point, argparse
├── evaluator.py          # Multi-stage evaluation engine
├── hook_io.py            # stdin/stdout JSON handling
├── rule_engine.py        # TOML rule loading and regex matching
├── command_normalizer.py # Strip prefix options before matching/grouping
├── llm_judge.py          # LLM_JUDGE: claude subprocess
├── analyzer.py           # Aggregate log records into ranked patterns
├── suggester.py          # LLM-driven rule candidate generation
├── applier.py            # Append validated rules to allow/ask.toml
├── logger.py             # Evaluation log writer/reader
├── installer.py          # Hook install/uninstall
└── rules/
    ├── deny.toml           # RULE_DENY patterns
    ├── allow.toml          # RULE_ALLOW patterns
    ├── ask.toml            # RULE_ASK patterns
    ├── llm_prompt.txt      # LLM_JUDGE prompt template
    └── suggest_prompt.txt  # Rule-suggestion prompt template
```

## Development

```bash
# Install dev dependencies (ruff, pyright, pytest)
make install

# Run all checks (lint, format, typecheck, test)
make check

# Individual targets
make lint          # Run linter (ruff check)
make lint-fix      # Run linter with auto-fix
make fmt           # Format code (ruff format)
make fmt-check     # Check code formatting
make typecheck     # Run type checker (pyright)
make test          # Run tests (pytest)
make clean         # Remove build artifacts and caches

# Rule maintenance
make analyze-logs  # Rank uncovered command patterns from recent logs
make suggest-rules # Ask Sonnet 4.6 for TOML rule candidates (stdout only)
make update-rules  # Analyze + suggest + apply; prints git diff for review

# Test a command locally
uv run claude-sentinel --test "your-command-here"
```

### Rule maintenance workflow

When `LLM_JUDGE` fallthroughs pile up in the evaluation log, use the built-in analyzer + LLM suggester to refresh `allow.toml` / `ask.toml`:

1. `make update-rules` — aggregates the log, asks Sonnet 4.6 for rule candidates, appends ALLOW/ASK entries to the TOML files, and prints the `git diff --stat`.
2. **Human review**: `git diff src/claude_sentinel/rules/` — inspect every new `[[rules]]` block. Revert any you disagree with (`git checkout -- <file>`).
3. `make check` — ensure the new regexes don't regress existing tests.
4. Optionally add targeted assertions in `tests/test_rules.py` for important new patterns (mirrors the workflow that produced commit `11aea10`).
5. Commit the approved changes.

Separate steps are available if you want more control:

- `make analyze-logs` — ranked pattern report only (no LLM call, no writes).
- `make suggest-rules` — suggestions on stdout, no writes.
- `claude-sentinel apply --dry-run` — validate a saved suggestion file without touching TOML.

DENY rule additions are never applied automatically. If the LLM proposes a DENY entry it is surfaced in the `[apply]` output and must be added by hand.

Requires Python 3.11+ (uses `tomllib` from the standard library). The only runtime dependency is `claude-agent-sdk` (used by the LLM judge stage); the rule engine and the bash splitter have zero external dependencies.

## Platform support

Works on macOS, Linux, and Windows.

- **Sensitive path rules** match both Unix (`/`) and Windows (`\`) path separators
- **Logs** are stored in `~/.local/share/claude-sentinel/logs/` on Unix, `%LOCALAPPDATA%\claude-sentinel\logs\` on Windows (override with `CLAUDE_SENTINEL_LOG_DIR`)
- **Settings** are read from `~/.claude/settings.json` on all platforms
