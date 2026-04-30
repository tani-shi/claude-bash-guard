---
description: Interactively propose ALLOW/ASK rule additions for claude-sentinel from recent LLM_JUDGE log entries
allowed-tools: Bash(claude-sentinel log:*), Bash(claude-sentinel rules:*), Bash(claude-sentinel apply:*), Bash(git diff:*), Read
---

You are helping the user maintain `allow.toml` and `ask.toml` for
claude-sentinel — the Claude Code safety hook that evaluates shell
commands. Find commands frequently falling through to LLM_JUDGE,
propose rules that would catch them, and refine the proposals
**interactively** with the user before applying.

## Workflow

1. Fetch recent LLM_JUDGE log records:
   ```
   claude-sentinel log --json --stage LLM_JUDGE --since 30d -n 200
   ```
   Each record has: ts, session_id, tool_name, input, cwd, decision,
   stage, reason, elapsed_ms. The `decision` field is what the slow
   LLM judge actually picked (allow / ask / deny) — use it as a strong
   signal for classification.

2. Fetch the existing rule sets:
   ```
   claude-sentinel rules --kind allow --json
   claude-sentinel rules --kind ask --json
   claude-sentinel rules --kind deny --json
   ```

3. Group log records by *intent*, not by surface form. Examples of
   commands that should collapse to the same intent:
   - `make test 2>&1 | tail -5` and `make test`
   - `cd src && terraform apply` and `terraform apply` — focus on the
     destructive segment, not the cd
   - `cat foo | grep bar` and `grep bar foo`
   Examples of related commands worth one shared rule (a family):
   - `make test`, `make test:integration`, `make test.fast` — a single
     `make test*` family rule may cover them all.

4. For each group, check whether the existing allow/ask/deny rules
   already match a representative sample. If they do, mark covered
   and skip — do NOT propose duplicate rules.

5. For groups not covered, classify them:
   - LLM consistently picked `allow` and the intent is read-only or a
     pure local dev-tool invocation → ALLOW rule.
   - LLM picked `ask`, or the intent is destructive / mutates shared
     state / reaches outside the local machine → ASK rule.
   - LLM picked `deny`, or the command is unambiguously dangerous →
     DO NOT propose. Surface in the Notes section only and tell the
     user to add it manually to `deny.toml`.

6. Present your proposed candidates to the user as a compact table
   or numbered list. For each row include: section (allow/ask),
   proposed `name`, proposed regex, a representative sample command,
   the decision tally (e.g. `allow=12, ask=3`), and a one-line
   rationale. Also list any covered/deny-flagged groups so the user
   sees the full picture.

7. **Iterate with the user.** They will say things like:
   - "drop #3" — remove that proposal
   - "narrow #5 — only `make test:*`, not `make test.*`" — refine the regex
   - "split #7 into two rules" — propose two `[[rules]]` entries
   - "this should be ASK not ALLOW" — change classification
   - "proceed" / "apply" — write the final TOML and apply
   Keep iterating until the user is satisfied. Do not apply until they
   say so explicitly.

8. When the user approves, build the final TOML and pipe it through
   `claude-sentinel apply` using a HEREDOC. The strict format is:
   ```
   cat <<'EOF' | claude-sentinel apply
   # --- allow.toml additions ---
   [[rules]]
   name = "example-allow"
   command_regex = '''^example( |$)'''

   # --- ask.toml additions ---
   [[rules]]
   name = "example-ask"
   command_regex = '''^other-example( |$)'''

   ## Notes
   - example-allow: safe read-only operation (LLM picked allow 12 times)
   - example-ask: external impact (LLM picked ask 3 times)
   - skipped `git status` family: already covered by allow:git-status
   EOF
   ```
   Always emit BOTH section headers (`allow.toml additions` first,
   then `ask.toml additions`), even if one is empty. Never emit a
   `# --- deny.toml additions ---` section.

9. After apply succeeds, run `git diff --stat src/claude_sentinel/rules/`
   and ask the user whether to keep, revert (`git checkout -- <file>`),
   or further refine.

## Regex rules

Each `[[rules]]` regex must:
- Be anchored with `^` (Python `re.search` matches anywhere otherwise).
- Use `( |$)` (with a leading space) after the head/subcommand to
  avoid prefix overlap (e.g. `git` matching `github`).
- Be conservative — better one extra ask prompt than silently allowing
  a risky command. When unsure, suggest ASK.
- Avoid prefix-option clutter (`-c key=val`, `--no-pager`, `--silent`,
  `-q`, `-R`, `-j N` etc.). The matching engine strips known prefix
  options before testing patterns, so write rules against the
  prefix-free form (`^git diff( |$)`, not `^git -c \S+ diff`).

## Constraints

- Use ONLY the Bash commands listed in `allowed-tools` (claude-sentinel
  log/rules/apply and git diff). Do not edit any rule file directly —
  go through `claude-sentinel apply`.
- Do not propose new entries for `deny.toml`. DENY changes always
  require manual human review.
- If the user asks for something outside this workflow (refactoring,
  new tooling, etc.), say so and stop.
