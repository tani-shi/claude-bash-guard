"""Command normalizer: strips prefix options between the program and its
subcommand so per-command rules can match through option clutter like
``git -c color.ui=never diff`` (which would otherwise fall through to
LLM_JUDGE).

Used by both ``rule_engine`` (for matching) and ``analyzer`` (for grouping
log records) so the two stay in sync.
"""

from __future__ import annotations

import shlex
from typing import NamedTuple

# Multi-token commands: the second token meaningfully changes intent
# (``git diff`` vs ``git status``). Shared with analyzer for consistent
# grouping keys.
_MULTI_TOKEN_COMMANDS: frozenset[str] = frozenset(
    {
        "git",
        "npm",
        "yarn",
        "pnpm",
        "bun",
        "uv",
        "pip",
        "pip3",
        "cargo",
        "docker",
        "make",
        "gh",
        "aws",
        "gcloud",
        "kubectl",
        "terraform",
        "pulumi",
        "helm",
        "brew",
        "apt",
        "apt-get",
        "conda",
        "go",
        "launchctl",
        "systemctl",
        "plutil",
        "defaults",
        "crontab",
    }
)


class _OptionSpec(NamedTuple):
    flag: str
    takes_value: bool


# Per-program known prefix options that may appear between the program
# and its subcommand. Whitelist-only — unknown options halt stripping
# (``normalize_for_matching`` returns the original string in that case).
_KNOWN_PREFIX_OPTIONS: dict[str, list[_OptionSpec]] = {
    "git": [
        _OptionSpec("-C", True),
        _OptionSpec("-c", True),
        _OptionSpec("--git-dir", True),
        _OptionSpec("--work-tree", True),
        _OptionSpec("--namespace", True),
        _OptionSpec("--super-prefix", True),
        _OptionSpec("--exec-path", True),
        _OptionSpec("--no-pager", False),
        _OptionSpec("--no-replace-objects", False),
        _OptionSpec("--bare", False),
        _OptionSpec("--no-optional-locks", False),
        _OptionSpec("--literal-pathspecs", False),
        _OptionSpec("-p", False),
        _OptionSpec("-P", False),
    ],
    "npm": [
        _OptionSpec("--silent", False),
        _OptionSpec("-s", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-q", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--no-fund", False),
        _OptionSpec("--no-audit", False),
        _OptionSpec("--no-progress", False),
        _OptionSpec("--prefix", True),
        _OptionSpec("--loglevel", True),
        _OptionSpec("--workspace", True),
        _OptionSpec("-w", True),
    ],
    "yarn": [
        _OptionSpec("--silent", False),
        _OptionSpec("-s", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--cwd", True),
    ],
    "pnpm": [
        _OptionSpec("--silent", False),
        _OptionSpec("-s", False),
        _OptionSpec("--filter", True),
        _OptionSpec("-w", False),
        _OptionSpec("--workspace-root", False),
    ],
    "bun": [
        _OptionSpec("--silent", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--cwd", True),
    ],
    "docker": [
        _OptionSpec("-q", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("--debug", False),
        _OptionSpec("-D", False),
        _OptionSpec("--config", True),
        _OptionSpec("-c", True),
        _OptionSpec("--context", True),
        _OptionSpec("-H", True),
        _OptionSpec("--host", True),
        _OptionSpec("-l", True),
        _OptionSpec("--log-level", True),
        _OptionSpec("--tlscacert", True),
        _OptionSpec("--tlscert", True),
        _OptionSpec("--tlskey", True),
    ],
    "gh": [
        _OptionSpec("-R", True),
        _OptionSpec("--repo", True),
        _OptionSpec("-H", True),
        _OptionSpec("--hostname", True),
    ],
    "make": [
        _OptionSpec("-C", True),
        _OptionSpec("--directory", True),
        _OptionSpec("-f", True),
        _OptionSpec("--file", True),
        _OptionSpec("--makefile", True),
        _OptionSpec("-j", True),
        _OptionSpec("--jobs", True),
        _OptionSpec("-l", True),
        _OptionSpec("--load-average", True),
        _OptionSpec("-I", True),
        _OptionSpec("--include-dir", True),
        _OptionSpec("-W", True),
        _OptionSpec("--what-if", True),
        _OptionSpec("-s", False),
        _OptionSpec("--silent", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-i", False),
        _OptionSpec("--ignore-errors", False),
        _OptionSpec("-k", False),
        _OptionSpec("--keep-going", False),
        _OptionSpec("-n", False),
        _OptionSpec("--dry-run", False),
        _OptionSpec("--just-print", False),
        _OptionSpec("-B", False),
        _OptionSpec("--always-make", False),
        _OptionSpec("-q", False),
        _OptionSpec("--question", False),
        _OptionSpec("-r", False),
        _OptionSpec("--no-builtin-rules", False),
        _OptionSpec("-R", False),
        _OptionSpec("--no-builtin-variables", False),
        _OptionSpec("-w", False),
        _OptionSpec("--print-directory", False),
        _OptionSpec("--no-print-directory", False),
    ],
    "kubectl": [
        _OptionSpec("-n", True),
        _OptionSpec("--namespace", True),
        _OptionSpec("--context", True),
        _OptionSpec("--cluster", True),
        _OptionSpec("--kubeconfig", True),
        _OptionSpec("-s", True),
        _OptionSpec("--server", True),
        _OptionSpec("--user", True),
        _OptionSpec("--token", True),
    ],
    "go": [
        _OptionSpec("-C", True),
    ],
    "uv": [
        _OptionSpec("-q", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-v", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--no-cache", False),
        _OptionSpec("--offline", False),
        _OptionSpec("--cache-dir", True),
        _OptionSpec("--directory", True),
        _OptionSpec("--project", True),
    ],
    "cargo": [
        _OptionSpec("-q", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-v", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--frozen", False),
        _OptionSpec("--locked", False),
        _OptionSpec("--offline", False),
        _OptionSpec("--manifest-path", True),
        _OptionSpec("--config", True),
        _OptionSpec("--target-dir", True),
    ],
    "aws": [
        _OptionSpec("--no-paginate", False),
        _OptionSpec("--no-sign-request", False),
        _OptionSpec("--region", True),
        _OptionSpec("--profile", True),
        _OptionSpec("--output", True),
        _OptionSpec("--endpoint-url", True),
        _OptionSpec("--ca-bundle", True),
    ],
    "gcloud": [
        _OptionSpec("--quiet", False),
        _OptionSpec("-q", False),
        _OptionSpec("--project", True),
        _OptionSpec("--account", True),
        _OptionSpec("--configuration", True),
        _OptionSpec("--billing-project", True),
        _OptionSpec("--verbosity", True),
    ],
}


def get_multi_token_commands() -> frozenset[str]:
    """Multi-token command names shared with analyzer for grouping."""
    return _MULTI_TOKEN_COMMANDS


def normalize_for_matching(command: str) -> str:
    """Strip per-command prefix options for rule matching.

    ``git -c color.ui=never diff`` becomes ``git diff`` so the existing
    ``git-status`` allow-rule pattern (which only knows about ``-C``) can
    still match.

    Returns the original string when stripping is unsafe or unnecessary:
    program not whitelisted, malformed bash, unknown option encountered,
    value-taking option without a value, or no prefix options actually
    present (idempotent).
    """
    s = command.lstrip()
    if not s:
        return command

    try:
        tokens = shlex.split(s, posix=True)
    except ValueError:
        return command

    if not tokens:
        return command

    head = tokens[0]
    specs = _KNOWN_PREFIX_OPTIONS.get(head)
    if not specs:
        return command

    flag_set = {spec.flag for spec in specs if not spec.takes_value}
    value_set = {spec.flag for spec in specs if spec.takes_value}

    out: list[str] = [head]
    i = 1
    stripped_any = False
    while i < len(tokens):
        tok = tokens[i]
        if not tok.startswith("-"):
            out.extend(tokens[i:])
            break
        if "=" in tok and tok.startswith("--"):
            opt_name = tok.split("=", 1)[0]
            if opt_name in flag_set or opt_name in value_set:
                i += 1
                stripped_any = True
                continue
            out.extend(tokens[i:])
            break
        if tok in flag_set:
            i += 1
            stripped_any = True
            continue
        if tok in value_set:
            if i + 1 >= len(tokens):
                return command
            i += 2
            stripped_any = True
            continue
        out.extend(tokens[i:])
        break

    if not stripped_any:
        return command
    if len(out) == 1:
        # Only options were present, no subcommand reached. Don't reduce
        # the command to its bare program name — that would lose context.
        return command
    return " ".join(out)


def normalize_for_analysis(command: str) -> str | None:
    """Return the analyzer grouping key for a Bash command.

    Strips prefix options first so ``git -c x=y diff`` and ``git diff``
    group together under ``"git diff"`` rather than fragmenting under
    ``"git"``.
    """
    normalized = normalize_for_matching(command).strip()
    if not normalized:
        return None
    try:
        tokens = shlex.split(normalized, posix=True)
    except ValueError:
        tokens = normalized.split()
    if not tokens:
        return None
    head = tokens[0]
    if head in _MULTI_TOKEN_COMMANDS and len(tokens) >= 2:
        second = tokens[1]
        if not second.startswith("-"):
            return f"{head} {second}"
    return head
