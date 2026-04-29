"""LLM agent driven rule suggestion.

The agent is given Bash tool access and instructed to invoke
``claude-sentinel log`` / ``claude-sentinel rules`` itself to inspect
the evaluation log and existing ruleset, group commands semantically,
and emit TOML rule candidates that the applier can append to
allow.toml / ask.toml. There is no client-side aggregation step —
grouping is a model judgement, not a regex match.
"""

from __future__ import annotations

import asyncio
import sys
import time
from importlib import resources

_MODEL = "claude-sonnet-4-6"
# Agent-driven suggest invokes the LLM with Bash tool access and lets
# it loop through several `claude-sentinel log/rules` calls before
# emitting TOML output. Needs more headroom than the old single-shot
# prompt.
_SDK_TIMEOUT = 300.0
_MAX_TURNS = 15
_MAX_RETRIES = 2


def _progress(msg: str) -> None:
    """Emit a progress line to stderr, without polluting the TOML stdout."""
    print(f"[suggest] {msg}", file=sys.stderr, flush=True)


def _describe_message(message: object) -> str:
    """One-line label describing an SDK streaming message."""
    name = type(message).__name__
    content = getattr(message, "content", None)
    if isinstance(content, list) and content:
        kinds: list[str] = [type(block).__name__ for block in content]
        return f"{name} ({len(content)} block(s): {', '.join(kinds)})"
    result = getattr(message, "result", None)
    if isinstance(result, str):
        return f"{name} ({len(result)} chars)"
    return name


def _load_prompt_template() -> str:
    rules_pkg = resources.files("claude_sentinel.rules")
    return (rules_pkg / "suggest_prompt.txt").read_text(encoding="utf-8")


def build_prompt(*, since: str, limit: int) -> str:
    """Render the agent prompt with the given log window.

    The template uses ``{since}`` and ``{limit}`` placeholders for the
    Bash command examples it shows the agent.
    """
    return _load_prompt_template().format(since=since, limit=limit)


async def _query_agent(prompt: str, *, verbose: bool) -> str:
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    options = ClaudeAgentOptions(
        model=_MODEL,
        max_turns=_MAX_TURNS,
        permission_mode="bypassPermissions",
        allowed_tools=["Bash"],
        env={"CLAUDECODE": "", "CLAUDE_CODE_ENTRYPOINT": ""},
    )
    result_text = ""
    t0 = time.monotonic()
    async with asyncio.timeout(_SDK_TIMEOUT):
        async for message in query(prompt=prompt, options=options):
            if verbose:
                dt = time.monotonic() - t0
                _progress(f"{dt:5.1f}s  {_describe_message(message)}")
            if isinstance(message, ResultMessage):
                result_text = message.result or ""
    return result_text.strip()


def suggest(
    *,
    since: str = "30d",
    limit: int = 200,
    verbose: bool = False,
) -> str:
    """Run the suggestion agent.

    Sonnet inspects the LLM_JUDGE log via Bash and returns TOML rule
    candidates suitable for piping into ``claude-sentinel apply``.

    Args:
        since: Relative time window the agent will pass to
            ``claude-sentinel log``.
        limit: Max log records exposed to the agent per fetch.
        verbose: Stream agent progress (Bash invocations and result
            chunks) to stderr while it runs.

    Returns:
        The raw agent output (TOML fragments + notes), or a status
        message when the call times out or fails.
    """
    if verbose:
        _progress(
            f"agent {_MODEL} since={since} limit={limit} "
            f"(timeout {int(_SDK_TIMEOUT)}s, max_turns={_MAX_TURNS})"
        )

    prompt = build_prompt(since=since, limit=limit)
    last_error = ""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            if verbose and attempt > 1:
                _progress(f"retry {attempt}/{_MAX_RETRIES}")
            result = asyncio.run(_query_agent(prompt, verbose=verbose))
            if verbose:
                _progress("done")
            return result
        except TimeoutError:
            last_error = f"LLM suggest call timed out after {int(_SDK_TIMEOUT)}s"
            if verbose:
                _progress(last_error)
        except Exception as e:  # noqa: BLE001 — surface any SDK error to the user
            if verbose:
                _progress(f"error: {e}")
            return f"# LLM suggest error: {e}"
    return f"# {last_error}"
