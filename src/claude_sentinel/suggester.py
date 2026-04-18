"""LLM-based rule suggestion from aggregated log patterns."""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Iterable
from importlib import resources

from claude_sentinel.analyzer import PatternSummary

_MODEL = "claude-sonnet-4-6"
# Sonnet with a reasoning-heavy prompt (existing rule taxonomy + pattern
# table) regularly runs longer than Haiku — give it a generous window.
_SDK_TIMEOUT = 180.0
_MAX_RETRIES = 2


def _progress(msg: str) -> None:
    """Emit a progress line to stderr, without polluting the TOML stdout."""
    print(f"[suggest] {msg}", file=sys.stderr, flush=True)


def _describe_message(message: object) -> str:
    """One-line label describing an SDK streaming message."""
    name = type(message).__name__
    # AssistantMessage has .content which is a list of blocks; show its size.
    content = getattr(message, "content", None)
    if isinstance(content, list) and content:
        kinds: list[str] = []
        for block in content:
            kinds.append(type(block).__name__)
        return f"{name} ({len(content)} block(s): {', '.join(kinds)})"
    # ResultMessage carries the final .result string; show its length.
    result = getattr(message, "result", None)
    if isinstance(result, str):
        return f"{name} ({len(result)} chars)"
    return name


def _load_prompt_template() -> str:
    rules_pkg = resources.files("claude_sentinel.rules")
    return (rules_pkg / "suggest_prompt.txt").read_text(encoding="utf-8")


def _format_ranking(patterns: Iterable[PatternSummary]) -> str:
    """Render pattern summaries as a human-readable table for the prompt."""
    lines: list[str] = []
    for rank, p in enumerate(patterns, start=1):
        stages = ",".join(f"{k}={v}" for k, v in sorted(p.stages.items()))
        lines.append(f"{rank}. [{p.tool_name}] key={p.key!r}  count={p.count}  stages={stages}")
        for sample in p.samples:
            lines.append(f"     sample: {sample}")
    return "\n".join(lines) if lines else "(no uncovered patterns)"


def build_prompt(patterns: Iterable[PatternSummary]) -> str:
    """Public for testing: render the full prompt without calling the LLM."""
    return _load_prompt_template().format(ranking_table=_format_ranking(patterns))


async def _query_sdk(prompt: str, *, verbose: bool) -> str:
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    options = ClaudeAgentOptions(
        model=_MODEL,
        max_turns=1,
        permission_mode="bypassPermissions",
        allowed_tools=[],
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
    patterns: list[PatternSummary],
    *,
    skip_covered: bool = True,
    verbose: bool = False,
) -> str:
    """Ask the LLM for ALLOW/ASK rule candidates covering the given patterns.

    Args:
        patterns: Aggregated log patterns from ``analyzer.summarize``.
        skip_covered: Exclude patterns already matched by an existing rule.
        verbose: Emit streaming progress to stderr while the LLM runs.

    Returns:
        The raw LLM output (TOML fragments + notes), or a status message
        when there is nothing to suggest or the call fails.
    """
    candidates = [p for p in patterns if not (skip_covered and p.covered_by)]
    if not candidates:
        return "# No uncovered patterns to suggest rules for."

    if verbose:
        _progress(
            f"sending {len(candidates)} pattern(s) to {_MODEL} (timeout {int(_SDK_TIMEOUT)}s)"
        )

    prompt = build_prompt(candidates)
    last_error = ""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            if verbose and attempt > 1:
                _progress(f"retry {attempt}/{_MAX_RETRIES}")
            result = asyncio.run(_query_sdk(prompt, verbose=verbose))
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
