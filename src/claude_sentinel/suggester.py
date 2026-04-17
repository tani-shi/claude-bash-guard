"""LLM-based rule suggestion from aggregated log patterns."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from importlib import resources

from claude_sentinel.analyzer import PatternSummary

_MODEL = "claude-sonnet-4-6"
_SDK_TIMEOUT = 60.0
_MAX_RETRIES = 2


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


async def _query_sdk(prompt: str) -> str:
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    options = ClaudeAgentOptions(
        model=_MODEL,
        max_turns=1,
        permission_mode="bypassPermissions",
        allowed_tools=[],
        env={"CLAUDECODE": "", "CLAUDE_CODE_ENTRYPOINT": ""},
    )
    result_text = ""
    async with asyncio.timeout(_SDK_TIMEOUT):
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage):
                result_text = message.result or ""
    return result_text.strip()


def suggest(patterns: list[PatternSummary], *, skip_covered: bool = True) -> str:
    """Ask the LLM for ALLOW/ASK rule candidates covering the given patterns.

    Args:
        patterns: Aggregated log patterns from ``analyzer.summarize``.
        skip_covered: Exclude patterns already matched by an existing rule.

    Returns:
        The raw LLM output (TOML fragments + notes), or a status message
        when there is nothing to suggest or the call fails.
    """
    candidates = [p for p in patterns if not (skip_covered and p.covered_by)]
    if not candidates:
        return "# No uncovered patterns to suggest rules for."

    prompt = build_prompt(candidates)
    last_error = ""
    for _attempt in range(_MAX_RETRIES):
        try:
            return asyncio.run(_query_sdk(prompt))
        except TimeoutError:
            last_error = "LLM suggest call timed out"
        except Exception as e:  # noqa: BLE001 — surface any SDK error to the user
            return f"# LLM suggest error: {e}"
    return f"# {last_error}"
