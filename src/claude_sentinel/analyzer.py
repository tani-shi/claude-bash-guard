"""Aggregate evaluation logs into command patterns for rule suggestions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from claude_sentinel import logger, rule_engine
from claude_sentinel.command_normalizer import normalize_for_analysis


@dataclass
class PatternSummary:
    """One aggregated command pattern with frequency and samples."""

    key: str
    tool_name: str
    count: int = 0
    stages: dict[str, int] = field(default_factory=dict)
    decisions: dict[str, int] = field(default_factory=dict)
    samples: list[str] = field(default_factory=list)
    covered_by: str | None = None  # rule name that already matches this pattern

    def add(self, sample: str, stage: str, decision: str) -> None:
        self.count += 1
        self.stages[stage] = self.stages.get(stage, 0) + 1
        self.decisions[decision] = self.decisions.get(decision, 0) + 1
        if sample and sample not in self.samples and len(self.samples) < 3:
            self.samples.append(sample)


def _normalize_bash(command: str) -> str | None:
    """Return a grouping key for a Bash command, or None if empty/unparseable.

    Delegates to ``command_normalizer.normalize_for_analysis`` so prefix
    options are stripped before grouping (``git -c x=y diff`` and
    ``git diff`` collapse to the same ``"git diff"`` key).
    """
    return normalize_for_analysis(command)


def _normalize_path(tool_name: str, file_path: str) -> str | None:
    """Return a grouping key like 'Read:.py' for file tools."""
    if not file_path:
        return None
    # Handle both posix and windows style paths without touching the filesystem.
    path: PurePosixPath | PureWindowsPath
    path = PureWindowsPath(file_path) if "\\" in file_path else PurePosixPath(file_path)
    suffix = path.suffix or path.name  # dotfiles like ".env" have no suffix
    return f"{tool_name}:{suffix}" if suffix else tool_name


def _normalize(tool_name: str, input_value: str) -> str | None:
    if tool_name == "Bash":
        return _normalize_bash(input_value)
    if tool_name in {"Read", "Write", "Edit", "MultiEdit"}:
        return _normalize_path(tool_name, input_value)
    return tool_name or None


def _check_existing_rule(tool_name: str, sample: str) -> str | None:
    """Return the name of an existing rule that matches, if any."""
    if tool_name == "Bash":
        if (rule := rule_engine.match_deny(sample)) is not None:
            return f"deny:{rule.name}"
        if (rule := rule_engine.match_ask(sample)) is not None:
            return f"ask:{rule.name}"
        if (rule := rule_engine.match_allow(sample)) is not None:
            return f"allow:{rule.name}"
        return None
    if tool_name in {"Read", "Write", "Edit", "MultiEdit"}:
        if (rule := rule_engine.match_sensitive_path(sample)) is not None:
            return f"deny:{rule.name}"
        return None
    return None


def summarize(
    *,
    since: float | None = None,
    decision: str | None = None,
    stage: str | None = "LLM_JUDGE",
    limit: int = 20,
    records: Iterable[dict[str, Any]] | None = None,
) -> list[PatternSummary]:
    """Aggregate log records into command patterns, ranked by frequency.

    Args:
        since: Unix timestamp; only consider records newer than this.
        decision: Filter by decision. ``None`` (default) includes all
            decisions — useful for surfacing ALLOW candidates the LLM
            judged safe but no rule covered.
        stage: Filter by stage. Defaults to ``"LLM_JUDGE"`` so the
            analyzer focuses on patterns that fell through the rule
            engine (the actionable improvement target).
        limit: Maximum number of patterns to return.
        records: Optional pre-fetched iterator (primarily for testing).

    Returns:
        Pattern summaries sorted by count descending, truncated to ``limit``.
    """
    if records is None:
        records = logger.iter_logs(
            since=since, decision=decision, stage=stage, limit=0, newest_first=False
        )

    groups: dict[str, PatternSummary] = {}
    for rec in records:
        tool_name = rec.get("tool_name", "")
        input_value = rec.get("input", "")
        rec_stage = rec.get("stage", "")
        rec_decision = rec.get("decision", "")
        key = _normalize(tool_name, input_value)
        if not key:
            continue
        summary = groups.get(key)
        if summary is None:
            summary = PatternSummary(key=key, tool_name=tool_name)
            groups[key] = summary
        summary.add(input_value, rec_stage, rec_decision)

    # Check existing rule coverage on a representative sample for each group.
    for summary in groups.values():
        if summary.samples:
            summary.covered_by = _check_existing_rule(summary.tool_name, summary.samples[0])

    ranked = sorted(groups.values(), key=lambda s: s.count, reverse=True)
    return ranked[:limit] if limit else ranked
