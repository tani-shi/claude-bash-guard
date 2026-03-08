"""3-tier evaluation engine for Bash commands and Read tool file paths."""

from __future__ import annotations

from typing import Any

from bash_guard import llm_judge, rule_engine as rules


def evaluate(hook_input: dict[str, Any]) -> tuple[str, str, str] | None:
    """Evaluate a hook input through the 3-tier system.

    Returns:
        (decision, reason, tier) or None for passthrough (unknown tools)
    """
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name == "Bash":
        return _evaluate_bash(tool_input, hook_input)
    elif tool_name == "Read":
        return _evaluate_read(tool_input)
    else:
        # Unknown tool: passthrough
        return None


def _evaluate_bash(
    tool_input: dict[str, Any], hook_input: dict[str, Any]
) -> tuple[str, str, str]:
    """Evaluate a Bash command through TIER1 deny -> TIER2 allow -> TIER3 LLM."""
    command = tool_input.get("command", "")

    # TIER 1: Deny rules
    deny_match = rules.match_deny(command)
    if deny_match:
        return "deny", f"Blocked by deny rule: {deny_match.name}", "TIER1"

    # TIER 2: Allow rules
    allow_match = rules.match_allow(command)
    if allow_match:
        return "allow", f"Allowed by rule: {allow_match.name}", "TIER2"

    # TIER 3: LLM judge
    cwd = hook_input.get("cwd", ".")
    decision, reason = llm_judge.evaluate(command, cwd)
    return decision, reason, "TIER3"


def _evaluate_read(tool_input: dict[str, Any]) -> tuple[str, str, str]:
    """Evaluate a Read tool file path through TIER1 read_deny rules."""
    file_path = tool_input.get("file_path", "")

    # TIER 1: Read deny rules
    deny_match = rules.match_read_deny(file_path)
    if deny_match:
        return "deny", f"Blocked by read rule: {deny_match.name}", "TIER1"

    # No match: allow
    return "allow", "No read deny rule matched", "TIER2"
