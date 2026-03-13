"""Multi-stage evaluation engine for Bash commands and Read tool file paths."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from claude_sentinel import llm_judge, rule_engine as rules

# Read-only tools with no side effects: auto-allow without evaluation.
# Supports fnmatch glob patterns (e.g. "mcp__*__slack_read_*").
AUTO_ALLOW_TOOLS = {
    "Grep",
    "Glob",
    "Search",
    "WebFetch",
    "WebSearch",
    "mcp__claude_ai_Slack__slack_read_*",
    "mcp__claude_ai_Slack__slack_search_*",
}

# Tools that have external impact and require user confirmation.
ASK_TOOLS = {
    "mcp__claude_ai_Slack__slack_send_message",
    "mcp__claude_ai_Slack__slack_send_message_draft",
    "mcp__claude_ai_Slack__slack_schedule_message",
    "mcp__claude_ai_Slack__slack_create_canvas",
    "mcp__claude_ai_Slack__slack_update_canvas",
}


def _is_auto_allowed(tool_name: str) -> bool:
    """Check if a tool matches any AUTO_ALLOW_TOOLS entry (exact or glob)."""
    return any(fnmatch(tool_name, pattern) for pattern in AUTO_ALLOW_TOOLS)


def evaluate(hook_input: dict[str, Any]) -> tuple[str, str, str] | None:
    """Evaluate a hook input through the multi-stage system.

    Returns:
        (decision, reason, stage) or None for passthrough (unknown tools)
    """
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name == "Bash":
        return _evaluate_bash(tool_input, hook_input)
    elif tool_name == "Read":
        return _evaluate_read(tool_input)
    elif _is_auto_allowed(tool_name):
        return "allow", f"Auto-allowed tool: {tool_name}", "AUTO_ALLOW"
    elif tool_name in ASK_TOOLS:
        return "ask", f"External impact tool requires confirmation: {tool_name}", "TOOL_ASK"
    else:
        # Unknown tool: passthrough
        return None


def _evaluate_bash(
    tool_input: dict[str, Any], hook_input: dict[str, Any]
) -> tuple[str, str, str]:
    """Evaluate a Bash command: RULE_DENY -> RULE_ALLOW -> LLM_JUDGE."""
    command = tool_input.get("command", "")

    # Deny rules
    deny_match = rules.match_deny(command)
    if deny_match:
        return "deny", f"Blocked by deny rule: {deny_match.name}", "RULE_DENY"

    # Allow rules
    allow_match = rules.match_allow(command)
    if allow_match:
        return "allow", f"Allowed by rule: {allow_match.name}", "RULE_ALLOW"

    # Ask rules
    ask_match = rules.match_ask(command)
    if ask_match:
        return "ask", f"Matched ask rule: {ask_match.name}", "RULE_ASK"

    # LLM judge
    cwd = hook_input.get("cwd", ".")
    decision, reason = llm_judge.evaluate(command, cwd)
    return decision, reason, "LLM_JUDGE"


def _evaluate_read(tool_input: dict[str, Any]) -> tuple[str, str, str]:
    """Evaluate a Read tool file path through read_deny rules."""
    file_path = tool_input.get("file_path", "")

    # Read deny rules
    deny_match = rules.match_read_deny(file_path)
    if deny_match:
        return "deny", f"Blocked by read rule: {deny_match.name}", "RULE_DENY"

    # No match: allow
    return "allow", "No read deny rule matched", "RULE_ALLOW"
