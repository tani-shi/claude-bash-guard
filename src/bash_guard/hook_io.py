"""Hook protocol I/O for Claude Code PreToolUse and PermissionRequest hooks."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO


def read_input(stdin: TextIO | None = None) -> dict[str, Any]:
    """Read and parse JSON from stdin."""
    if stdin is None:
        stdin = sys.stdin
    raw = stdin.read()
    return json.loads(raw)


def write_output(
    decision: str,
    reason: str,
    hook_event_name: str,
    stdout: TextIO | None = None,
) -> None:
    """Write the appropriate JSON response to stdout.

    For PreToolUse:
      {"hookSpecificOutput": {"hookEventName": "PreToolUse",
       "permissionDecision": "...", "permissionDecisionReason": "..."}}

    For PermissionRequest:
      - "allow" or "deny": {"hookSpecificOutput": {"hookEventName": "PermissionRequest",
        "decision": {"behavior": "...", "message": "..."}}}
      - "ask": no output (passthrough)
    """
    if stdout is None:
        stdout = sys.stdout
    if hook_event_name == "PreToolUse":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
        json.dump(output, stdout)
        stdout.write("\n")
    elif hook_event_name == "PermissionRequest":
        if decision == "ask":
            # Passthrough: no output, exit 0
            return
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": decision,
                    "message": reason,
                },
            }
        }
        json.dump(output, stdout)
        stdout.write("\n")
