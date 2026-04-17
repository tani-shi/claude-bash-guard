"""Hook protocol I/O for Claude Code PermissionRequest hooks."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO


def read_input(stdin: TextIO | None = None) -> dict[str, Any]:
    """Read and parse JSON from stdin."""
    stream = stdin if stdin is not None else sys.stdin
    raw = stream.read()
    return json.loads(raw)


def write_output(
    decision: str,
    reason: str,
    stdout: TextIO | None = None,
) -> None:
    """Write the PermissionRequest JSON response to stdout.

    - "allow" or "deny": {"hookSpecificOutput": {"hookEventName": "PermissionRequest",
      "decision": {"behavior": "...", "message": "..."}}}
    - "ask": no output (passthrough, exit 0)
    """
    stream = stdout if stdout is not None else sys.stdout
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
    json.dump(output, stream)
    stream.write("\n")
