"""TIER 3: LLM-based command evaluation using claude CLI."""

from __future__ import annotations

import os
import subprocess
from importlib import resources


def _load_prompt_template() -> str:
    """Load the LLM prompt template."""
    rules_pkg = resources.files("bash_guard.rules")
    return (rules_pkg / "llm_prompt.txt").read_text(encoding="utf-8")


def evaluate(command: str, cwd: str) -> tuple[str, str]:
    """Evaluate a command using the LLM judge.

    Returns:
        (decision, reason) where decision is "allow", "deny", or "ask"
    """
    prompt_template = _load_prompt_template()
    prompt = prompt_template.format(command=command, cwd=cwd)

    env = os.environ.copy()
    env["CLAUDE_CODE_ENTRYPOINT"] = ""

    try:
        result = subprocess.run(
            [
                "claude",
                "-p",
                prompt,
                "--model",
                "claude-haiku-4-5-20251001",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )

        if result.returncode != 0:
            return "ask", f"LLM judge error: exit code {result.returncode}"

        output = result.stdout.strip()
        return _parse_response(output)

    except subprocess.TimeoutExpired:
        return "ask", "LLM judge timed out"
    except FileNotFoundError:
        return "ask", "claude CLI not found"
    except Exception as e:
        return "ask", f"LLM judge error: {e}"


def _parse_response(output: str) -> tuple[str, str]:
    """Parse the LLM response into (decision, reason)."""
    if not output:
        return "ask", "Empty LLM response"

    lines = output.strip().splitlines()
    first_line = lines[0].strip().upper()
    reason = lines[1].strip() if len(lines) > 1 else "No reason provided"

    if first_line == "ALLOW":
        return "allow", reason
    elif first_line == "DENY":
        return "deny", reason
    elif first_line == "ASK":
        return "ask", reason
    else:
        return "ask", f"Unexpected LLM response: {lines[0]}"
