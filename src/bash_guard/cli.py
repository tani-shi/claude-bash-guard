"""CLI entry point for bash-guard."""

from __future__ import annotations

import argparse
import sys

from bash_guard import evaluator, hook_io, installer


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="bash-guard",
        description="Claude Code hook for evaluating Bash command safety",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Output decision reason to stderr",
    )
    parser.add_argument(
        "--test",
        metavar="COMMAND",
        help="Test a command with synthetic hook input",
    )

    subparsers = parser.add_subparsers(dest="subcommand")
    subparsers.add_parser("install", help="Install hooks into Claude Code settings")
    subparsers.add_parser(
        "uninstall", help="Remove hooks from Claude Code settings"
    )

    args = parser.parse_args(argv)

    if args.subcommand == "install":
        msg = installer.install()
        print(msg)
        return

    if args.subcommand == "uninstall":
        msg = installer.uninstall()
        print(msg)
        return

    if args.test:
        _run_test(args.test, explain=args.explain)
        return

    # Default: hook mode — read from stdin, evaluate, write to stdout
    _run_hook(explain=args.explain)


def _run_test(command: str, *, explain: bool = False) -> None:
    """Test a command with synthetic hook input."""
    import os

    hook_input = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": "test",
        "cwd": os.getcwd(),
    }

    result = evaluator.evaluate(hook_input)
    if result is None:
        print("PASS (unknown tool, passthrough)")
        return

    decision, reason, tier = result
    print(f"{decision.upper()} [{tier}]: {reason}")

    if explain:
        print(f"  Command: {command}", file=sys.stderr)


def _run_hook(*, explain: bool = False) -> None:
    """Run in hook mode: read stdin JSON, evaluate, write stdout JSON."""
    try:
        hook_input = hook_io.read_input()
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    hook_event_name = hook_input.get("hook_event_name", "")
    result = evaluator.evaluate(hook_input)

    if result is None:
        # Unknown tool: passthrough (exit 0, no output)
        return

    decision, reason, tier = result

    if explain:
        tool_name = hook_input.get("tool_name", "")
        print(f"[bash-guard] {tool_name}: {decision} [{tier}] {reason}", file=sys.stderr)

    hook_io.write_output(decision, reason, hook_event_name)


if __name__ == "__main__":
    main()
