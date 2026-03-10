"""CLI entry point for bash-guard."""

from __future__ import annotations

import argparse
import json
import sys
import time

from bash_guard import evaluator, hook_io, installer, logger


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

    # log subcommand
    log_parser = subparsers.add_parser("log", help="View evaluation logs")
    log_parser.add_argument(
        "-n", type=int, default=20, help="Number of records to show (default: 20)"
    )
    log_parser.add_argument(
        "--decision", choices=["allow", "deny", "ask"], help="Filter by decision"
    )
    log_parser.add_argument(
        "--stage",
        choices=["RULE_DENY", "RULE_ALLOW", "RULE_ASK", "LLM_JUDGE"],
        help="Filter by stage",
    )
    log_parser.add_argument(
        "--since", help="Show records since (e.g. 1h, 30m, 2d)"
    )
    log_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Raw JSON Lines output"
    )
    log_parser.add_argument(
        "--tail", action="store_true", help="Show oldest first (chronological order)"
    )
    log_parser.add_argument(
        "-f", "--follow", action="store_true", help="Follow log in real-time (tail -f)"
    )
    log_parser.add_argument(
        "--path", action="store_true", help="Print log directory path and exit"
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

    if args.subcommand == "log":
        _run_log(args)
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
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": "test",
        "cwd": os.getcwd(),
    }

    t0 = time.monotonic()
    result = evaluator.evaluate(hook_input)
    elapsed_ms = (time.monotonic() - t0) * 1000

    if result is None:
        print("PASS (unknown tool, passthrough)")
        return

    decision, reason, stage = result
    logger.log_evaluation(hook_input, decision, reason, stage, elapsed_ms)
    print(f"{decision.upper()} [{stage}]: {reason}")

    if explain:
        print(f"  Command: {command}", file=sys.stderr)


def _run_hook(*, explain: bool = False) -> None:
    """Run in hook mode: read stdin JSON, evaluate, write stdout JSON."""
    try:
        hook_input = hook_io.read_input()
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    t0 = time.monotonic()
    result = evaluator.evaluate(hook_input)
    elapsed_ms = (time.monotonic() - t0) * 1000

    if result is None:
        # Unknown tool: passthrough (exit 0, no output)
        return

    decision, reason, stage = result
    logger.log_evaluation(hook_input, decision, reason, stage, elapsed_ms)

    if explain:
        tool_name = hook_input.get("tool_name", "")
        print(f"[bash-guard] {tool_name}: {decision} [{stage}] {reason}", file=sys.stderr)

    hook_io.write_output(decision, reason)


def _run_log(args: argparse.Namespace) -> None:
    """Handle the log subcommand."""
    if args.path:
        print(logger.get_log_dir())
        return

    if args.follow:
        _follow_log(args)
        return

    since_ts = _parse_since(args.since) if args.since else None

    records = logger.iter_logs(
        since=since_ts,
        decision=args.decision,
        stage=args.stage,
        limit=args.n,
        newest_first=not args.tail,
    )

    for rec in records:
        if args.json_output:
            print(json.dumps(rec, ensure_ascii=False))
        else:
            _print_record(rec)


def _follow_log(args: argparse.Namespace) -> None:
    """Follow the log file in real-time."""
    import select

    log_path = logger.get_log_dir() / logger.LOG_FILENAME
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Start from end of file if it exists
        try:
            f = open(log_path, encoding="utf-8")
            f.seek(0, 2)  # Seek to end
        except FileNotFoundError:
            # Wait for file to be created
            print(f"Waiting for {log_path} ...", file=sys.stderr)
            while not log_path.exists():
                time.sleep(0.5)
            f = open(log_path, encoding="utf-8")

        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    if args.json_output:
                        print(line, flush=True)
                    else:
                        try:
                            rec = json.loads(line)
                            _print_record(rec)
                            sys.stdout.flush()
                        except json.JSONDecodeError:
                            pass
            else:
                time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        if "f" in locals():
            f.close()


def _print_record(rec: dict) -> None:
    """Print a single record in human-readable format."""
    ts = rec.get("ts", "")
    # Trim to seconds for display
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(ts)
        ts_display = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        ts_display = ts

    decision = rec.get("decision", "").upper()
    stage = rec.get("stage", "")
    tool_name = rec.get("tool_name", "")
    input_val = rec.get("input", "")
    reason = rec.get("reason", "")
    elapsed = rec.get("elapsed_ms", 0)

    print(f"{ts_display} {decision} [{stage}] {tool_name}: {input_val}")
    print(f"  {reason} ({elapsed}ms)")


def _parse_since(value: str) -> float:
    """Parse a relative time string like '1h', '30m', '2d' to a Unix timestamp."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if not value:
        raise argparse.ArgumentTypeError("empty --since value")

    unit = value[-1].lower()
    if unit not in units:
        raise argparse.ArgumentTypeError(
            f"Invalid time unit '{unit}'. Use s, m, h, or d."
        )
    try:
        amount = float(value[:-1])
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid number in '{value}'")

    return time.time() - (amount * units[unit])


if __name__ == "__main__":
    main()
