"""Parse suggester output and append validated rules to TOML files.

The applier never edits existing rules — it only appends new ``[[rules]]``
entries to ``allow.toml`` or ``ask.toml``. ``deny.toml`` is never written
to automatically; DENY changes always require human review.

Human review of the resulting diff is expected afterward
(``git diff src/claude_sentinel/rules/``).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from claude_sentinel import rule_engine

# Only these kinds may be appended automatically. DENY entries from the
# LLM are surfaced via `skipped` so a human can review and add them.
_WRITABLE_KINDS = frozenset({"allow", "ask"})

_SECTION_RE = re.compile(
    r"#\s*---\s*(?P<kind>allow|ask|deny)\.toml\s+additions\s*---\s*\n"
    r"(?P<body>.*?)(?=\n#\s*---|\n##\s|\Z)",
    re.DOTALL | re.IGNORECASE,
)


@dataclass
class ApplyResult:
    """Summary of an apply run, grouped by rule kind."""

    added: dict[str, list[str]] = field(default_factory=dict)
    skipped: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    @property
    def total_added(self) -> int:
        return sum(len(v) for v in self.added.values())

    @property
    def total_skipped(self) -> int:
        return sum(len(v) for v in self.skipped.values())


def _extract_sections(text: str) -> dict[str, str]:
    """Parse the suggester output into per-kind TOML bodies."""
    sections: dict[str, str] = {}
    for m in _SECTION_RE.finditer(text):
        kind = m.group("kind").lower()
        sections[kind] = m.group("body").strip()
    return sections


def _parse_toml_rules(body: str) -> list[dict]:
    if not body.strip():
        return []
    try:
        data = tomllib.loads(body)
    except tomllib.TOMLDecodeError:
        return []
    out: list[dict] = []
    out.extend(data.get("rules", []))
    out.extend(data.get("sensitive_path_rules", []))
    return out


def _existing_rule_names(kind: str) -> set[str]:
    ruleset = rule_engine.load_rules(kind=kind)
    return {r.name for r in ruleset.command_rules} | {r.name for r in ruleset.sensitive_path_rules}


def _rules_dir() -> Path:
    """Return the rules directory as a real filesystem path."""
    pkg = resources.files("claude_sentinel.rules")
    # importlib.resources.files returns a Traversable; under a normal
    # wheel/editable install it is a filesystem path.
    return Path(str(pkg))


def _format_entries(entries: list[dict]) -> str:
    """Render parsed rule dicts back as TOML fragments suitable for appending."""
    chunks: list[str] = []
    for entry in entries:
        name = entry["name"]
        if "command_regex" in entry:
            pattern = entry["command_regex"]
            chunks.append(f"[[rules]]\nname = \"{name}\"\ncommand_regex = '''{pattern}'''\n")
        elif "path_regex" in entry:
            pattern = entry["path_regex"]
            chunks.append(
                f"[[sensitive_path_rules]]\nname = \"{name}\"\npath_regex = '''{pattern}'''\n"
            )
    return "\n".join(chunks)


def _append_to_file(path: Path, entries: list[dict]) -> None:
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d")
    header = f"\n# Added by `claude-sentinel apply` on {timestamp}\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(_format_entries(entries))


def apply(
    text: str,
    *,
    dry_run: bool = False,
    rules_dir: Path | None = None,
) -> ApplyResult:
    """Append new allow/ask rules parsed from ``text`` to their TOML files.

    Args:
        text: Raw suggester output (expected to contain the ``# --- allow.toml
            additions ---`` / ``# --- ask.toml additions ---`` markers).
        dry_run: If True, validate without writing any file.
        rules_dir: Override the target directory (primarily for testing).

    Returns:
        ApplyResult summarising appended and skipped rules per kind.
    """
    target_dir = rules_dir if rules_dir is not None else _rules_dir()
    result = ApplyResult()
    for kind, body in _extract_sections(text).items():
        if kind not in _WRITABLE_KINDS:
            result.skipped.setdefault(kind, []).append(
                ("<section>", f"{kind} rules require human review")
            )
            continue

        entries = _parse_toml_rules(body)
        if not entries:
            continue

        existing = _existing_rule_names(kind)
        to_write: list[dict] = []
        for entry in entries:
            name = entry.get("name", "").strip()
            pattern = entry.get("command_regex") or entry.get("path_regex") or ""
            if not name or not pattern:
                result.skipped.setdefault(kind, []).append(
                    (name or "<unnamed>", "missing name or pattern")
                )
                continue
            if name in existing:
                result.skipped.setdefault(kind, []).append((name, "duplicate name"))
                continue
            try:
                re.compile(pattern)
            except re.error as e:
                result.skipped.setdefault(kind, []).append((name, f"invalid regex: {e}"))
                continue
            to_write.append(entry)
            existing.add(name)  # block intra-batch dupes

        if to_write and not dry_run:
            _append_to_file(target_dir / f"{kind}.toml", to_write)

        result.added.setdefault(kind, []).extend(e["name"] for e in to_write)

    if not dry_run and result.total_added:
        rule_engine.reset_cache()
    return result
