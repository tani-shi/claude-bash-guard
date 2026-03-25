"""TOML rule loading and regex matching."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from typing import Any


@dataclass
class Rule:
    name: str
    pattern: re.Pattern[str]


@dataclass
class RuleSet:
    command_rules: list[Rule] = field(default_factory=list)
    sensitive_path_rules: list[Rule] = field(default_factory=list)


# Module-level cache
_deny_rules: RuleSet | None = None
_allow_rules: RuleSet | None = None
_ask_rules: RuleSet | None = None


def _parse_rules(data: dict[str, Any]) -> RuleSet:
    """Parse TOML data into a RuleSet."""
    ruleset = RuleSet()
    for entry in data.get("rules", []):
        ruleset.command_rules.append(
            Rule(name=entry["name"], pattern=re.compile(entry["command_regex"]))
        )
    for entry in data.get("sensitive_path_rules", []):
        ruleset.sensitive_path_rules.append(
            Rule(name=entry["name"], pattern=re.compile(entry["path_regex"]))
        )
    return ruleset


def load_rules(path: str | None = None, *, kind: str = "deny") -> RuleSet:
    """Load rules from a TOML file. Uses importlib.resources for bundled rules."""
    if path:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    else:
        rules_pkg = resources.files("claude_sentinel.rules")
        filename = f"{kind}.toml"
        content = (rules_pkg / filename).read_text(encoding="utf-8")
        data = tomllib.loads(content)
    return _parse_rules(data)


def get_deny_rules() -> RuleSet:
    """Get cached deny rules."""
    global _deny_rules
    if _deny_rules is None:
        _deny_rules = load_rules(kind="deny")
    return _deny_rules


def get_allow_rules() -> RuleSet:
    """Get cached allow rules."""
    global _allow_rules
    if _allow_rules is None:
        _allow_rules = load_rules(kind="allow")
    return _allow_rules


def get_ask_rules() -> RuleSet:
    """Get cached ask rules."""
    global _ask_rules
    if _ask_rules is None:
        _ask_rules = load_rules(kind="ask")
    return _ask_rules


def match_deny(command: str) -> Rule | None:
    """Check if command matches any deny rule."""
    for rule in get_deny_rules().command_rules:
        if rule.pattern.search(command):
            return rule
    return None


def match_allow(command: str) -> Rule | None:
    """Check if command matches any allow rule."""
    for rule in get_allow_rules().command_rules:
        if rule.pattern.search(command):
            return rule
    return None


def match_ask(command: str) -> Rule | None:
    """Check if command matches any ask rule."""
    for rule in get_ask_rules().command_rules:
        if rule.pattern.search(command):
            return rule
    return None


def match_sensitive_path(file_path: str) -> Rule | None:
    """Check if file path matches any sensitive path deny rule."""
    for rule in get_deny_rules().sensitive_path_rules:
        if rule.pattern.search(file_path):
            return rule
    return None


def reset_cache() -> None:
    """Reset the rule cache (useful for testing)."""
    global _deny_rules, _allow_rules, _ask_rules
    _deny_rules = None
    _allow_rules = None
    _ask_rules = None
