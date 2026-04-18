"""Tests for applier module."""

import pytest

from claude_sentinel import applier
from claude_sentinel.rule_engine import reset_cache


@pytest.fixture()
def tmp_rules(tmp_path):
    """Create a temporary rules dir seeded with the same names as the real one.

    We load the real ruleset via ``_existing_rule_names`` for duplicate
    detection, so the test only needs to provide empty allow/ask/deny files
    that the applier can append to.
    """
    reset_cache()
    d = tmp_path / "rules"
    d.mkdir()
    (d / "allow.toml").write_text("", encoding="utf-8")
    (d / "ask.toml").write_text("", encoding="utf-8")
    (d / "deny.toml").write_text("", encoding="utf-8")
    yield d
    reset_cache()


SAMPLE_OUTPUT = """
# --- allow.toml additions ---
[[rules]]
name = "fresh-allow"
command_regex = '''^foo-xyz-fresh( |$)'''

# --- ask.toml additions ---
[[rules]]
name = "fresh-ask"
command_regex = '''^bar-xyz-fresh( |$)'''

## Notes
- fresh-allow: safe
- fresh-ask:   ambiguous
"""


class TestExtractSections:
    def test_basic(self):
        sections = applier._extract_sections(SAMPLE_OUTPUT)
        assert "allow" in sections
        assert "ask" in sections
        assert "fresh-allow" in sections["allow"]
        assert "fresh-ask" in sections["ask"]
        assert "Notes" not in sections["ask"]  # note block is excluded

    def test_deny_section_captured(self):
        text = "# --- deny.toml additions ---\n[[rules]]\nname = 'x'\ncommand_regex = '''^x'''\n"
        sections = applier._extract_sections(text)
        assert "deny" in sections

    def test_empty_input(self):
        assert applier._extract_sections("") == {}


class TestApply:
    def test_appends_to_allow_and_ask(self, tmp_rules):
        result = applier.apply(SAMPLE_OUTPUT, rules_dir=tmp_rules)
        assert result.added["allow"] == ["fresh-allow"]
        assert result.added["ask"] == ["fresh-ask"]
        allow_body = (tmp_rules / "allow.toml").read_text()
        ask_body = (tmp_rules / "ask.toml").read_text()
        assert "fresh-allow" in allow_body
        assert "foo-xyz-fresh" in allow_body
        assert "fresh-ask" in ask_body
        assert "bar-xyz-fresh" in ask_body

    def test_dry_run_does_not_write(self, tmp_rules):
        result = applier.apply(SAMPLE_OUTPUT, rules_dir=tmp_rules, dry_run=True)
        assert result.added["allow"] == ["fresh-allow"]
        assert (tmp_rules / "allow.toml").read_text() == ""
        assert (tmp_rules / "ask.toml").read_text() == ""

    def test_skips_deny_section(self, tmp_rules):
        text = (
            "# --- deny.toml additions ---\n"
            "[[rules]]\n"
            'name = "dangerous"\n'
            "command_regex = '''^nope'''\n"
        )
        result = applier.apply(text, rules_dir=tmp_rules)
        assert "deny" in result.skipped
        assert (tmp_rules / "deny.toml").read_text() == ""

    def test_skips_duplicate_name(self, tmp_rules):
        # "sudo" is already a real deny rule; try to sneak it into allow.
        text = (
            "# --- allow.toml additions ---\n"
            "[[rules]]\n"
            'name = "fresh-ok"\n'
            "command_regex = '''^fresh-ok'''\n"
            "[[rules]]\n"
            'name = "fresh-ok"\n'
            "command_regex = '''^dup'''\n"
        )
        result = applier.apply(text, rules_dir=tmp_rules)
        assert result.added["allow"] == ["fresh-ok"]
        assert ("fresh-ok", "duplicate name") in result.skipped["allow"]

    def test_skips_invalid_regex(self, tmp_rules):
        text = (
            "# --- allow.toml additions ---\n"
            "[[rules]]\n"
            'name = "bad-regex"\n'
            "command_regex = '''(unclosed'''\n"
        )
        result = applier.apply(text, rules_dir=tmp_rules)
        assert result.added.get("allow", []) == []
        assert any(n == "bad-regex" for n, _ in result.skipped["allow"])

    def test_skips_missing_fields(self, tmp_rules):
        text = '# --- allow.toml additions ---\n[[rules]]\nname = "no-pattern"\n'
        result = applier.apply(text, rules_dir=tmp_rules)
        assert result.added.get("allow", []) == []
        assert any(n == "no-pattern" for n, _ in result.skipped["allow"])

    def test_broken_toml_yields_nothing(self, tmp_rules):
        text = "# --- allow.toml additions ---\n[[broken\nnot valid\n"
        result = applier.apply(text, rules_dir=tmp_rules)
        assert result.total_added == 0

    def test_empty_input(self, tmp_rules):
        result = applier.apply("", rules_dir=tmp_rules)
        assert result.total_added == 0
        assert result.total_skipped == 0

    def test_appended_file_remains_parseable(self, tmp_rules):
        import tomllib

        existing = "[[rules]]\nname = \"seed\"\ncommand_regex = '''^seed( |$)'''\n"
        (tmp_rules / "allow.toml").write_text(existing, encoding="utf-8")
        applier.apply(SAMPLE_OUTPUT, rules_dir=tmp_rules)
        data = tomllib.loads((tmp_rules / "allow.toml").read_text())
        names = [r["name"] for r in data["rules"]]
        assert names == ["seed", "fresh-allow"]
