"""Tests for analyzer module."""

import pytest

from claude_sentinel import analyzer
from claude_sentinel.rule_engine import reset_cache


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


def _record(tool_name, input_value, stage="LLM_JUDGE"):
    return {
        "tool_name": tool_name,
        "input": input_value,
        "stage": stage,
        "decision": "ask",
        "ts": "2026-04-01T00:00:00+00:00",
    }


class TestNormalizeBash:
    def test_single_token(self):
        assert analyzer._normalize_bash("sqlite3 /tmp/db 'SELECT 1'") == "sqlite3"

    def test_multi_token_git(self):
        assert analyzer._normalize_bash("git worktree add ../foo") == "git worktree"

    def test_multi_token_npm_run(self):
        assert analyzer._normalize_bash("npm run migrate:up") == "npm run"

    def test_unknown_flag_after_head_falls_back_to_head(self):
        # Unknown options halt prefix-stripping; the grouping key is the
        # head command alone.
        assert analyzer._normalize_bash("git --version") == "git"
        assert analyzer._normalize_bash("git --unknown-flag") == "git"

    def test_known_prefix_options_stripped_to_subcommand(self):
        # Known prefix options (-C, -c, --no-pager, --silent, ...) collapse
        # to the same grouping key as the prefix-free form.
        assert analyzer._normalize_bash("git -C /tmp status") == "git status"
        assert analyzer._normalize_bash("git -c color.ui=never diff") == "git diff"
        assert analyzer._normalize_bash("npm --silent install") == "npm install"
        assert analyzer._normalize_bash("docker -q ps") == "docker ps"

    def test_empty(self):
        assert analyzer._normalize_bash("") is None
        assert analyzer._normalize_bash("   ") is None

    def test_unparseable_quote_falls_back(self):
        # shlex raises on unterminated quote; the fallback splits on whitespace.
        assert analyzer._normalize_bash("echo 'unterminated") == "echo"


class TestNormalizePath:
    def test_suffix(self):
        assert analyzer._normalize_path("Read", "/tmp/foo.py") == "Read:.py"

    def test_dotfile_no_suffix(self):
        assert analyzer._normalize_path("Read", "/home/user/.bashrc") == "Read:.bashrc"

    def test_windows_path(self):
        assert analyzer._normalize_path("Write", "C:\\Users\\x\\file.txt") == "Write:.txt"

    def test_empty(self):
        assert analyzer._normalize_path("Read", "") is None


class TestSummarize:
    def test_groups_by_normalized_key(self):
        records = [
            _record("Bash", "sqlite3 a.db 'SELECT 1'"),
            _record("Bash", "sqlite3 b.db 'SELECT 2'"),
            _record("Bash", "git worktree add ../x"),
        ]
        patterns = analyzer.summarize(records=records)
        keys = {p.key: p.count for p in patterns}
        assert keys["sqlite3"] == 2
        assert keys["git worktree"] == 1

    def test_sorted_by_count_desc(self):
        records = (
            [_record("Bash", "sqlite3 db")] * 3
            + [_record("Bash", "jq '.env'")] * 5
            + [_record("Bash", "git worktree add foo")] * 1
        )
        patterns = analyzer.summarize(records=records)
        assert [p.key for p in patterns[:3]] == ["jq", "sqlite3", "git worktree"]

    def test_samples_limited_to_three(self):
        records = [_record("Bash", f"sqlite3 db{i}") for i in range(10)]
        patterns = analyzer.summarize(records=records)
        assert len(patterns[0].samples) == 3

    def test_stage_tally(self):
        records = [
            _record("Bash", "sqlite3 a", stage="LLM_JUDGE"),
            _record("Bash", "sqlite3 b", stage="LLM_JUDGE"),
            _record("Bash", "sqlite3 c", stage="RULE_ASK"),
        ]
        patterns = analyzer.summarize(records=records)
        assert patterns[0].stages == {"LLM_JUDGE": 2, "RULE_ASK": 1}

    def test_decision_tally(self):
        records = [
            _record("Bash", "sqlite3 a"),
            _record("Bash", "sqlite3 b"),
            _record("Bash", "sqlite3 c"),
        ]
        records[0]["decision"] = "allow"
        records[1]["decision"] = "allow"
        records[2]["decision"] = "ask"
        patterns = analyzer.summarize(records=records)
        assert patterns[0].decisions == {"allow": 2, "ask": 1}

    def test_prefix_options_collapse_grouping(self):
        # git -c x=y diff and git diff group together under "git diff"
        records = [
            _record("Bash", "git -c color.ui=never diff"),
            _record("Bash", "git diff HEAD"),
            _record("Bash", "git -C /tmp/repo diff"),
        ]
        patterns = analyzer.summarize(records=records)
        keys = {p.key: p.count for p in patterns}
        assert keys["git diff"] == 3

    def test_limit(self):
        records = [_record("Bash", f"cmd{i}") for i in range(30)]
        patterns = analyzer.summarize(records=records, limit=5)
        assert len(patterns) == 5

    def test_file_tool_grouping(self):
        records = [
            _record("Read", "/tmp/foo.py"),
            _record("Read", "/tmp/bar.py"),
            _record("Read", "/tmp/config.yaml"),
        ]
        patterns = analyzer.summarize(records=records)
        keys = {p.key: p.count for p in patterns}
        assert keys["Read:.py"] == 2
        assert keys["Read:.yaml"] == 1

    def test_skips_unknown_tool(self):
        records = [{"tool_name": "", "input": "", "stage": "", "decision": "ask"}]
        patterns = analyzer.summarize(records=records)
        assert patterns == []

    def test_covered_by_existing_allow_rule(self):
        # "ls -la" matches the existing ls allow rule.
        records = [_record("Bash", "ls -la")]
        patterns = analyzer.summarize(records=records)
        assert patterns[0].covered_by is not None
        assert patterns[0].covered_by.startswith("allow:")

    def test_not_covered_by_existing(self):
        # A made-up command unlikely to match any real rule.
        records = [_record("Bash", "flarglewidgetxyz --spin")]
        patterns = analyzer.summarize(records=records)
        assert patterns[0].covered_by is None
