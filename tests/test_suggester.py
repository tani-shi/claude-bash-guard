"""Tests for suggester module."""

from unittest.mock import patch

from claude_sentinel import suggester
from claude_sentinel.analyzer import PatternSummary


def _pattern(key, count, covered_by=None, tool_name="Bash"):
    p = PatternSummary(key=key, tool_name=tool_name)
    p.count = count
    p.samples = [f"{key} sample"]
    p.stages = {"LLM_JUDGE": count}
    p.covered_by = covered_by
    return p


class TestBuildPrompt:
    def test_includes_key_and_count(self):
        prompt = suggester.build_prompt([_pattern("sqlite3", 12)])
        assert "sqlite3" in prompt
        assert "count=12" in prompt

    def test_includes_samples(self):
        prompt = suggester.build_prompt([_pattern("git worktree", 4)])
        assert "sample: git worktree sample" in prompt

    def test_empty_patterns(self):
        prompt = suggester.build_prompt([])
        assert "(no uncovered patterns)" in prompt


class TestSuggest:
    def test_skips_covered_by_default(self):
        patterns = [_pattern("ls", 5, covered_by="allow:ls"), _pattern("sqlite3", 3)]
        with patch("claude_sentinel.suggester.asyncio.run", return_value="# allow ..."):
            suggester.suggest(patterns)
        # build_prompt on the filtered set mirrors what suggest() sends to the LLM.
        remaining = [p for p in patterns if not p.covered_by]
        prompt = suggester.build_prompt(remaining)
        assert "sqlite3 sample" in prompt
        assert "ls sample" not in prompt

    def test_returns_note_when_all_covered(self):
        patterns = [_pattern("ls", 5, covered_by="allow:ls")]
        result = suggester.suggest(patterns)
        assert "No uncovered patterns" in result

    def test_passes_all_when_skip_covered_false(self):
        patterns = [_pattern("ls", 5, covered_by="allow:ls")]
        with patch("claude_sentinel.suggester.asyncio.run", return_value="ok") as m:
            result = suggester.suggest(patterns, skip_covered=False)
        assert result == "ok"
        assert m.call_count == 1

    @patch("claude_sentinel.suggester.asyncio.run", side_effect=TimeoutError("slow"))
    def test_timeout_retries_then_fails(self, mock_run):
        patterns = [_pattern("sqlite3", 3)]
        result = suggester.suggest(patterns)
        assert "timed out" in result
        assert mock_run.call_count == 2

    @patch("claude_sentinel.suggester.asyncio.run", side_effect=Exception("connection refused"))
    def test_exception_returns_error(self, mock_run):
        patterns = [_pattern("sqlite3", 3)]
        result = suggester.suggest(patterns)
        assert "connection refused" in result
        assert mock_run.call_count == 1

    @patch(
        "claude_sentinel.suggester.asyncio.run",
        side_effect=[TimeoutError("slow"), "recovered"],
    )
    def test_timeout_then_success(self, mock_run):
        patterns = [_pattern("sqlite3", 3)]
        result = suggester.suggest(patterns)
        assert result == "recovered"
        assert mock_run.call_count == 2
