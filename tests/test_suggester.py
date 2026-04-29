"""Tests for the agent-driven suggester."""

from unittest.mock import patch

from claude_sentinel import suggester


class TestBuildPrompt:
    def test_includes_since_placeholder(self):
        prompt = suggester.build_prompt(since="7d", limit=100)
        assert "--since 7d" in prompt

    def test_includes_limit_placeholder(self):
        prompt = suggester.build_prompt(since="30d", limit=42)
        assert "-n 42" in prompt

    def test_includes_strict_output_format_markers(self):
        prompt = suggester.build_prompt(since="30d", limit=200)
        assert "# --- allow.toml additions ---" in prompt
        assert "# --- ask.toml additions ---" in prompt
        assert "## Notes" in prompt

    def test_mentions_only_allowed_bash_commands(self):
        prompt = suggester.build_prompt(since="30d", limit=200)
        # Whitelist of inspection commands the agent may run.
        assert "claude-sentinel log" in prompt
        assert "claude-sentinel rules" in prompt
        # The prompt explicitly forbids other shell tools.
        assert "Do NOT run any other shell command" in prompt

    def test_does_not_mention_deny_section_output(self):
        prompt = suggester.build_prompt(since="30d", limit=200)
        # The applier must never receive a deny section, so the prompt
        # must instruct the agent to keep DENY candidates in Notes.
        assert "Do NOT emit a `# --- deny.toml additions ---`" in prompt


class TestSuggest:
    def test_success_returns_agent_output(self):
        canned = "# --- allow.toml additions ---\n# --- ask.toml additions ---\n## Notes\n"
        with patch("claude_sentinel.suggester.asyncio.run", return_value=canned):
            result = suggester.suggest(since="7d", limit=10)
        assert result == canned

    @patch("claude_sentinel.suggester.asyncio.run", side_effect=TimeoutError("slow"))
    def test_timeout_retries_then_fails(self, mock_run):
        result = suggester.suggest(since="7d", limit=10)
        assert "timed out" in result
        assert mock_run.call_count == 2

    @patch(
        "claude_sentinel.suggester.asyncio.run",
        side_effect=Exception("connection refused"),
    )
    def test_exception_returns_error(self, mock_run):
        result = suggester.suggest(since="7d", limit=10)
        assert "connection refused" in result
        assert mock_run.call_count == 1

    @patch(
        "claude_sentinel.suggester.asyncio.run",
        side_effect=[TimeoutError("slow"), "recovered"],
    )
    def test_timeout_then_success(self, mock_run):
        result = suggester.suggest(since="7d", limit=10)
        assert result == "recovered"
        assert mock_run.call_count == 2
