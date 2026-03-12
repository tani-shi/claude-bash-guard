"""Tests for llm_judge module."""

from unittest.mock import patch

from claude_sentinel.llm_judge import _parse_response, evaluate


class TestParseResponse:
    def test_allow(self):
        decision, reason = _parse_response("ALLOW\nThis is safe")
        assert decision == "allow"
        assert reason == "This is safe"

    def test_deny(self):
        decision, reason = _parse_response("DENY\nThis is dangerous")
        assert decision == "deny"
        assert reason == "This is dangerous"

    def test_ask(self):
        decision, reason = _parse_response("ASK\nNeeds review")
        assert decision == "ask"
        assert reason == "Needs review"

    def test_empty_response(self):
        decision, reason = _parse_response("")
        assert decision == "ask"

    def test_unexpected_response(self):
        decision, reason = _parse_response("MAYBE\nNot sure")
        assert decision == "ask"

    def test_no_reason(self):
        decision, reason = _parse_response("ALLOW")
        assert decision == "allow"
        assert reason == "No reason provided"


class TestEvaluate:
    @patch("claude_sentinel.llm_judge.subprocess.run")
    def test_successful_allow(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "ALLOW\nSafe command"
        decision, reason = evaluate("ls -la", "/tmp")
        assert decision == "allow"
        assert reason == "Safe command"

    @patch("claude_sentinel.llm_judge.subprocess.run")
    def test_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="claude", timeout=15)
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "timed out" in reason

    @patch("claude_sentinel.llm_judge.subprocess.run")
    def test_claude_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "not found" in reason

    @patch("claude_sentinel.llm_judge.subprocess.run")
    def test_nonzero_exit(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
