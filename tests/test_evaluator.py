"""Tests for evaluator module."""

from unittest.mock import patch

import pytest

from bash_guard.evaluator import evaluate
from bash_guard.rule_engine import reset_cache


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


class TestBashEvaluation:
    def test_deny_sudo(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "sudo rm -rf /"},
            "cwd": "/tmp",
        }
        decision, reason, tier = evaluate(hook_input)
        assert decision == "deny"
        assert tier == "TIER1"

    def test_allow_ls(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        }
        decision, reason, tier = evaluate(hook_input)
        assert decision == "allow"
        assert tier == "TIER2"

    def test_allow_git_status(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": "/tmp",
        }
        decision, reason, tier = evaluate(hook_input)
        assert decision == "allow"
        assert tier == "TIER2"

    @patch("bash_guard.llm_judge.evaluate", return_value=("allow", "Safe"))
    def test_tier3_llm_fallback(self, mock_llm):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-obscure-command --flag"},
            "cwd": "/tmp",
        }
        decision, reason, tier = evaluate(hook_input)
        assert tier == "TIER3"
        mock_llm.assert_called_once_with("some-obscure-command --flag", "/tmp")

    @patch("bash_guard.llm_judge.evaluate", return_value=("deny", "Dangerous"))
    def test_tier3_deny(self, mock_llm):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-dangerous-command"},
            "cwd": "/tmp",
        }
        decision, reason, tier = evaluate(hook_input)
        assert decision == "deny"
        assert tier == "TIER3"


class TestReadEvaluation:
    def test_deny_env_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.env"},
        }
        decision, reason, tier = evaluate(hook_input)
        assert decision == "deny"
        assert tier == "TIER1"

    def test_allow_normal_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/README.md"},
        }
        decision, reason, tier = evaluate(hook_input)
        assert decision == "allow"


class TestUnknownTool:
    def test_passthrough(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/test.txt"},
        }
        result = evaluate(hook_input)
        assert result is None
