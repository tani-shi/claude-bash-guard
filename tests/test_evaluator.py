"""Tests for evaluator module."""

from unittest.mock import patch

import pytest

from claude_sentinel.evaluator import evaluate
from claude_sentinel.rule_engine import reset_cache


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
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_allow_ls(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    def test_allow_git_status(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    @patch("claude_sentinel.llm_judge.evaluate", return_value=("allow", "Safe"))
    def test_stage3_llm_fallback(self, mock_llm):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-obscure-command --flag"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert stage == "LLM_JUDGE"
        mock_llm.assert_called_once_with("some-obscure-command --flag", "/tmp")

    @patch("claude_sentinel.llm_judge.evaluate", return_value=("deny", "Dangerous"))
    def test_stage3_deny(self, mock_llm):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-dangerous-command"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "LLM_JUDGE"


    def test_ask_ssh(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ssh user@host"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_allow_overrides_ask(self):
        """Allow rules take priority over ask rules."""
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"


class TestReadEvaluation:
    def test_deny_env_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_allow_normal_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"


class TestAutoAllowTools:
    def test_grep_allowed(self):
        hook_input = {
            "tool_name": "Grep",
            "tool_input": {"pattern": "foo", "path": "/project"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_glob_allowed(self):
        hook_input = {
            "tool_name": "Glob",
            "tool_input": {"pattern": "**/*.py"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_webfetch_allowed(self):
        hook_input = {
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_websearch_allowed(self):
        hook_input = {
            "tool_name": "WebSearch",
            "tool_input": {"query": "python docs"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "mcp__claude_ai_Slack__slack_read_canvas",
            "mcp__claude_ai_Slack__slack_read_channel",
            "mcp__claude_ai_Slack__slack_read_thread",
            "mcp__claude_ai_Slack__slack_read_user_profile",
            "mcp__claude_ai_Slack__slack_search_channels",
            "mcp__claude_ai_Slack__slack_search_public",
            "mcp__claude_ai_Slack__slack_search_public_and_private",
            "mcp__claude_ai_Slack__slack_search_users",
        ],
    )
    def test_slack_mcp_read_search_allowed(self, tool_name):
        hook_input = {
            "tool_name": tool_name,
            "tool_input": {"channel": "general"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_slack_mcp_future_read_tool_allowed(self):
        """New read/search tools matching the prefix are auto-allowed."""
        hook_input = {
            "tool_name": "mcp__claude_ai_Slack__slack_read_new_feature",
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "mcp__claude_ai_Slack__slack_send_message",
            "mcp__claude_ai_Slack__slack_send_message_draft",
            "mcp__claude_ai_Slack__slack_create_canvas",
            "mcp__claude_ai_Slack__slack_update_canvas",
            "mcp__claude_ai_Slack__slack_schedule_message",
        ],
    )
    def test_slack_mcp_write_tools_ask(self, tool_name):
        """Write/send tools must require confirmation (ASK)."""
        hook_input = {
            "tool_name": tool_name,
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "TOOL_ASK"


class TestExternalImpactCommands:
    """Commands with external impact should be ASK, not ALLOW."""

    def test_docker_push_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "docker push myimage"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_npm_publish_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm publish"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_npm_run_deploy_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm run deploy"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_cargo_publish_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "cargo publish"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_curl_post_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "curl -X POST https://api.example.com"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_make_deploy_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "make deploy"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_aws_cp_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws s3 cp file s3://bucket"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_gh_pr_create_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "gh pr create --title test"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"


class TestUnknownTool:
    def test_passthrough(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/test.txt"},
        }
        result = evaluate(hook_input)
        assert result is None
