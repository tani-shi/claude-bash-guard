"""Tests for hook_io module."""

import io
import json

from bash_guard.hook_io import read_input, write_output


class TestReadInput:
    def test_read_valid_json(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        stdin = io.StringIO(json.dumps(data))
        result = read_input(stdin)
        assert result == data

    def test_read_complex_input(self):
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "session_id": "abc123",
            "cwd": "/tmp",
        }
        stdin = io.StringIO(json.dumps(data))
        result = read_input(stdin)
        assert result["tool_name"] == "Bash"
        assert result["cwd"] == "/tmp"


class TestWriteOutput:
    def test_pretooluse_allow(self):
        stdout = io.StringIO()
        write_output("allow", "Safe command", "PreToolUse", stdout)
        output = json.loads(stdout.getvalue())
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert output["hookSpecificOutput"]["permissionDecisionReason"] == "Safe command"

    def test_pretooluse_deny(self):
        stdout = io.StringIO()
        write_output("deny", "Dangerous", "PreToolUse", stdout)
        output = json.loads(stdout.getvalue())
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_permission_request_allow(self):
        stdout = io.StringIO()
        write_output("allow", "Approved", "PermissionRequest", stdout)
        output = json.loads(stdout.getvalue())
        decision = output["hookSpecificOutput"]["decision"]
        assert decision["behavior"] == "allow"
        assert decision["message"] == "Approved"

    def test_permission_request_deny(self):
        stdout = io.StringIO()
        write_output("deny", "Blocked", "PermissionRequest", stdout)
        output = json.loads(stdout.getvalue())
        decision = output["hookSpecificOutput"]["decision"]
        assert decision["behavior"] == "deny"

    def test_permission_request_ask_passthrough(self):
        stdout = io.StringIO()
        write_output("ask", "Need review", "PermissionRequest", stdout)
        assert stdout.getvalue() == ""
