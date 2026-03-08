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
            "hook_event_name": "PermissionRequest",
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
    def test_allow(self):
        stdout = io.StringIO()
        write_output("allow", "Safe command", stdout)
        output = json.loads(stdout.getvalue())
        decision = output["hookSpecificOutput"]["decision"]
        assert decision["behavior"] == "allow"
        assert decision["message"] == "Safe command"

    def test_deny(self):
        stdout = io.StringIO()
        write_output("deny", "Dangerous", stdout)
        output = json.loads(stdout.getvalue())
        decision = output["hookSpecificOutput"]["decision"]
        assert decision["behavior"] == "deny"
        assert decision["message"] == "Dangerous"

    def test_ask_passthrough(self):
        stdout = io.StringIO()
        write_output("ask", "Need review", stdout)
        assert stdout.getvalue() == ""

    def test_hook_event_name(self):
        stdout = io.StringIO()
        write_output("allow", "OK", stdout)
        output = json.loads(stdout.getvalue())
        assert output["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
