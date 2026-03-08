"""Tests for CLI module."""

import json
from unittest.mock import patch

from bash_guard.cli import main


class TestHookMode:
    def test_bash_allow(self, capsys):
        hook_input = {
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("bash_guard.hook_io.read_input", return_value=hook_input):
            main([])

        output = json.loads(capsys.readouterr().out)
        assert output["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_bash_deny(self, capsys):
        hook_input = {
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "sudo rm -rf /"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("bash_guard.hook_io.read_input", return_value=hook_input):
            main([])

        output = json.loads(capsys.readouterr().out)
        assert output["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_unknown_tool_passthrough(self, capsys):
        hook_input = {
            "hook_event_name": "PermissionRequest",
            "tool_name": "Write",
            "tool_input": {"file_path": "/test.txt"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("bash_guard.hook_io.read_input", return_value=hook_input):
            main([])

        assert capsys.readouterr().out == ""


class TestTestMode:
    def test_allow_command(self, capsys):
        main(["--test", "ls -la"])
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out

    def test_deny_command(self, capsys):
        main(["--test", "sudo rm -rf /"])
        captured = capsys.readouterr()
        assert "DENY" in captured.out

    def test_explain_flag(self, capsys):
        main(["--test", "ls -la", "--explain"])
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out
        assert "ls -la" in captured.err


class TestSubcommands:
    def test_install(self, tmp_path, capsys):
        settings_file = tmp_path / "settings.json"
        with patch("bash_guard.installer.SETTINGS_PATH", settings_file):
            main(["install"])
        captured = capsys.readouterr()
        assert "installed" in captured.out

    def test_uninstall(self, tmp_path, capsys):
        settings_file = tmp_path / "settings.json"
        with patch("bash_guard.installer.SETTINGS_PATH", settings_file):
            main(["install"])
            main(["uninstall"])
        captured = capsys.readouterr()
        assert "removed" in captured.out
