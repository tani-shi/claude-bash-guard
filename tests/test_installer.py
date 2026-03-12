"""Tests for installer module."""

import json

import pytest

from claude_sentinel.installer import install, uninstall


@pytest.fixture
def settings_file(tmp_path):
    return tmp_path / "settings.json"


class TestInstall:
    def test_install_fresh(self, settings_file):
        msg = install(settings_file)
        assert "installed" in msg

        settings = json.loads(settings_file.read_text())
        assert "PermissionRequest" in settings["hooks"]
        assert "PreToolUse" not in settings["hooks"]

        entries = settings["hooks"]["PermissionRequest"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "claude-sentinel"

    def test_install_existing_settings(self, settings_file):
        settings_file.write_text(json.dumps({"someKey": "value"}))
        install(settings_file)

        settings = json.loads(settings_file.read_text())
        assert settings["someKey"] == "value"
        assert "hooks" in settings

    def test_install_idempotent(self, settings_file):
        install(settings_file)
        install(settings_file)

        settings = json.loads(settings_file.read_text())
        assert len(settings["hooks"]["PermissionRequest"]) == 1

    def test_install_creates_backup(self, settings_file):
        settings_file.write_text(json.dumps({"existing": True}))
        install(settings_file)

        backup = settings_file.with_suffix(".json.bak")
        assert backup.exists()
        backup_data = json.loads(backup.read_text())
        assert backup_data["existing"] is True


class TestUninstall:
    def test_uninstall(self, settings_file):
        install(settings_file)
        msg = uninstall(settings_file)
        assert "removed" in msg

        settings = json.loads(settings_file.read_text())
        assert "PermissionRequest" not in settings.get("hooks", {})

    def test_uninstall_not_installed(self, settings_file):
        settings_file.write_text(json.dumps({}))
        msg = uninstall(settings_file)
        assert "not found" in msg

    def test_uninstall_preserves_other_hooks(self, settings_file):
        settings = {
            "hooks": {
                "PermissionRequest": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": "other-hook"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": "claude-sentinel"}]},
                ]
            }
        }
        settings_file.write_text(json.dumps(settings))
        uninstall(settings_file)

        result = json.loads(settings_file.read_text())
        entries = result["hooks"]["PermissionRequest"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "other-hook"
