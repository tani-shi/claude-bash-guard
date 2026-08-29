"""Tests for the Codex task-message approval contract."""

from pathlib import Path

import pytest

from agent_sentinel.evaluator import codex_defer_target, evaluate_codex

VALID_CONFIG = """\
approval_policy = "on-request"
approvals_reviewer = "user"

[plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app.tools.send_message_to_thread]
approval_mode = "prompt"
"""


def _write_config(codex_home: Path, content: str = VALID_CONFIG) -> None:
    codex_home.mkdir()
    (codex_home / "config.toml").write_text(content)


def _hook(cwd: Path, *, tool: str = "codex_appsend_message_to_thread", mode: object = "default"):
    return {
        "tool_name": tool,
        "tool_input": {"threadId": "target", "prompt": "Continue"},
        "cwd": str(cwd),
        "permission_mode": mode,
    }


@pytest.mark.parametrize("mode", ["default", "acceptEdits"])
def test_task_message_defers_to_native_human_approval(tmp_path, monkeypatch, mode):
    codex_home = tmp_path / "codex-home"
    _write_config(codex_home)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    hook_input = _hook(tmp_path, mode=mode)

    assert evaluate_codex(hook_input) is None
    assert codex_defer_target(hook_input) == (
        "native",
        "CODEX_NATIVE_PROMPT",
        "No hook denial; Codex native human approval applies",
    )


@pytest.mark.parametrize(
    "content",
    [
        "",
        'approval_policy = "never"\napprovals_reviewer = "user"\n',
        'approval_policy = "untrusted"\napprovals_reviewer = "user"\n',
        'approval_policy = "on-request"\napprovals_reviewer = "auto_review"\n',
        'approval_policy = "on-request"\napprovals_reviewer = "user"\n',
        (
            'approval_policy = "on-request"\napprovals_reviewer = "user"\n'
            '[plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app.tools.'
            'send_message_to_thread]\napproval_mode = "approve"\n'
        ),
        (
            'approval_policy = "on-request"\napprovals_reviewer = "user"\n'
            '[plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app.tools.'
            'send_message_to_thread]\napproval_mode = "auto"\n'
        ),
        (
            'approval_policy = "on-request"\napprovals_reviewer = "user"\n'
            '[plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app.tools.'
            'send_message_to_thread]\napproval_mode = "writes"\n'
        ),
    ],
)
def test_task_message_denies_incomplete_or_nonhuman_config(tmp_path, monkeypatch, content):
    codex_home = tmp_path / "codex-home"
    _write_config(codex_home, content)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    result = evaluate_codex(_hook(tmp_path))

    assert result is not None
    decision, reason, stage = result
    assert decision == "deny"
    assert "Codex task messaging is blocked" in reason
    assert stage == "CODEX_APPROVAL_DENY"


def test_task_message_denies_missing_config(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "missing"))

    result = evaluate_codex(_hook(tmp_path))

    assert result is not None
    assert result[0] == "deny"
    assert "is missing" in result[1]


def test_task_message_denies_invalid_toml(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex-home"
    _write_config(codex_home, "invalid = [")
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    result = evaluate_codex(_hook(tmp_path))

    assert result is not None
    assert result[0] == "deny"
    assert "could not be parsed" in result[1]


@pytest.mark.parametrize("mode", [None, "plan", "dontAsk", "bypassPermissions", "unknown"])
def test_task_message_denies_noninteractive_permission_mode(tmp_path, monkeypatch, mode):
    codex_home = tmp_path / "codex-home"
    _write_config(codex_home)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    result = evaluate_codex(_hook(tmp_path, mode=mode))

    assert result is not None
    assert result[0] == "deny"
    assert "interactive permission mode" in result[1]


def test_project_config_override_is_checked(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex-home"
    _write_config(codex_home)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / ".codex").mkdir()
    (project / ".codex" / "config.toml").write_text('approvals_reviewer = "auto_review"\n')

    result = evaluate_codex(_hook(project))

    assert result is not None
    assert result[0] == "deny"
    assert "approvals_reviewer" in result[1]


def test_project_config_cannot_supply_missing_managed_base_contract(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / ".codex").mkdir()
    (project / ".codex" / "config.toml").write_text(VALID_CONFIG)

    result = evaluate_codex(_hook(project))

    assert result is not None
    assert result[0] == "deny"
    assert "approval_policy is missing" in result[1]


@pytest.mark.parametrize(
    "tool",
    [
        "codex_app__send_message_to_thread",
        "codex_appcreate_thread",
        "codex_appset_thread_archived",
        "codex_appset_thread_pinned",
        "codex_appset_thread_title",
        "codex_appread_thread",
        "codex_applist_threads",
        "codex_applist_archived_threads",
        "codex_appwait_threads",
    ],
)
def test_only_exact_observed_task_message_tool_is_protected(tmp_path, monkeypatch, tool):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "missing"))

    assert evaluate_codex(_hook(tmp_path, tool=tool, mode=None)) is None
