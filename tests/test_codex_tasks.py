"""Tests for Codex task ownership."""

import json

from agent_sentinel import codex_tasks


def _creation(parent="parent", child="child", host="local"):
    return {
        "tool_name": codex_tasks.CREATE_TASK_TOOL,
        "session_id": parent,
        "tool_response": {"threadId": child, "hostId": host},
    }


def _message(parent="parent", child="child", host="local"):
    return {
        "tool_name": codex_tasks.SEND_MESSAGE_TOOL,
        "session_id": parent,
        "tool_input": {"threadId": child, "hostId": host},
    }


def test_direct_child_is_owned(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SENTINEL_STATE_DIR", str(tmp_path))

    assert codex_tasks.record_created_task(_creation())
    assert codex_tasks.owns_message_target(_message())


def test_other_parent_host_and_descendant_are_not_owned(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SENTINEL_STATE_DIR", str(tmp_path))
    codex_tasks.record_created_task(_creation())
    codex_tasks.record_created_task(_creation(parent="child", child="grandchild"))

    assert not codex_tasks.owns_message_target(_message(parent="other"))
    assert not codex_tasks.owns_message_target(_message(host="remote"))
    assert not codex_tasks.owns_message_target(_message(child="grandchild"))


def test_text_tool_response_is_recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SENTINEL_STATE_DIR", str(tmp_path))
    hook_input = _creation()
    hook_input["tool_response"] = {
        "content": [{"type": "text", "text": json.dumps({"threadId": "child"})}]
    }

    assert codex_tasks.record_created_task(hook_input)
    assert codex_tasks.owns_message_target(_message())


def test_queued_client_thread_is_recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SENTINEL_STATE_DIR", str(tmp_path))
    hook_input = _creation()
    hook_input["tool_response"] = {"clientThreadId": "child"}

    assert codex_tasks.record_created_task(hook_input)
    assert codex_tasks.owns_message_target(_message())


def test_failed_creation_and_corrupt_state_do_not_grant_ownership(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SENTINEL_STATE_DIR", str(tmp_path))
    hook_input = _creation()
    hook_input["tool_response"] = {"error": "failed"}
    assert not codex_tasks.record_created_task(hook_input)
    assert not codex_tasks.owns_message_target(_message())

    codex_tasks.record_created_task(_creation())
    next(tmp_path.rglob("*.json")).write_text("{")
    assert not codex_tasks.owns_message_target(_message())
