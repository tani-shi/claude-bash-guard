"""Ownership of Codex tasks created by another task."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

CREATE_TASK_TOOL = "codex_appcreate_thread"
SEND_MESSAGE_TOOL = "codex_appsend_message_to_thread"
_STATE_VERSION = 1


def record_created_task(hook_input: dict[str, Any]) -> bool:
    """Record a successful direct child creation."""
    if hook_input.get("tool_name") != CREATE_TASK_TOOL:
        return False
    parent = _identifier(hook_input.get("session_id"))
    created = _created_thread(hook_input.get("tool_response"))
    if parent is None or created is None:
        return False
    child, host = created
    try:
        _write_edge(parent, child, host)
    except OSError:
        return False
    return True


def owns_message_target(hook_input: dict[str, Any]) -> bool:
    """Return whether the requesting task directly created the target."""
    if hook_input.get("tool_name") != SEND_MESSAGE_TOOL:
        return False
    parent = _identifier(hook_input.get("session_id"))
    tool_input = hook_input.get("tool_input")
    if parent is None or not isinstance(tool_input, dict):
        return False
    child = _identifier(tool_input.get("threadId"))
    if child is None:
        return False
    host = _host(tool_input.get("hostId"))
    expected = {"version": _STATE_VERSION, "parent": parent, "child": child, "host": host}
    try:
        return _read_json(_edge_path(parent, child, host)) == expected
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def _created_thread(value: object) -> tuple[str, str] | None:
    if isinstance(value, dict):
        child = _identifier(value.get("threadId")) or _identifier(value.get("clientThreadId"))
        if child is not None:
            return child, _host(value.get("hostId"))
        for nested in value.values():
            if created := _created_thread(nested):
                return created
    elif isinstance(value, list):
        for nested in value:
            if created := _created_thread(nested):
                return created
    elif isinstance(value, str) and len(value) <= 16_384:
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return None
        return _created_thread(decoded)
    return None


def _write_edge(parent: str, child: str, host: str) -> None:
    path = _edge_path(parent, child, host)
    _prepare_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(
                {"version": _STATE_VERSION, "parent": parent, "child": child, "host": host},
                stream,
                separators=(",", ":"),
            )
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _prepare_directory(path: Path) -> None:
    ownership_dir = _ownership_dir()
    ownership_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.mkdir(mode=0o700, exist_ok=True)
    if hasattr(os, "chmod"):
        os.chmod(ownership_dir, 0o700)
        os.chmod(path, 0o700)


def _read_json(path: Path) -> object:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd, encoding="utf-8") as stream:
        return json.load(stream)


def _edge_path(parent: str, child: str, host: str) -> Path:
    parent_key = hashlib.sha256(parent.encode()).hexdigest()
    child_key = hashlib.sha256(f"{host}\0{child}".encode()).hexdigest()
    return _ownership_dir() / parent_key / f"{child_key}.json"


def _ownership_dir() -> Path:
    configured = os.environ.get("AGENT_SENTINEL_STATE_DIR")
    if configured:
        base = Path(configured)
    elif sys.platform == "win32" and (local := os.environ.get("LOCALAPPDATA")):
        base = Path(local) / "agent-sentinel"
    else:
        base = Path.home() / ".local" / "share" / "agent-sentinel"
    return base / "codex-task-ownership"


def _identifier(value: object) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 256 else None


def _host(value: object) -> str:
    return value if isinstance(value, str) and 0 < len(value) <= 256 else "local"
