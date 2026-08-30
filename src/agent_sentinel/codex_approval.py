"""Human-approval contract for Codex task messages."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

TASK_MESSAGE_TOOL = "codex_appsend_message_to_thread"

_APPROVAL_PATHS = {
    ("approval_policy",): "on-request",
    ("approvals_reviewer",): "user",
    (
        "plugins",
        "codex-app-tools@openai-bundled",
        "mcp_servers",
        "codex_app",
        "tools",
        "send_message_to_thread",
        "approval_mode",
    ): "prompt",
}
_INTERACTIVE_PERMISSION_MODES = {"default", "acceptEdits"}
_MISSING = object()


def protected_tool_error(hook_input: dict[str, Any]) -> str | None:
    """Return a denial reason when a protected tool lacks human approval."""
    if hook_input.get("tool_name") != TASK_MESSAGE_TOOL:
        return None

    permission_mode = hook_input.get("permission_mode")
    if (
        not isinstance(permission_mode, str)
        or permission_mode not in _INTERACTIVE_PERMISSION_MODES
    ):
        return (
            "Codex task messaging requires an interactive permission mode; "
            f"received {permission_mode!r}."
        )

    config_path = _codex_home() / "config.toml"
    project_paths = _project_config_paths(hook_input.get("cwd", "."))
    return approval_config_error(config_path, project_paths)


def approval_config_error(config_path: Path, override_paths: Iterable[Path] = ()) -> str | None:
    """Return the first error in the native human-approval configuration."""
    effective: dict[tuple[str, ...], object] = {}
    seen: set[Path] = set()

    error = _merge_config(config_path, effective, seen)
    if error:
        return error
    error = _contract_error(effective)
    if error:
        return error

    for path in override_paths:
        error = _merge_config(path, effective, seen)
        if error:
            return error
    return _contract_error(effective)


def _merge_config(
    path: Path,
    effective: dict[tuple[str, ...], object],
    seen: set[Path],
) -> str | None:
    path = path.resolve(strict=False)
    if path in seen or not path.exists():
        return None
    seen.add(path)
    try:
        with path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return f"Cannot verify human approval because {path} could not be parsed: {error}"
    for key_path in _APPROVAL_PATHS:
        value = _nested_value(config, key_path)
        if value is not _MISSING:
            effective[key_path] = value
    return None


def _contract_error(effective: dict[tuple[str, ...], object]) -> str | None:
    for key_path, expected in _APPROVAL_PATHS.items():
        actual = effective.get(key_path, _MISSING)
        if actual != expected:
            key = ".".join(key_path)
            rendered = "missing" if actual is _MISSING else repr(actual)
            return (
                f"Codex task messaging is blocked because {key} is {rendered}; "
                f"set it to {expected!r} so native policy requests human approval."
            )
    return None


def _codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


def _project_config_paths(cwd: object) -> list[Path]:
    if not isinstance(cwd, str):
        return []
    current = Path(cwd).resolve(strict=False)
    if not current.is_dir():
        current = current.parent

    project_root = next(
        (candidate for candidate in (current, *current.parents) if (candidate / ".git").exists()),
        None,
    )
    if project_root is None:
        return [current / ".codex" / "config.toml"]

    directories = []
    candidate = current
    while True:
        directories.append(candidate)
        if candidate == project_root:
            break
        candidate = candidate.parent
    return [path / ".codex" / "config.toml" for path in reversed(directories)]


def _nested_value(config: dict[str, Any], path: tuple[str, ...]) -> object:
    value: object = config
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return _MISSING
        value = value[key]
    return value
