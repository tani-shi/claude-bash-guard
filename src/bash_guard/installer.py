"""Install/uninstall bash-guard hooks into Claude Code settings."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

SETTINGS_PATH = Path.home() / ".claude" / "settings.json"

HOOK_ENTRIES = [
    {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": "bash-guard",
            }
        ],
    }
]


def install(settings_path: Path | None = None) -> str:
    """Install bash-guard hooks into Claude Code settings.

    Creates a backup before modifying settings.
    Returns a status message.
    """
    path = settings_path or SETTINGS_PATH
    settings = _load_settings(path)

    # Backup
    if path.exists():
        backup = path.with_suffix(".json.bak")
        shutil.copy2(path, backup)

    # Merge hooks
    hooks = settings.setdefault("hooks", {})

    for event_name in ("PreToolUse", "PermissionRequest"):
        existing = hooks.get(event_name, [])

        # Check if already installed
        already_installed = any(
            hook.get("command") == "bash-guard"
            for entry in existing
            for hook in entry.get("hooks", [])
        )
        if already_installed:
            continue

        existing.extend(HOOK_ENTRIES)
        hooks[event_name] = existing

    _save_settings(path, settings)
    return f"bash-guard hooks installed to {path}"


def uninstall(settings_path: Path | None = None) -> str:
    """Remove bash-guard hooks from Claude Code settings.

    Returns a status message.
    """
    path = settings_path or SETTINGS_PATH
    settings = _load_settings(path)

    hooks = settings.get("hooks", {})
    modified = False

    for event_name in ("PreToolUse", "PermissionRequest"):
        existing = hooks.get(event_name, [])
        filtered = [
            entry
            for entry in existing
            if not any(
                hook.get("command") == "bash-guard" for hook in entry.get("hooks", [])
            )
        ]
        if len(filtered) != len(existing):
            modified = True
            if filtered:
                hooks[event_name] = filtered
            else:
                del hooks[event_name]

    if modified:
        _save_settings(path, settings)
        return f"bash-guard hooks removed from {path}"
    return "bash-guard hooks not found in settings"


def _load_settings(path: Path) -> dict:
    """Load settings from JSON file."""
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _save_settings(path: Path, settings: dict) -> None:
    """Save settings to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
