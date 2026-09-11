"""Read the user's broker mode. This module never writes grants or executes actions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat


class PolicyError(ValueError):
    pass


def policy_path(state_root: Path) -> Path:
    return state_root.parent / "broker-policy.json"


def mode(state_root: Path) -> str:
    path = policy_path(state_root)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return "prompt"
    except OSError as error:
        raise PolicyError("The broker policy cannot be read safely.") from error
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 65536):
            raise PolicyError("The broker policy has unsafe file metadata.")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            data = json.load(handle)
    except (OSError, UnicodeError, ValueError) as error:
        raise PolicyError("The broker policy is invalid.") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if (not isinstance(data, dict) or set(data) != {"version", "mode"}
            or type(data.get("version")) is not int or data["version"] != 1
            or data.get("mode") not in {"prompt", "no_prompt"}):
        raise PolicyError("The broker policy has an unsupported schema or mode.")
    return data["mode"]
