#!/usr/bin/env python3
"""Run one argv command only when it matches a user-selected prefix policy."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


def _test_mode() -> bool:
    state_root = os.environ.get("CODEX_ACCESSIBLE_APPROVAL_STATE_DIR")
    if os.environ.get("ACCESSIBLE_APPROVAL_TEST_MODE") != "1" or not state_root:
        return False
    try:
        return Path(state_root).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    except (OSError, RuntimeError):
        return False


def _policy_file() -> Path:
    override = os.environ.get("ACCESSIBLE_APPROVAL_WRAPPER_POLICY_FILE")
    if override is not None:
        if not _test_mode():
            raise RuntimeError(
                "ACCESSIBLE_APPROVAL_WRAPPER_POLICY_FILE is allowed only in isolated test mode."
            )
        state_root = Path(os.environ["CODEX_ACCESSIBLE_APPROVAL_STATE_DIR"]).resolve()
        candidate = Path(override).resolve()
        if not candidate.is_relative_to(state_root.parent):
            raise RuntimeError(
                "ACCESSIBLE_APPROVAL_WRAPPER_POLICY_FILE must stay inside the isolated test root."
            )
        return candidate
    if _test_mode():
        state_root = Path(os.environ["CODEX_ACCESSIBLE_APPROVAL_STATE_DIR"]).resolve()
        return state_root.parent / "defaults" / "command-wrappers.json"
    return Path.home() / ".codex" / "accessible-approvals" / "command-wrappers.json"


POLICY_FILE = _policy_file()
POLICY_ID_RE = re.compile(r"^[a-f0-9]{16}$")


def _read_policy_text() -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(POLICY_FILE, flags)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 10 * 1024 * 1024
        ):
            raise RuntimeError("The command-wrapper policy has unsafe file metadata.")
        return os.read(fd, metadata.st_size + 1).decode("utf-8")
    finally:
        os.close(fd)


def _load_policy() -> dict[str, Any]:
    try:
        data = json.loads(_read_policy_text())
    except FileNotFoundError:
        return {"version": 1, "entries": {}}
    except (json.JSONDecodeError, OSError, UnicodeError) as exc:
        raise RuntimeError("The command-wrapper policy is unreadable.") from exc
    if not isinstance(data, dict) or data.get("version", 1) != 1:
        raise RuntimeError("The command-wrapper policy has an invalid schema.")
    entries = data.get("entries")
    if not isinstance(entries, dict):
        raise RuntimeError("The command-wrapper policy has invalid entries.")
    return {
        "version": 1,
        "entries": entries,
    }


def resolve_command(policy_id: str, command: list[str]) -> list[str]:
    if POLICY_ID_RE.fullmatch(policy_id) is None:
        raise RuntimeError("Invalid approval policy ID.")
    policy = _load_policy()
    entry = policy["entries"].get(policy_id)
    if not isinstance(entry, dict):
        raise RuntimeError("The approval policy is missing or revoked.")
    expected_wrapper_digest = entry.get("wrapperSha256")
    current_wrapper_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if expected_wrapper_digest != current_wrapper_digest:
        raise RuntimeError("The approved command wrapper changed after this policy was created.")
    prefix = entry.get("prefix")
    if (
        not isinstance(prefix, list)
        or not prefix
        or not all(isinstance(token, str) and token for token in prefix)
    ):
        raise RuntimeError("The approval policy contains an invalid command prefix.")
    if command[: len(prefix)] != prefix:
        raise RuntimeError("The command does not match the approved prefix.")
    executable = command[0]
    if "/" in executable:
        resolved = executable
    else:
        resolved = shutil.which(executable) or ""
    if not resolved or not Path(resolved).is_file():
        raise RuntimeError(f"Approved executable is unavailable: {executable}")
    return [resolved, *command[1:]]


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print(
            "Usage: approved_command_wrapper.py POLICY_ID -- COMMAND [ARG ...]",
            file=sys.stderr,
        )
        return 64
    try:
        command = resolve_command(sys.argv[1], sys.argv[3:])
    except RuntimeError as exc:
        print(f"ACCESSIBLE_APPROVAL_WRAPPER_DENIED: {exc}", file=sys.stderr)
        return 77
    os.execv(command[0], command)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
