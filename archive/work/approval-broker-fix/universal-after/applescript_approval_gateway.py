#!/usr/bin/env python3
"""Approval-enforcing MCP gateway for Peakmojo's AppleScript tool."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import logging
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from pydantic import AnyUrl


logger = logging.getLogger("accessible_applescript_gateway")
BROKER_PATH = Path(__file__).with_name("accessible_approval_broker.py")


def _test_mode() -> bool:
    state_root = os.environ.get("CODEX_ACCESSIBLE_APPROVAL_STATE_DIR")
    if os.environ.get("ACCESSIBLE_APPROVAL_TEST_MODE") != "1" or not state_root:
        return False
    try:
        return Path(state_root).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    except (OSError, RuntimeError):
        return False


def _test_only_value(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None:
        if _test_mode() and name == "ACCESSIBLE_APPROVAL_APPLESCRIPT_POLICY_FILE":
            state_root = Path(os.environ["CODEX_ACCESSIBLE_APPROVAL_STATE_DIR"]).resolve()
            return str(state_root.parent / "defaults" / "applescript-policy.json")
        return default
    if not _test_mode():
        raise RuntimeError(f"{name} is allowed only in isolated test mode.")
    state_root = Path(os.environ["CODEX_ACCESSIBLE_APPROVAL_STATE_DIR"]).resolve()
    candidate = Path(value).resolve()
    if not candidate.is_relative_to(state_root.parent):
        raise RuntimeError(f"{name} must stay inside the isolated test root.")
    return str(candidate)


POLICY_FILE = Path(_test_only_value(
    "ACCESSIBLE_APPROVAL_APPLESCRIPT_POLICY_FILE",
    str(Path.home() / ".codex" / "accessible-approvals" / "applescript-policy.json"),
))
OSASCRIPT = _test_only_value("ACCESSIBLE_APPROVAL_OSASCRIPT", "/usr/bin/osascript")


def _load_broker() -> Any:
    spec = importlib.util.spec_from_file_location("accessible_approval_broker", BROKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load approval broker at {BROKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _normalize_code(code: str) -> str:
    return code.replace("\r\n", "\n").replace("\r", "\n")


def _code_digest(code: str) -> str:
    return hashlib.sha256(_normalize_code(code).encode("utf-8", "surrogatepass")).hexdigest()


def _gateway_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


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
            raise RuntimeError("The AppleScript approval policy has unsafe file metadata.")
        return os.read(fd, metadata.st_size + 1).decode("utf-8")
    finally:
        os.close(fd)


def _load_policy() -> dict[str, Any]:
    try:
        data = json.loads(_read_policy_text())
    except FileNotFoundError:
        return {"version": 1, "allowAll": False, "entries": []}
    except (json.JSONDecodeError, OSError, UnicodeError):
        return {"version": 1, "allowAll": False, "entries": [], "invalid": True}
    if (
        not isinstance(data, dict)
        or data.get("version", 1) != 1
        or data.get("gatewaySha256") != _gateway_digest()
    ):
        return {"version": 1, "allowAll": False, "entries": [], "invalid": True}
    allow_all = data.get("allowAll", False)
    entries = data.get("entries")
    if not isinstance(allow_all, bool) or (entries is not None and not isinstance(entries, list)):
        return {"version": 1, "allowAll": False, "entries": [], "invalid": True}
    clean_entries = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            return {"version": 1, "allowAll": False, "entries": [], "invalid": True}
        digest = entry.get("digest")
        timeout = entry.get("maxTimeout")
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", digest) is None
            or not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= 600
        ):
            return {"version": 1, "allowAll": False, "entries": [], "invalid": True}
        clean_entries.append(entry)
    return {
        "version": 1,
        "allowAll": allow_all,
        "entries": clean_entries,
    }


def policy_allows(code: str, timeout: int) -> tuple[bool, str]:
    policy = _load_policy()
    if policy.get("invalid") is True:
        return False, "approval policy is invalid"
    if policy["allowAll"]:
        return True, "unrestricted applescript_execute scope"
    digest = _code_digest(code)
    for entry in policy["entries"]:
        if entry.get("digest") != digest:
            continue
        max_timeout = entry.get("maxTimeout")
        if isinstance(max_timeout, int) and not isinstance(max_timeout, bool) and timeout <= max_timeout:
            return True, f"exact AppleScript candidate {entry.get('candidateId', 'unknown')}"
    return False, "no persistent AppleScript scope matched"


def approval_decision(arguments: dict[str, Any]) -> dict[str, str]:
    code = arguments.get("code_snippet")
    timeout = arguments.get("timeout", 60)
    if not isinstance(code, str) or not code:
        return {
            "behavior": "deny",
            "id": "",
            "message": "ACCESSIBLE_APPROVAL_INVALID. code_snippet must be a non-empty string.",
        }
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 600:
        return {
            "behavior": "deny",
            "id": "",
            "message": "ACCESSIBLE_APPROVAL_INVALID. timeout must be an integer from 1 to 600 seconds.",
        }
    allowed, scope = policy_allows(code, timeout)
    if allowed:
        return {"behavior": "allow", "id": "", "scope": scope}
    broker = _load_broker()
    return broker.request_external_action(
        "mcp__applescript__applescript_execute",
        {"code_snippet": code, "timeout": timeout},
    )


async def execute_applescript(code: str, timeout: int) -> str:
    fd, temp_name = tempfile.mkstemp(suffix=".scpt")
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(code.encode("utf-8", "surrogatepass"))
            handle.flush()
            os.fsync(handle.fileno())
        proc = await asyncio.create_subprocess_exec(
            OSASCRIPT,
            str(temp_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"AppleScript execution timed out after {timeout} seconds"
        if proc.returncode != 0:
            return f"AppleScript execution failed: {stderr.decode('utf-8', 'replace')}"
        return stdout.decode("utf-8", "replace")
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "WARNING"))
    return parser.parse_args()


async def main() -> None:
    args = _parse_arguments()
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.WARNING),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    server = Server("accessible-applescript-mcp")

    @server.list_resources()
    async def handle_list_resources() -> list[types.Resource]:
        return []

    @server.read_resource()
    async def handle_read_resource(uri: AnyUrl) -> str:
        return ""

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="applescript_execute",
                description=(
                    "Run AppleScript on this Mac through the accessible approval gateway. Unknown "
                    "scripts remain blocked until the user chooses allow once, allow similar, or "
                    "allow always in chat. Persisted exact-script hashes or an explicitly selected "
                    "unrestricted tool scope may run without another prompt. This tool can control "
                    "applications, files, shell commands, personal data, and communications."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code_snippet": {
                            "type": "string",
                            "description": "AppleScript source to execute.",
                        },
                        "timeout": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 600,
                            "description": "Execution timeout in seconds. Defaults to 60.",
                        },
                    },
                    "required": ["code_snippet"],
                },
            )
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str,
        arguments: dict[str, Any] | None,
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        if name != "applescript_execute":
            return [types.TextContent(type="text", text=f"Error: unknown tool {name}")]
        supplied = arguments or {}
        decision = approval_decision(supplied)
        if decision.get("behavior") != "allow":
            return [
                types.TextContent(
                    type="text",
                    text=decision.get("message", "ACCESSIBLE_APPROVAL_REQUIRED. The action did not run."),
                )
            ]
        code = supplied["code_snippet"]
        timeout = supplied.get("timeout", 60)
        output = await execute_applescript(code, timeout)
        return [types.TextContent(type="text", text=output)]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="accessible-applescript-mcp",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
