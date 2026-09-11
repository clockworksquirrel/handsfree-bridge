#!/usr/bin/env python3
"""Accessible, exact-action approvals for Codex and the AppleScript gateway.

The broker fails closed. It keeps the exact action only in a short-lived,
mode-0600 local state record so an explicitly requested similar-command
analysis can operate on more than a hash. The action is removed when analysis
finishes or the record expires.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

import exact_command_scope as command_scopes


MAX_RECORDS = 8
PENDING_TTL_SECONDS = 30 * 60
ANALYSIS_TTL_SECONDS = 4 * 60 * 60
PROPOSAL_TTL_SECONDS = 60 * 60
APPROVED_TTL_SECONDS = 10 * 60
EXTERNAL_SESSION_ID = "accessible-approvals-applescript-gateway"
SAFE_ROUTINE_SHA256 = "43011beb2f2df1c6d2437d348a806e0b6571368f5c0c95a901c4653aba7b2a94"

APPROVAL_RE = re.compile(
    r"^(allow once|allow always and similar|allow always|allow similar|deny)\s+([a-f0-9]{6,12})$",
    re.IGNORECASE,
)
SELECTION_RE = re.compile(
    r"^allow selected\s+([a-f0-9]{6,12})\s+((?:C[1-9][0-9]*)(?:\s*,\s*C[1-9][0-9]*)*)$",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"^[a-f0-9]{32,64}$")
ACTIVE_STATUSES = {
    "pending",
    "approved",
    "always_persisting",
    "exact_persisting",
    "analysis_requested",
    "research_preparing",
    "research_prepared",
    "research_importing",
    "research_ready",
    "research_partial",
    "synthesis_running",
    "proposal_ready",
    "selection_approved",
    "applying",
}


def _state_root() -> Path:
    override = os.environ.get("CODEX_ACCESSIBLE_APPROVAL_STATE_DIR")
    if override:
        candidate = Path(override)
        try:
            isolated = (
                os.environ.get("ACCESSIBLE_APPROVAL_TEST_MODE") == "1"
                and candidate.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
            )
        except (OSError, RuntimeError):
            isolated = False
        if not isolated:
            raise RuntimeError(
                "CODEX_ACCESSIBLE_APPROVAL_STATE_DIR is allowed only in isolated test mode."
            )
        return candidate
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    return codex_home / "accessible-approvals" / "state"


def _session_key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8", "surrogatepass")).hexdigest()


def _canonical_action(tool_name: str, tool_input: Any, execution_context: Any = None) -> bytes:
    action = {"tool_name": tool_name, "tool_input": command_scopes.canonical_input(tool_name, tool_input)}
    if tool_name == "Bash" and execution_context is not None:
        action["execution_context"] = execution_context
    return json.dumps(
        action,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", "surrogatepass")


def _action_digest(action: bytes, salt_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(salt_hex) + action).hexdigest()


def _safe_routine_bash(payload: dict[str, Any]) -> bool:
    """Mirror the existing safe-routine hook so a later deny cannot override it."""
    if payload.get("tool_name") != "Bash":
        return False
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        return False
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    module_path = codex_home / "hooks" / "permission-request-safe-routine.py"
    if not module_path.is_file():
        return False
    try:
        metadata = module_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or hashlib.sha256(module_path.read_bytes()).hexdigest() != SAFE_ROUTINE_SHA256
        ):
            return False
        spec = importlib.util.spec_from_file_location("codex_safe_routine", module_path)
        if spec is None or spec.loader is None:
            return False
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tokens = module._tokenize(tool_input["command"])
        return tokens is not None and bool(module._safe_tokens(tokens))
    except Exception:
        return False


def _load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeError):
        return {"records": []}
    records = data.get("records")
    if not isinstance(records, list):
        return {"records": []}
    return {"records": [record for record in records if isinstance(record, dict)]}


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n"
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _prune(records: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    for record in records:
        created_at = record.get("created_at")
        status = record.get("status")
        if not isinstance(created_at, (int, float)) or status not in ACTIVE_STATUSES:
            continue
        if status == "approved":
            reference = record.get("approved_at", created_at)
            ttl = APPROVED_TTL_SECONDS
        elif status in {"proposal_ready", "selection_approved", "applying"}:
            reference = record.get("proposal_at", created_at)
            ttl = PROPOSAL_TTL_SECONDS
        elif status in {
            "analysis_requested",
            "always_persisting",
            "exact_persisting",
            "research_preparing",
            "research_prepared",
            "research_importing",
            "research_ready",
            "research_partial",
            "synthesis_running",
        }:
            timestamps = [
                record.get("analysis_requested_at"),
                record.get("research_prepared_at"),
                record.get("research_at"),
                record.get("synthesis_started_at"),
            ]
            reference = max(
                (value for value in timestamps if isinstance(value, (int, float))),
                default=created_at,
            )
            ttl = ANALYSIS_TTL_SECONDS
        else:
            reference = created_at
            ttl = PENDING_TTL_SECONDS
        if isinstance(reference, (int, float)) and now - reference <= ttl:
            kept.append(record)
    kept.sort(key=lambda item: float(item.get("created_at", 0)))
    return kept[-MAX_RECORDS:]


def _with_locked_path(path: Path, callback: Callable[[dict[str, Any]], Any]) -> Any:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    lock_path = path.with_suffix(".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(lock_fd, "r+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _load_state(path)
        previous_records = state["records"]
        state["records"] = _prune(previous_records, time.time())
        kept_ids = {id(record) for record in state["records"]}
        for record in previous_records:
            if id(record) not in kept_ids:
                _cleanup_record_files(record)
        callback_records = list(state["records"])
        result = callback(state)
        remaining_ids = {id(record) for record in state["records"]}
        for record in callback_records:
            if id(record) not in remaining_ids:
                _cleanup_record_files(record)
        _write_state(path, state)
        return result


def _with_locked_state(session_id: str, callback: Callable[[dict[str, Any]], Any]) -> Any:
    root = _state_root()
    path = root / f"{_session_key(session_id)}.json"
    return _with_locked_path(path, callback)


def _cleanup_record_files(record: dict[str, Any]) -> None:
    inbox_value = record.get("research_inbox_path")
    if not isinstance(inbox_value, str):
        return
    inbox_root = Path(
        os.environ.get(
            "ACCESSIBLE_APPROVAL_RESEARCH_INBOX_ROOT",
            Path.home() / ".codex" / "accessible-approvals" / "research-inbox",
        )
    )
    inbox_path = Path(inbox_value)
    try:
        if (
            inbox_path.parent.resolve() == inbox_root.resolve()
            and re.fullmatch(r"[a-f0-9]{64}\.json", inbox_path.name)
        ):
            inbox_path.unlink(missing_ok=True)
    except OSError:
        pass


def _prune_all_state_files() -> None:
    root = _state_root()
    if not root.is_dir():
        return
    for path in sorted(root.glob("*.json")):
        _with_locked_path(path, lambda _state: None)


def _with_record_token(
    token: str,
    token_field: str,
    callback: Callable[[dict[str, Any], dict[str, Any]], Any],
) -> Any:
    if TOKEN_RE.fullmatch(token) is None:
        return None
    root = _state_root()
    if not root.is_dir():
        return None
    for path in sorted(root.glob("*.json")):
        def visit(state: dict[str, Any]) -> tuple[bool, Any]:
            for record in state["records"]:
                value = record.get(token_field)
                if isinstance(value, str) and hmac.compare_digest(value, token):
                    return True, callback(state, record)
            return False, None

        found, result = _with_locked_path(path, visit)
        if found:
            return result
    return None


def _new_record(tool_name: str, tool_input: Any, origin: str, execution_context: Any = None) -> dict[str, Any]:
    action = _canonical_action(tool_name, tool_input, execution_context)
    salt = secrets.token_hex(16)
    record = {
        "id": secrets.token_hex(4),
        "salt": salt,
        "digest": _action_digest(action, salt),
        "tool_name": tool_name[:160],
        "origin": origin,
        "action_json": action.decode("utf-8", "surrogatepass"),
        "status": "pending",
        "created_at": time.time(),
    }
    if tool_name == "Bash":
        try:
            record["command_scope"] = command_scopes.build_scope(json.loads(action))
        except command_scopes.UnsupportedScope as error:
            record["exact_unsupported_reason"] = str(error)
        except (OSError, ValueError):
            record["exact_unsupported_reason"] = "The execution scope could not be inspected."
    return record


def _record_matches_action(record: dict[str, Any], action: bytes) -> bool:
    salt = record.get("salt")
    digest = record.get("digest")
    if not isinstance(salt, str) or not isinstance(digest, str):
        return False
    try:
        return hmac.compare_digest(_action_digest(action, salt), digest)
    except ValueError:
        return False


def _approval_message(approval_id: str, record: dict[str, Any] | None = None) -> str:
    exact_supported = record is not None and _has_exact_scope(record)
    similar_supported = record is not None and record.get("tool_name") in {
        "Bash", "mcp__applescript__applescript_execute",
    }
    options = [f"`allow once {approval_id}`"]
    if similar_supported:
        options.append(f"`allow similar {approval_id}`")
    if exact_supported:
        options.extend([f"`allow always {approval_id}`", f"`allow always and similar {approval_id}`"])
    options.append(f"`deny {approval_id}`")
    message = (
        f"ACCESSIBLE_APPROVAL_REQUIRED {approval_id}. The action did not run. "
        "Explain the exact action and target in ordinary chat, why approval is required, "
        "a genuinely safer alternative if one exists, and whether it is reversible. "
        "Supported replies: " + ", ".join(options) + ". "
        "Submit the reply as a user message in the task holding this request. Forwarded "
        "delegation text and model acknowledgments do not register approval. "
    )
    if exact_supported:
        message += "Before offering always, show the exact persistent scope, matches, non-matches, and worst plausible harm. "
    else:
        message += "Saved exact approval is unsupported for this action or its execution context. "
        if record is not None and isinstance(record.get("exact_unsupported_reason"), str):
            message += record["exact_unsupported_reason"] + " "
    if similar_supported:
        message += (
        "Before offering allow similar, explain that it "
        "stores the exact action briefly in a local mode-0600 file, redacts credential values "
        "from research prompts, authorizes a normal paid DeepAPI research workflow, and uses the "
        "local Codex App Server to propose individual candidates from the accepted report. The "
        "original action remains blocked during analysis. Risky families remain eligible, "
        "subject to Codex and administrator limits. ")
    return message + "Do not retry before hook context confirms the answer."


def _analyzer_digest() -> str | None:
    path = Path(__file__).with_name("similar_command_analyzer.py")
    try:
        parts = [hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in (path, Path(__file__), Path(command_scopes.__file__))]
        return hashlib.sha256(json.dumps(parts).encode()).hexdigest()
    except OSError:
        return None


def _has_exact_applescript_scope(record: dict[str, Any]) -> bool:
    if record.get("tool_name") != "mcp__applescript__applescript_execute":
        return False
    action_json = record.get("action_json")
    if not isinstance(action_json, str):
        return False
    try:
        action = json.loads(action_json)
    except json.JSONDecodeError:
        return False
    tool_input = action.get("tool_input") if isinstance(action, dict) else None
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("code_snippet"), str) or not tool_input["code_snippet"]:
        return False
    timeout = tool_input.get("timeout", 60)
    return isinstance(timeout, int) and not isinstance(timeout, bool) and 1 <= timeout <= 600


def _exact_command_scope(record: dict[str, Any]) -> dict[str, Any] | None:
    saved = record.get("command_scope")
    if not isinstance(saved, dict):
        return None
    try:
        current = command_scopes.build_scope(json.loads(record["action_json"]))
        return current if current == saved else None
    except (KeyError, OSError, ValueError, TypeError):
        return None


def _has_exact_scope(record: dict[str, Any]) -> bool:
    return _has_exact_applescript_scope(record) or _exact_command_scope(record) is not None


def _command_policy_path() -> Path:
    return _state_root().parent / "command-policy.json"


def _command_matcher_digest() -> str:
    parts = [hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (Path(__file__), Path(command_scopes.__file__))]
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()


def _load_command_policy() -> dict[str, Any]:
    path = _command_policy_path()
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {"version": 1, "matcherSha256": _command_matcher_digest(), "entries": []}
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 10 * 1024 * 1024):
            raise ValueError("Unsafe command policy metadata.")
        data = json.loads(os.read(fd, metadata.st_size + 1).decode("utf-8"))
    finally:
        os.close(fd)
    if (not isinstance(data, dict) or set(data) != {"version", "matcherSha256", "entries"}
            or data.get("version") != 1 or data.get("matcherSha256") != _command_matcher_digest()
            or not isinstance(data.get("entries"), list)):
        raise ValueError("Invalid or outdated command policy.")
    for entry in data["entries"]:
        scope = entry.get("scope") if isinstance(entry, dict) else None
        if (not isinstance(scope, dict) or set(scope) != {"kind", "actionDigest", "bindingsDigest"}
                or scope.get("kind") != "command_exact"
                or any(not isinstance(scope.get(k), str) or re.fullmatch(r"[a-f0-9]{64}", scope[k]) is None
                       for k in ("actionDigest", "bindingsDigest"))):
            raise ValueError("Malformed saved command scope.")
    return data


def _command_policy_allows(action: dict[str, Any]) -> bool:
    try:
        scope = command_scopes.build_scope(action)
        policy = _load_command_policy()
        return any(entry["scope"] == scope for entry in policy["entries"])
    except (OSError, ValueError, TypeError):
        return False


def _parse_helper_command(payload: dict[str, Any]) -> tuple[str, str] | None:
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        return None
    try:
        tokens = shlex.split(tool_input["command"], posix=True)
    except ValueError:
        return None
    if len(tokens) == 3 and tokens[0] in {"/bin/zsh", "/bin/bash", "/bin/sh"} and tokens[1] in {"-c", "-lc"}:
        try:
            tokens = shlex.split(tokens[2], posix=True)
        except ValueError:
            return None
    analyzer = str(Path(__file__).with_name("similar_command_analyzer.py"))
    if tokens[:2] == ["/usr/bin/python3", analyzer]:
        tokens = tokens[2:]
    elif tokens[:1] == [analyzer]:
        tokens = tokens[1:]
    else:
        return None
    if len(tokens) != 3 or tokens[1] != "--token" or tokens[0] not in {
        "prepare-research",
        "accept-research",
        "persist-exact",
        "synthesize",
        "apply",
    }:
        return None
    if TOKEN_RE.fullmatch(tokens[2]) is None:
        return tokens[0], ""
    return tokens[0], tokens[2]


def _authorize_helper(payload: dict[str, Any]) -> bool | None:
    parsed = _parse_helper_command(payload)
    if parsed is None:
        return None
    operation, token = parsed
    if not token:
        return False
    if operation == "persist-exact":
        def authorize_exact(_state: dict[str, Any], record: dict[str, Any]) -> bool:
            if record.get("status") not in {
                "always_persisting",
                "analysis_requested",
                "research_preparing",
                "research_prepared",
                "research_importing",
                "research_ready",
                "research_partial",
            }:
                return False
            if record.get("analyzer_sha256") != _analyzer_digest():
                return False
            attempts = int(record.get("persist-exact_attempts", 0))
            if attempts >= 1:
                return False
            record["persist-exact_attempts"] = attempts + 1
            record["persist-exact_started_at"] = time.time()
            record["exact_persistence_resume_status"] = record.get("status")
            record["status"] = "exact_persisting"
            return True

        return bool(_with_record_token(token, "exact_persistence_token", authorize_exact))
    field = (
        "analysis_token"
        if operation in {"prepare-research", "accept-research", "synthesize"}
        else "apply_token"
    )
    if operation == "prepare-research":
        valid_statuses = {"analysis_requested", "research_preparing", "research_partial"}
        next_status = "research_preparing"
    elif operation == "accept-research":
        valid_statuses = {"research_prepared", "research_importing", "research_partial"}
        next_status = "research_importing"
    elif operation == "synthesize":
        valid_statuses = {"research_ready", "synthesis_running"}
        next_status = "synthesis_running"
    else:
        valid_statuses = {"selection_approved", "applying"}
        next_status = "applying"

    def authorize(_state: dict[str, Any], record: dict[str, Any]) -> bool:
        if record.get("status") not in valid_statuses:
            return False
        current_analyzer_digest = _analyzer_digest()
        if (
            current_analyzer_digest is None
            or record.get("analyzer_sha256") != current_analyzer_digest
        ):
            return False
        attempts_field = f"{operation}_attempts"
        attempts = int(record.get(attempts_field, 0))
        max_attempts = 1 if operation == "apply" else 2
        if attempts >= max_attempts:
            return False
        record[attempts_field] = attempts + 1
        record["status"] = next_status
        record[f"{operation}_started_at"] = time.time()
        return True

    return bool(_with_record_token(token, field, authorize))


def _permission_request(payload: dict[str, Any]) -> dict[str, Any] | None:
    if _safe_routine_bash(payload):
        return None
    helper_authorized = _authorize_helper(payload)
    if helper_authorized is not None:
        if helper_authorized:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"},
                }
            }
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": (
                        "ACCESSIBLE_APPROVAL_HELPER_UNAUTHORIZED. The analyzer or persistence "
                        "helper did not have a current one-use token. Do not retry it automatically."
                    ),
                },
            }
        }

    session_id = payload.get("session_id")
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(session_id, str) or not session_id or not isinstance(tool_name, str):
        return None
    try:
        execution_context = {"cwd": payload.get("cwd")} if tool_name == "Bash" else None
        action = _canonical_action(tool_name, tool_input, execution_context)
    except (TypeError, ValueError, UnicodeError):
        return None

    if tool_name == "Bash" and _command_policy_allows(json.loads(action)):
        return {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}
    try:
        current_command_scope = command_scopes.build_scope(json.loads(action)) if tool_name == "Bash" else None
    except (OSError, ValueError, TypeError):
        current_command_scope = None

    def decide(state: dict[str, Any]) -> tuple[str, str, str]:
        records = state["records"]
        for index, record in enumerate(records):
            if not _record_matches_action(record, action):
                continue
            if record.get("command_scope") is not None and record["command_scope"] != current_command_scope:
                # A changed executable/environment needs a fresh request, never
                # a replacement scope silently attached to the old approval.
                continue
            approval_id = str(record.get("id", ""))
            if record.get("status") == "approved":
                del records[index]
                return "allow", approval_id, ""
            if record.get("exact_retry_approved") is True:
                record.pop("exact_retry_approved", None)
                record["original_retry_consumed"] = True
                record["original_retry_consumed_at"] = time.time()
                return "allow", approval_id, ""
            return "deny", approval_id, _approval_message(approval_id, record)

        record = _new_record(tool_name, tool_input, "permission_request", execution_context)
        records.append(record)
        state["records"] = _prune(records, time.time())
        return "deny", str(record["id"]), _approval_message(str(record["id"]), record)

    behavior, approval_id, message = _with_locked_state(session_id, decide)
    if behavior == "allow":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "allow"},
            }
        }
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": message},
        }
    }


def request_external_action(tool_name: str, tool_input: Any) -> dict[str, str]:
    """Create or consume an exact-action request for the AppleScript MCP gateway."""
    action = _canonical_action(tool_name, tool_input)

    def decide(state: dict[str, Any]) -> dict[str, str]:
        records = state["records"]
        for index, record in enumerate(records):
            if not _record_matches_action(record, action):
                continue
            approval_id = str(record.get("id", ""))
            if record.get("status") == "approved":
                del records[index]
                return {"behavior": "allow", "id": approval_id}
            if record.get("exact_retry_approved") is True:
                record.pop("exact_retry_approved", None)
                record["original_retry_consumed"] = True
                record["original_retry_consumed_at"] = time.time()
                return {"behavior": "allow", "id": approval_id}
            return {
                "behavior": "deny",
                "id": approval_id,
                "message": _approval_message(approval_id, record),
            }
        record = _new_record(tool_name, tool_input, "applescript_gateway")
        records.append(record)
        state["records"] = _prune(records, time.time())
        approval_id = str(record["id"])
        return {
            "behavior": "deny",
            "id": approval_id,
            "message": _approval_message(approval_id, record),
        }

    return _with_locked_state(EXTERNAL_SESSION_ID, decide)


def _apply_user_choice(
    state: dict[str, Any],
    approval_id: str,
    choice: str,
    selected_ids: list[str] | None,
    external_only: bool,
) -> dict[str, Any]:
    records = state["records"]
    for index, record in enumerate(records):
        if str(record.get("id", "")).lower() != approval_id:
            continue
        if external_only and record.get("origin") != "applescript_gateway":
            continue
        if choice == "deny":
            if record.get("status") in {"applying", "exact_persisting"}:
                return {"result": "busy"}
            del records[index]
            return {"result": "denied"}
        if choice == "allow selected":
            if record.get("status") != "proposal_ready" or not selected_ids:
                return {"result": "unavailable"}
            candidates = record.get("proposal", {}).get("candidates", [])
            available = {
                str(candidate.get("id", "")).upper()
                for candidate in candidates
                if isinstance(candidate, dict) and candidate.get("persistable") is True
            }
            normalized = [candidate_id.upper() for candidate_id in selected_ids]
            if not normalized or any(candidate_id not in available for candidate_id in normalized):
                return {"result": "unavailable"}
            apply_token = secrets.token_hex(24)
            record["selected_candidate_ids"] = list(dict.fromkeys(normalized))
            record["apply_token"] = apply_token
            record["apply_attempts"] = 0
            record["selection_at"] = time.time()
            record["status"] = "selection_approved"
            return {"result": "selection_approved", "token": apply_token}
        if record.get("status") == "proposal_ready":
            return {"result": "unavailable"}
        if choice in {"allow similar", "allow always and similar"} and record.get("status") != "pending":
            return {"result": "unavailable"}
        if record.get("status") not in {"pending", "proposal_ready"}:
            return {"result": "unavailable"}
        if choice == "allow always and similar":
            if not _has_exact_scope(record):
                return {"result": "exact_persistence_unsupported"}
            token = secrets.token_hex(24)
            persistence_token = secrets.token_hex(24)
            analyzer_sha256 = _analyzer_digest()
            if analyzer_sha256 is None:
                return {"result": "unavailable"}
            record["analysis_token"] = token
            record["exact_persistence_token"] = persistence_token
            record["analyzer_sha256"] = analyzer_sha256
            record["analysis_requested_at"] = time.time()
            record["always_requested"] = True
            record["status"] = "analysis_requested"
            return {
                "result": "always_and_analysis_requested",
                "token": token,
                "persistence_token": persistence_token,
            }
        if choice == "allow similar":
            token = secrets.token_hex(24)
            analyzer_sha256 = _analyzer_digest()
            if analyzer_sha256 is None:
                return {"result": "unavailable"}
            record["analysis_token"] = token
            record["analyzer_sha256"] = analyzer_sha256
            record["analysis_requested_at"] = time.time()
            record["status"] = "analysis_requested"
            return {"result": "analysis_requested", "token": token}
        if choice == "allow always":
            if not _has_exact_scope(record):
                return {"result": "exact_persistence_unsupported"}
            persistence_token = secrets.token_hex(24)
            analyzer_sha256 = _analyzer_digest()
            if analyzer_sha256 is None:
                return {"result": "unavailable"}
            record["exact_persistence_token"] = persistence_token
            record["analyzer_sha256"] = analyzer_sha256
            record["always_requested"] = True
            record["status"] = "always_persisting"
            return {
                "result": "always_persistence_requested",
                "persistence_token": persistence_token,
            }
        record["status"] = "approved"
        record["approved_at"] = time.time()
        record.pop("action_json", None)
        return {"result": "approved"}
    return {"result": "unavailable"}


def _user_prompt_submit(payload: dict[str, Any]) -> dict[str, Any] | None:
    session_id = payload.get("session_id")
    prompt = payload.get("prompt")
    if not isinstance(session_id, str) or not session_id or not isinstance(prompt, str):
        return None
    stripped = prompt.strip()
    selection = SELECTION_RE.fullmatch(stripped)
    if selection is not None:
        approval_id = selection.group(1).lower()
        choice = "allow selected"
        selected_ids = [part.strip().upper() for part in selection.group(2).split(",")]
    else:
        match = APPROVAL_RE.fullmatch(stripped)
        if match is None:
            return None
        choice, approval_id = match.group(1).lower(), match.group(2).lower()
        selected_ids = None

    def apply_local(state: dict[str, Any]) -> dict[str, Any]:
        return _apply_user_choice(state, approval_id, choice, selected_ids, False)

    result = _with_locked_state(session_id, apply_local)
    if result.get("result") == "unavailable":
        def apply_external(state: dict[str, Any]) -> dict[str, Any]:
            return _apply_user_choice(state, approval_id, choice, selected_ids, True)

        result = _with_locked_state(EXTERNAL_SESSION_ID, apply_external)

    outcome = result.get("result")
    analyzer = shlex.quote(str(Path(__file__).with_name("similar_command_analyzer.py")))
    if outcome == "approved":
        context = (
            f"ACCESSIBLE_APPROVAL_GRANTED {approval_id}. The user authorized one retry of only "
            "the exact stored action. Retry the identical tool name and arguments once. Do not "
            "broaden or alter it. The approval expires in ten minutes and is consumed before use."
        )
    elif outcome == "denied":
        context = (
            f"ACCESSIBLE_APPROVAL_DENIED {approval_id}. Do not retry that action. Offer a safe, "
            "non-mutating alternative if useful."
        )
    elif outcome == "always_persistence_requested":
        persistence_token = str(result["persistence_token"])
        context = (
            f"ACCESSIBLE_APPROVAL_ALWAYS_GRANTED {approval_id}. The user requested one exact "
            "local digest-and-timeout-bound persistent scope and one identical execution. First run exactly: "
            f"`/usr/bin/python3 {analyzer} persist-exact --token {persistence_token}`. Retry the "
            "identical action only after that helper confirms persistence. Do not invent or widen "
            "the scope. If the helper rejects this action type, keep it blocked."
        )
    elif outcome == "analysis_requested":
        token = str(result["token"])
        context = (
            f"ACCESSIBLE_APPROVAL_SIMILAR_REQUESTED {approval_id}. The original action remains "
            "blocked. The user authorized one normal DeepAPI research workflow using a "
            "credential-redacted action packet and one isolated local Codex App Server analysis. "
            f"First run exactly: `/usr/bin/python3 {analyzer} prepare-research --token {token}`. "
            "Use the normal DeepAPI skill for the actual research, publish its complete report, "
            "write the required public-evidence envelope to the returned mode-0600 inbox path, and "
            "run the returned `accept-research` command. Run `synthesize` only when acceptance "
            f"returns it. Then show every candidate and ask for "
            f"`allow selected {approval_id} C1,C2` or `deny {approval_id}`. Do not execute the "
            "original action or persist any candidate yet."
        )
    elif outcome == "always_and_analysis_requested":
        token = str(result["token"])
        persistence_token = str(result["persistence_token"])
        context = (
            f"ACCESSIBLE_APPROVAL_ALWAYS_AND_SIMILAR_GRANTED {approval_id}. The user authorized "
            "one identical execution, requested one local digest-and-timeout-bound exact persistent scope, and "
            "authorized one normal DeepAPI similar-scope research workflow. First run exactly: "
            f"`/usr/bin/python3 {analyzer} persist-exact --token {persistence_token}`. Retry the "
            "identical action only after that helper confirms persistence. Keep the research record "
            "active. Then run exactly: "
            f"`/usr/bin/python3 {analyzer} prepare-research --token {token}`. Use the normal DeepAPI "
            "skill, publish the complete report, submit the returned public-evidence envelope, and "
            "run the acceptance and synthesis helpers. Broader candidates remain blocked until the "
            f"user replies `allow selected {approval_id} C1,C2`. If the exact retry already ran, do "
            "not run it again after candidate persistence."
        )
    elif outcome == "exact_persistence_unsupported":
        context = (
            f"ACCESSIBLE_APPROVAL_EXACT_PERSISTENCE_UNSUPPORTED {approval_id}. This action type "
            "cannot express the requested exact persistent scope safely. The action remains "
            "blocked. Offer `allow once`, `allow similar`, or `deny`; do not substitute a broader "
            "prefix or wrapper."
        )
    elif outcome == "selection_approved":
        token = str(result["token"])
        context = (
            f"ACCESSIBLE_APPROVAL_SELECTION_GRANTED {approval_id}. The user selected only the "
            "candidate IDs in the pending proposal. Run exactly: `/usr/bin/python3 "
            f"{analyzer} apply --token {token}`. Report the exact rules or guarded AppleScript "
            "entries written. Retry the original action only if the helper says a selected "
            "candidate covers it."
        )
    elif outcome == "busy":
        context = (
            f"ACCESSIBLE_APPROVAL_BUSY {approval_id}. Candidate persistence has already started, "
            "so denial cannot safely race the in-flight transaction. Do not retry, cancel, or "
            "start another apply operation. Wait for the current helper result."
        )
    else:
        context = (
            f"ACCESSIBLE_APPROVAL_UNAVAILABLE {approval_id}. No matching pending approval exists "
            "in this session. Do not run or retry an action based on this message."
        )
    return {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0
    if not isinstance(payload, dict):
        return 0
    _prune_all_state_files()
    event = payload.get("hook_event_name")
    if event == "PermissionRequest":
        output = _permission_request(payload)
    elif event == "UserPromptSubmit":
        output = _user_prompt_submit(payload)
    else:
        output = None
    if output is not None:
        print(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
