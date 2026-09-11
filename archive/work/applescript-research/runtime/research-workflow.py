#!/usr/bin/env python3
"""Run resumable, client-managed DeepAPI research workflows via [SSH_HOST].

This is a compatibility layer for the synchronous 120-second research route.
It does not extend one server-side request. Instead, it runs focused questions,
persists every result, and safely resumes only pending work with stable keys.
Terminal failures and indeterminate outcomes are retained, never auto-reissued.
"""

from __future__ import annotations

import argparse
import concurrent.futures
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any
import uuid


SCHEMA_VERSION = 1
MAX_QUESTIONS = 300
MAX_CONCURRENCY = 300
DEFAULT_CONCURRENCY = "auto"
DEFAULT_FAIL_FAST = True
RATE_LIMIT_PREFLIGHT_RESERVE = 1
RATE_WINDOW_SECONDS = 60
DEFAULT_AUTO_CONTINUE = False
DEFAULT_COORDINATION = {
    "mode": "barrier",
    "compression": "grug",
    "sharedContextChars": 12_000,
}
DEEPAPI_QUESTION_FIELDS = {
    "query",
    "context",
    "instructions",
    "maxCostUsd",
    "dryRun",
    "mode",
}
GRUG_INSTRUCTIONS = (
    "GRUG MODE: terse evidence, fragments okay, no greeting/filler/repetition. "
    "Preserve exact queries, URLs, identifiers, code, numbers, quotations, and citations. "
    "Do not compress or paraphrase literal evidence fields."
)


class WorkflowError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise WorkflowError(f"File not found: {path}") from error
    except json.JSONDecodeError as error:
        raise WorkflowError(f"Invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise WorkflowError(f"Expected a JSON object in {path}.")
    return value


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    os.replace(temporary, path)


@contextmanager
def exclusive_lock(path: Path):
    """Hold an advisory process lock for one workflow or shared rate ledger."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def manifest_hash(manifest: dict[str, Any]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def require_text(
    value: Any,
    field: str,
    *,
    minimum: int = 1,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise WorkflowError(f"{field} must be a string.")
    stripped = value.strip()
    if not minimum <= len(stripped) <= maximum:
        raise WorkflowError(
            f"{field} must contain {minimum}-{maximum} characters after trimming."
        )
    return stripped


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    allowed_top = {
        "name",
        "questions",
        "maxConcurrency",
        "failFast",
        "autoContinue",
        "coordination",
    }
    extras = set(manifest) - allowed_top
    if extras:
        raise WorkflowError(f"Unknown manifest fields: {sorted(extras)}")

    name = require_text(manifest.get("name"), "name", maximum=120)
    questions = manifest.get("questions")
    if not isinstance(questions, list) or not 1 <= len(questions) <= MAX_QUESTIONS:
        raise WorkflowError(f"questions must contain 1-{MAX_QUESTIONS} items.")

    max_concurrency = manifest.get("maxConcurrency", DEFAULT_CONCURRENCY)
    if max_concurrency != "auto" and (
        not isinstance(max_concurrency, int)
        or isinstance(max_concurrency, bool)
        or not 1 <= max_concurrency <= MAX_CONCURRENCY
    ):
        raise WorkflowError(
            f"maxConcurrency must be 'auto' or an integer from 1-{MAX_CONCURRENCY}."
        )
    fail_fast = manifest.get("failFast", DEFAULT_FAIL_FAST)
    if not isinstance(fail_fast, bool):
        raise WorkflowError("failFast must be boolean.")
    auto_continue = manifest.get("autoContinue", DEFAULT_AUTO_CONTINUE)
    if not isinstance(auto_continue, bool):
        raise WorkflowError("autoContinue must be boolean.")
    raw_coordination = manifest.get("coordination", DEFAULT_COORDINATION)
    if not isinstance(raw_coordination, dict):
        raise WorkflowError("coordination must be an object.")
    coordination_extras = set(raw_coordination) - set(DEFAULT_COORDINATION)
    if coordination_extras:
        raise WorkflowError(
            f"Unknown coordination fields: {sorted(coordination_extras)}"
        )
    coordination = {**DEFAULT_COORDINATION, **raw_coordination}
    if coordination["mode"] != "barrier":
        raise WorkflowError("coordination.mode must be 'barrier'.")
    if coordination["compression"] not in {"grug", "none"}:
        raise WorkflowError("coordination.compression must be 'grug' or 'none'.")
    shared_context_chars = coordination["sharedContextChars"]
    if (
        not isinstance(shared_context_chars, int)
        or isinstance(shared_context_chars, bool)
        or not 1_000 <= shared_context_chars <= 14_000
    ):
        raise WorkflowError("coordination.sharedContextChars must be 1000-14000.")

    allowed_question = {
        "id",
        "query",
        "context",
        "instructions",
        "maxCostUsd",
        "dryRun",
        "dependsOn",
        "phase",
        "role",
        "mode",
    }
    normalized_questions: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(questions):
        if not isinstance(raw, dict):
            raise WorkflowError(f"questions[{index}] must be an object.")
        extras = set(raw) - allowed_question
        if extras:
            raise WorkflowError(
                f"questions[{index}] has unknown fields: {sorted(extras)}"
            )
        question_id = require_text(
            raw.get("id"), f"questions[{index}].id", maximum=80
        )
        if not all(character.isalnum() or character in "-_." for character in question_id):
            raise WorkflowError(
                f"questions[{index}].id must use letters, digits, dash, underscore, or dot."
            )
        if question_id in seen_ids:
            raise WorkflowError(f"Duplicate question id: {question_id}")
        seen_ids.add(question_id)

        normalized: dict[str, Any] = {
            "id": question_id,
            "query": require_text(
                raw.get("query"), f"questions[{index}].query", maximum=4_000
            ),
        }
        if raw.get("mode") is not None:
            if raw["mode"] not in {"clean", "raw"}:
                raise WorkflowError("Question mode must be clean or raw.")
            normalized["mode"] = raw["mode"]
        for field, maximum in (("context", 16_000), ("instructions", 8_000)):
            if raw.get(field) is not None:
                normalized[field] = require_text(
                    raw[field], f"questions[{index}].{field}", maximum=maximum
                )
        if raw.get("maxCostUsd") is not None:
            value = raw["maxCostUsd"]
            if not isinstance(value, str) or not re.fullmatch(r"\d+(\.\d{1,6})?", value):
                raise WorkflowError(
                    f"questions[{index}].maxCostUsd must be a decimal string."
                )
            normalized["maxCostUsd"] = value
        if raw.get("dryRun") is not None:
            if not isinstance(raw["dryRun"], bool):
                raise WorkflowError(f"questions[{index}].dryRun must be boolean.")
            normalized["dryRun"] = raw["dryRun"]
        depends_on = raw.get("dependsOn", [])
        if not isinstance(depends_on, list) or not all(
            isinstance(value, str) and value for value in depends_on
        ):
            raise WorkflowError(f"questions[{index}].dependsOn must be a string list.")
        if len(depends_on) != len(set(depends_on)):
            raise WorkflowError(f"questions[{index}].dependsOn contains duplicates.")
        normalized["dependsOn"] = depends_on
        phase = raw.get("phase", 0)
        if (
            not isinstance(phase, int)
            or isinstance(phase, bool)
            or not 0 <= phase <= 99
        ):
            raise WorkflowError(f"questions[{index}].phase must be 0-99.")
        normalized["phase"] = phase
        if raw.get("role") is not None:
            normalized["role"] = require_text(
                raw["role"], f"questions[{index}].role", maximum=80
            )
        normalized_questions.append(normalized)

    known_ids = {question["id"] for question in normalized_questions}
    dependency_map = {
        question["id"]: question["dependsOn"] for question in normalized_questions
    }
    phases = {question["id"]: question["phase"] for question in normalized_questions}
    for question_id, dependencies in dependency_map.items():
        unknown = set(dependencies) - known_ids
        if unknown:
            raise WorkflowError(
                f"Question {question_id} has unknown dependencies: {sorted(unknown)}"
            )
        if question_id in dependencies:
            raise WorkflowError(f"Question {question_id} cannot depend on itself.")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(question_id: str) -> None:
        if question_id in visiting:
            raise WorkflowError(f"Dependency cycle includes {question_id}.")
        if question_id in visited:
            return
        visiting.add(question_id)
        for dependency in dependency_map[question_id]:
            visit(dependency)
        visiting.remove(question_id)
        visited.add(question_id)

    for question_id in dependency_map:
        visit(question_id)
    for question_id, dependencies in dependency_map.items():
        invalid_phases = [
            dependency
            for dependency in dependencies
            if phases[dependency] >= phases[question_id]
        ]
        if invalid_phases:
            raise WorkflowError(
                f"Question {question_id} dependencies must be in an earlier phase: {invalid_phases}"
            )

    return {
        "name": name,
        "questions": normalized_questions,
        "maxConcurrency": max_concurrency,
        "failFast": fail_fast,
        "autoContinue": auto_continue,
        "coordination": coordination,
    }


def initial_state(manifest: dict[str, Any]) -> dict[str, Any]:
    workflow_id = str(uuid.uuid4())
    timestamp = now_iso()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "workflowId": workflow_id,
        "name": manifest["name"],
        "manifestHash": manifest_hash(manifest),
        "coordination": manifest["coordination"],
        "autoContinue": manifest["autoContinue"],
        "status": "pending",
        "createdAt": timestamp,
        "updatedAt": timestamp,
        "scheduler": {
            "requestedConcurrency": manifest["maxConcurrency"],
            "maxConcurrency": None,
            "failFast": manifest["failFast"],
            "rateLimitPerMinute": None,
            "launchBudget": None,
            "deferredCount": 0,
            "stoppedAt": None,
            "stopReason": None,
        },
        "questions": {
            question["id"]: {
                "status": "pending",
                "idempotencyKey": str(uuid.uuid4()),
                "requestId": None,
                "startedAt": None,
                "finishedAt": None,
                "response": None,
                "runnerError": None,
                "dependsOn": question["dependsOn"],
                "phase": question["phase"],
                "role": question.get("role"),
            }
            for question in manifest["questions"]
        },
    }


def parse_response(stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
    candidate = stdout.strip()
    response: dict[str, Any] | None = None
    if candidate:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                response = parsed
        except json.JSONDecodeError:
            response = None
    if response is not None:
        return response
    detail = stderr.strip() or stdout.strip() or f"launcher exited {returncode}"
    return {
        "requestId": None,
        "status": "failed",
        "output": None,
        "error": {
            "code": "local_runner_error",
            "message": detail[-2_000:],
            "retryable": False,
        },
    }


def deepapi_payload(question: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in question.items()
        if key in DEEPAPI_QUESTION_FIELDS
    }


def coordinated_question(
    question: dict[str, Any],
    state: dict[str, Any],
    coordination: dict[str, Any],
) -> dict[str, Any]:
    """Inject compact, completed dependency evidence at a barrier boundary."""

    prepared = dict(question)
    dependencies = question.get("dependsOn", [])
    if dependencies:
        max_chars = coordination["sharedContextChars"]
        base_context = prepared.get("context", "")
        role_prefix = f"ROLE: {question['role']}\n" if question.get("role") else ""
        base_limit = max(1_000, 16_000 - max_chars - len(role_prefix) - 64)
        if len(base_context) > base_limit:
            base_context = base_context[:base_limit] + "\n[base context truncated]"
        remaining = max(
            1_000,
            min(max_chars, 16_000 - len(base_context) - len(role_prefix) - 64),
        )
        per_dependency = max(500, remaining // len(dependencies))
        evidence = []
        for dependency_id in dependencies:
            item = state["questions"][dependency_id]
            response = item.get("response")
            output = response.get("output") if isinstance(response, dict) else None
            record: dict[str, Any] = {
                "taskId": dependency_id,
                "requestId": item.get("requestId"),
            }
            if isinstance(output, dict):
                answer = output.get("answer")
                sources = output.get("sources")
                if isinstance(sources, list):
                    record["sources"] = sources[:10]
                if isinstance(answer, str):
                    record["answer"] = answer[:per_dependency]
                    if len(answer) > per_dependency:
                        record["answerTruncated"] = True
                if output.get("completeness") is not None:
                    record["completeness"] = output["completeness"]
            elif output is not None:
                rendered = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
                record["output"] = rendered[:per_dependency]
            evidence.append(record)
        ledger = json.dumps(
            {"completedDependencies": evidence},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(ledger) > remaining:
            for record in evidence:
                answer = record.get("answer")
                if isinstance(answer, str) and len(answer) > 500:
                    record["answer"] = answer[:500]
                    record["answerTruncated"] = True
                sources = record.get("sources")
                if isinstance(sources, list) and len(sources) > 3:
                    record["sources"] = sources[:3]
                    record["sourcesTruncated"] = True
            envelope = {"completedDependencies": evidence, "ledgerTruncated": True}
            ledger = json.dumps(
                envelope,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            while len(ledger) > remaining:
                largest = max(
                    (
                        record
                        for record in evidence
                        if isinstance(record.get("answer"), str)
                        and len(record["answer"]) > 128
                    ),
                    key=lambda record: len(record["answer"]),
                    default=None,
                )
                if largest is not None:
                    largest["answer"] = largest["answer"][: max(128, len(largest["answer"]) // 2)]
                else:
                    with_sources = next(
                        (
                            record
                            for record in evidence
                            if isinstance(record.get("sources"), list)
                            and record["sources"]
                        ),
                        None,
                    )
                    if with_sources is None:
                        break
                    with_sources["sources"].pop()
                    with_sources["sourcesTruncated"] = True
                ledger = json.dumps(
                    envelope,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            if len(ledger) > remaining:
                ledger = json.dumps(
                    {
                        "completedDependencyIds": dependencies,
                        "ledgerTruncated": True,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
        prepared["context"] = (
            f"{base_context}\n\nCOORDINATION_LEDGER_JSON:\n{ledger}".strip()
        )

    if question.get("role"):
        prefix = f"ROLE: {question['role']}\n"
        prepared["context"] = prefix + prepared.get("context", "")[: 16_000 - len(prefix)]
    if coordination["compression"] == "grug":
        existing = prepared.get("instructions", "")
        existing = existing[: max(0, 8_000 - len(GRUG_INSTRUCTIONS) - 1)]
        prepared["instructions"] = f"{existing}\n{GRUG_INSTRUCTIONS}".strip()
    return prepared


def invoke_question(
    launcher: Path,
    question: dict[str, Any],
    idempotency_key: str,
) -> dict[str, Any]:
    payload = deepapi_payload(question)
    environment = os.environ.copy()
    environment["DEEPAPI_IDEMPOTENCY_KEY"] = idempotency_key
    environment["DEEPAPI_REQUEST_TIMEOUT_SECONDS"] = "0"
    try:
        completed = subprocess.run(
            [str(launcher), "request", "POST", "/v1/research/deep"],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            env=environment,
            timeout=None,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "requestId": None,
            "status": "failed",
            "output": None,
            "error": {
                "code": "client_request_timeout",
                "message": "The client stopped this research call at its absolute 120-second deadline.",
                "retryable": False,
            },
        }
    return parse_response(completed.stdout, completed.stderr, completed.returncode)


def invoke_batch(
    launcher: Path,
    questions: list[dict[str, Any]],
    state: dict[str, Any],
    max_concurrency: int,
    fail_fast: bool,
) -> dict[str, Any]:
    requests = []
    for question in questions:
        question_id = question["id"]
        requests.append(
            {
                "questionId": question_id,
                "idempotencyKey": state["questions"][question_id]["idempotencyKey"],
                "payload": deepapi_payload(question),
            }
        )
    payload = {
        "maxConcurrency": max_concurrency,
        "failFast": fail_fast,
        "requests": requests,
    }
    environment = os.environ.copy()
    environment["DEEPAPI_REQUEST_TIMEOUT_SECONDS"] = "0"
    waves = max(1, math.ceil(len(requests) / max_concurrency))
    workflow_timeout = None
    try:
        completed = subprocess.run(
            [str(launcher), "batch-request", "POST", "/v1/research/deep"],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            env=environment,
            timeout=workflow_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "requestCount": 0,
            "results": [],
            "transportError": {
                "code": "local_batch_deadline_exceeded",
                "message": "The batch transport exceeded its absolute wave deadline; admitted request outcomes are indeterminate.",
            },
        }
    try:
        parsed = json.loads(completed.stdout.strip())
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
        return parsed
    detail = completed.stderr.strip() or completed.stdout.strip()
    return {
        "status": "failed",
        "requestCount": 0,
        "results": [],
        "transportError": {
            "code": "local_batch_transport_error",
            "message": (detail or f"launcher exited {completed.returncode}")[-2_000:],
        },
    }


def uses_default_remote_launcher(launcher: Path) -> bool:
    if os.environ.get("DEEPAPI_DISABLE_REMOTE_BATCH") == "1":
        return False
    return launcher.resolve() == default_launcher().resolve()


def default_rate_ledger() -> Path:
    configured = os.environ.get("DEEPAPI_RATE_LEDGER_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path.home() / ".cache" / "deepapi" / "research-rate-window.json"


def read_live_rate_limit(launcher: Path) -> int:
    completed = subprocess.run(
        [str(launcher), "request", "GET", "/v1/me"],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        timeout=60,
        check=False,
    )
    response = parse_response(completed.stdout, completed.stderr, completed.returncode)
    if response.get("status") != "succeeded":
        error = response.get("error")
        code = error.get("code") if isinstance(error, dict) else "unknown_error"
        raise WorkflowError(f"Could not read the live DeepAPI rate limit: {code}")
    output = response.get("output")
    if not isinstance(output, dict):
        raise WorkflowError("DeepAPI account info did not include output.")
    values: list[int] = []
    for owner in (output.get("apiKey"), output.get("workspace")):
        if isinstance(owner, dict):
            value = owner.get("rateLimitPerMinute")
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                values.append(value)
    if not values:
        raise WorkflowError("DeepAPI account info did not publish a rate limit.")
    return min(values)


def resolve_concurrency_limit(
    launcher: Path,
    requested: int | str,
    question_count: int,
) -> tuple[int, int | None, int, int | None]:
    rate_limit: int | None = None
    launch_budget = question_count
    if not uses_default_remote_launcher(launcher):
        requested_limit = question_count if requested == "auto" else int(requested)
        effective = min(requested_limit, question_count, MAX_CONCURRENCY)
        return effective, None, launch_budget, None

    ledger_path = default_rate_ledger()
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    with exclusive_lock(lock_path):
        now = time.time()
        if ledger_path.exists():
            ledger = read_json(ledger_path)
        else:
            ledger = {"rateLimitPerMinute": None, "reservations": []}
        raw_reservations = ledger.get("reservations")
        reservations = [
            item
            for item in raw_reservations
            if isinstance(raw_reservations, list)
            and isinstance(item, dict)
            and isinstance(item.get("timestamp"), (int, float))
            and isinstance(item.get("count"), int)
            and item["count"] > 0
            and now - float(item["timestamp"]) < RATE_WINDOW_SECONDS
        ] if isinstance(raw_reservations, list) else []
        used = sum(item["count"] for item in reservations)
        cached_limit = ledger.get("rateLimitPerMinute")
        if isinstance(cached_limit, int) and cached_limit > 0 and used >= cached_limit:
            oldest = min(float(item["timestamp"]) for item in reservations)
            retry_after = max(1, math.ceil(RATE_WINDOW_SECONDS - (now - oldest)))
            return 0, cached_limit, 0, retry_after

        rate_limit = read_live_rate_limit(launcher)
        available_after_preflight = max(
            0,
            rate_limit - used - RATE_LIMIT_PREFLIGHT_RESERVE,
        )
        window_budget = min(question_count, available_after_preflight)
        requested_limit = window_budget if requested == "auto" else int(requested)
        effective = min(requested_limit, window_budget, MAX_CONCURRENCY)
        # Reserve and transport one concurrency-sized production wave. Queuing
        # more behind slow calls would let their t0 reservations expire before
        # the later HTTP requests actually start.
        launch_budget = effective
        reservations.append(
            {
                "timestamp": time.time(),
                "count": RATE_LIMIT_PREFLIGHT_RESERVE + launch_budget,
            }
        )
        atomic_write_json(
            ledger_path,
            {
                "rateLimitPerMinute": rate_limit,
                "reservations": reservations,
            },
        )
        retry_after = None
        if (
            launch_budget < question_count
            and available_after_preflight <= launch_budget
            and reservations
        ):
            oldest = min(float(item["timestamp"]) for item in reservations)
            retry_after = max(1, math.ceil(RATE_WINDOW_SECONDS - (time.time() - oldest)))
        return effective, rate_limit, launch_budget, retry_after


def load_or_create_state(
    manifest: dict[str, Any],
    state_path: Path,
    *,
    resume: bool,
) -> dict[str, Any]:
    if state_path.exists():
        if not resume:
            raise WorkflowError(
                f"State already exists: {state_path}. Use --resume to continue it."
            )
        state = read_json(state_path)
        if state.get("schemaVersion") != SCHEMA_VERSION:
            raise WorkflowError("Unsupported workflow state schema version.")
        if state.get("manifestHash") != manifest_hash(manifest):
            raise WorkflowError("Manifest changed since this workflow state was created.")
        recovered = False
        for item in state.get("questions", {}).values():
            if item.get("status") == "running":
                item["status"] = "indeterminate"
                item["finishedAt"] = now_iso()
                item["runnerError"] = (
                    "A prior process ended while this request was running; outcome is indeterminate and will not be retried automatically."
                )
                recovered = True
        if recovered:
            state["updatedAt"] = now_iso()
            atomic_write_json(state_path, state)
        return state
    state = initial_state(manifest)
    atomic_write_json(state_path, state)
    return state


def summarize_state(state: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in state.get("questions", {}).values():
        status = item.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    return {
        "workflowId": state.get("workflowId"),
        "name": state.get("name"),
        "status": state.get("status"),
        "counts": counts,
        "scheduler": state.get("scheduler"),
        "updatedAt": state.get("updatedAt"),
    }


def _run_workflow_unlocked(
    manifest_path: Path,
    state_path: Path,
    launcher: Path,
    *,
    resume: bool,
) -> dict[str, Any]:
    manifest = validate_manifest(read_json(manifest_path))
    if not launcher.is_file():
        raise WorkflowError(f"DeepAPI launcher not found: {launcher}")
    state = load_or_create_state(manifest, state_path, resume=resume)
    lock = threading.Lock()
    questions_by_id = {question["id"]: question for question in manifest["questions"]}
    all_pending_ids = [
        question_id
        for question_id, item in state["questions"].items()
        if item.get("status") == "pending"
    ]
    ready_ids = [
        question_id
        for question_id in all_pending_ids
        if all(
            state["questions"][dependency_id].get("status") == "succeeded"
            for dependency_id in questions_by_id[question_id]["dependsOn"]
        )
    ]
    current_phase = None
    if ready_ids:
        current_phase = min(questions_by_id[question_id]["phase"] for question_id in ready_ids)
    pending_ids = [
        question_id
        for question_id in ready_ids
        if questions_by_id[question_id]["phase"] == current_phase
    ]
    dependency_blocked_ids = [
        question_id for question_id in all_pending_ids if question_id not in pending_ids
    ]
    max_workers = 0
    rate_limit: int | None = None
    launch_budget = 0
    retry_after: int | None = None
    if pending_ids:
        max_workers, rate_limit, launch_budget, retry_after = resolve_concurrency_limit(
            launcher,
            manifest["maxConcurrency"],
            len(pending_ids),
        )
    launch_count = launch_budget if pending_ids else 0
    launch_ids = pending_ids[:launch_count]
    deferred_ids = pending_ids[launch_count:]
    use_remote_batch = bool(launch_ids and uses_default_remote_launcher(launcher))
    prepared_questions = {
        question_id: coordinated_question(
            questions_by_id[question_id], state, manifest["coordination"]
        )
        for question_id in launch_ids
    }

    state["status"] = "running"
    state["scheduler"] = {
        "requestedConcurrency": manifest["maxConcurrency"],
        "maxConcurrency": max_workers,
        "failFast": manifest["failFast"],
        "rateLimitPerMinute": rate_limit,
        "launchBudget": launch_count,
        "deferredCount": len(deferred_ids),
        "retryAfterSecs": retry_after,
        "currentPhase": current_phase,
        "readyCount": len(pending_ids),
        "dependencyBlockedCount": len(dependency_blocked_ids),
        "stoppedAt": None,
        "stopReason": None,
        "transport": (
            "single_ssh_remote_batch" if use_remote_batch else "local_subprocess_pool"
        ),
        "perRequestTimeoutSeconds": None,
    }
    state["updatedAt"] = now_iso()
    atomic_write_json(state_path, state)

    def execute(question_id: str) -> tuple[str, dict[str, Any]]:
        with lock:
            item = state["questions"][question_id]
            item["status"] = "running"
            item["startedAt"] = now_iso()
            item["finishedAt"] = None
            item["runnerError"] = None
            state["updatedAt"] = now_iso()
            atomic_write_json(state_path, state)
            idempotency_key = item["idempotencyKey"]
        response = invoke_question(
            launcher,
            prepared_questions[question_id],
            idempotency_key,
        )
        return question_id, response

    def record_result(
        question_id: str,
        response: dict[str, Any] | None,
        runner_error: str | None = None,
    ) -> dict[str, Any] | None:
        with lock:
            item = state["questions"][question_id]
            item["response"] = response
            item["requestId"] = response.get("requestId") if response else None
            item["runnerError"] = runner_error
            item["finishedAt"] = now_iso()
            succeeded = bool(
                response and response.get("status") == "succeeded"
            )
            validated = bool(response and response.get("status") == "dry_run")
            item["status"] = (
                "succeeded" if succeeded else ("validated" if validated else "failed")
            )
            failure = None
            if not succeeded and not validated:
                response_error = (
                    response.get("error") if isinstance(response, dict) else None
                )
                failure = {
                    "code": "first_error",
                    "questionId": question_id,
                    "errorCode": (
                        response_error.get("code")
                        if isinstance(response_error, dict)
                        else "runner_exception"
                    ),
                }
            state["updatedAt"] = now_iso()
            atomic_write_json(state_path, state)
            return failure

    def stop_after_failure(failure: dict[str, Any] | None) -> None:
        if (
            failure is not None
            and manifest["failFast"]
            and state["scheduler"]["stopReason"] is None
        ):
            with lock:
                state["scheduler"]["stoppedAt"] = now_iso()
                state["scheduler"]["stopReason"] = failure
                state["updatedAt"] = now_iso()
                atomic_write_json(state_path, state)

    pending_iterator = iter(launch_ids)

    def submit_next(
        executor: concurrent.futures.ThreadPoolExecutor,
        active: dict[concurrent.futures.Future, str],
    ) -> bool:
        try:
            question_id = next(pending_iterator)
        except StopIteration:
            return False
        active[executor.submit(execute, question_id)] = question_id
        return True

    if launch_ids and use_remote_batch:
        with lock:
            for question_id in launch_ids:
                item = state["questions"][question_id]
                item["status"] = "running"
                item["startedAt"] = now_iso()
                item["finishedAt"] = None
                item["runnerError"] = None
            state["updatedAt"] = now_iso()
            atomic_write_json(state_path, state)
        batch = invoke_batch(
            launcher,
            [prepared_questions[question_id] for question_id in launch_ids],
            state,
            max_workers,
            manifest["failFast"],
        )
        state["scheduler"]["batchRequestCount"] = batch.get("requestCount", 0)
        batch_deferred = {
            question_id
            for question_id in batch.get("deferredQuestionIds", [])
            if isinstance(question_id, str)
        }
        state["scheduler"]["batchDeferredCount"] = len(batch_deferred)
        entries = {
            entry.get("questionId"): entry
            for entry in batch.get("results", [])
            if isinstance(entry, dict) and isinstance(entry.get("questionId"), str)
        }
        transport_error = batch.get("transportError")
        first_failure = None
        for question_id in launch_ids:
            entry = entries.get(question_id)
            if entry is not None and isinstance(entry.get("response"), dict):
                response = entry["response"]
                runner_error = None
                failure = record_result(question_id, response, runner_error)
                if first_failure is None and failure is not None:
                    first_failure = failure
            elif question_id in batch_deferred:
                with lock:
                    item = state["questions"][question_id]
                    item["status"] = "pending"
                    item["startedAt"] = None
                    item["finishedAt"] = None
                    item["runnerError"] = None
                    state["updatedAt"] = now_iso()
                    atomic_write_json(state_path, state)
            else:
                message = (
                    transport_error.get("message")
                    if isinstance(transport_error, dict)
                    else "The remote batch did not return this question."
                )
                response = {
                    "requestId": None,
                    "status": "failed",
                    "output": None,
                    "error": {
                        "code": "local_batch_transport_error",
                        "message": message,
                        "retryable": False,
                    },
                }
                with lock:
                    item = state["questions"][question_id]
                    item["status"] = "indeterminate"
                    item["response"] = response
                    item["requestId"] = None
                    item["runnerError"] = message
                    item["finishedAt"] = now_iso()
                    state["updatedAt"] = now_iso()
                    atomic_write_json(state_path, state)
                if first_failure is None:
                    first_failure = {
                        "code": "indeterminate_transport",
                        "questionId": question_id,
                        "errorCode": "local_batch_transport_error",
                    }
        stop_after_failure(first_failure)
    elif launch_ids:
        if launch_ids:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                active: dict[concurrent.futures.Future, str] = {}
                for _ in range(max_workers):
                    submit_next(executor, active)

                while active:
                    done, _ = concurrent.futures.wait(
                        active,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    completed_count = 0
                    first_failure: dict[str, Any] | None = None
                    for future in done:
                        question_id = active.pop(future)
                        try:
                            _, response = future.result()
                            runner_error = None
                        except Exception as error:  # Preserve state before surfacing.
                            response = None
                            runner_error = f"{type(error).__name__}: {error}"
                        failure = record_result(question_id, response, runner_error)
                        if first_failure is None and failure is not None:
                            first_failure = failure
                        completed_count += 1

                    stop_after_failure(first_failure)

                    if state["scheduler"]["stopReason"] is None:
                        for _ in range(completed_count):
                            if not submit_next(executor, active):
                                break
    if deferred_ids and state["scheduler"]["stopReason"] is None:
        state["scheduler"]["stoppedAt"] = now_iso()
        state["scheduler"]["stopReason"] = {
            "code": (
                "rate_window_budget"
                if isinstance(retry_after, int)
                else "concurrency_wave"
            ),
            "deferredQuestions": len(deferred_ids),
        }
        state["updatedAt"] = now_iso()
        atomic_write_json(state_path, state)
    elif (
        all_pending_ids
        and not launch_ids
        and not deferred_ids
        and state["scheduler"]["stopReason"] is None
    ):
        state["scheduler"]["stoppedAt"] = now_iso()
        state["scheduler"]["stopReason"] = {
            "code": "dependency_blocked",
            "blockedQuestions": len(dependency_blocked_ids),
        }
        state["updatedAt"] = now_iso()
        atomic_write_json(state_path, state)

    statuses = [item["status"] for item in state["questions"].values()]
    if all(status == "succeeded" for status in statuses):
        state["status"] = "succeeded"
    elif any(status == "succeeded" for status in statuses):
        state["status"] = "partial"
    elif any(status == "validated" for status in statuses) and all(
        status in {"validated", "pending"} for status in statuses
    ):
        state["status"] = "validated"
    elif statuses and all(status == "pending" for status in statuses):
        state["status"] = "pending"
    else:
        state["status"] = "failed"
    state["updatedAt"] = now_iso()
    atomic_write_json(state_path, state)
    return state


def run_workflow(
    manifest_path: Path,
    state_path: Path,
    launcher: Path,
    *,
    resume: bool,
) -> dict[str, Any]:
    lock_path = state_path.with_suffix(state_path.suffix + ".lock")
    with exclusive_lock(lock_path):
        manifest = validate_manifest(read_json(manifest_path))
        current_resume = resume
        while True:
            state = _run_workflow_unlocked(
                manifest_path,
                state_path,
                launcher,
                resume=current_resume,
            )
            if not manifest["autoContinue"]:
                return state
            pending = any(
                item.get("status") == "pending"
                for item in state["questions"].values()
            )
            if not pending:
                return state
            stop_reason = state.get("scheduler", {}).get("stopReason")
            stop_code = stop_reason.get("code") if isinstance(stop_reason, dict) else None
            if stop_code in {"first_error", "indeterminate_transport", "dependency_blocked"}:
                return state
            retry_after = state.get("scheduler", {}).get("retryAfterSecs")
            if stop_code == "rate_window_budget" and isinstance(retry_after, int):
                time.sleep(max(1, min(retry_after, RATE_WINDOW_SECONDS)))
            current_resume = True


def start_detached(
    manifest_path: Path,
    state_path: Path,
    launcher: Path,
    *,
    resume: bool,
) -> dict[str, Any]:
    if state_path.exists() and not resume:
        raise WorkflowError(
            f"State already exists: {state_path}. Use --resume to continue it."
        )
    log_path = state_path.with_suffix(state_path.suffix + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run",
        "--manifest",
        str(manifest_path),
        "--state",
        str(state_path),
        "--launcher",
        str(launcher),
    ]
    if resume:
        command.append("--resume")
    with log_path.open("ab") as log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    return {
        "status": "started",
        "pid": process.pid,
        "state": str(state_path),
        "log": str(log_path),
    }


def default_launcher() -> Path:
    return Path(__file__).resolve().with_name("remote-deepapi.sh")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("run", "start"):
        command = subparsers.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--state", type=Path, required=True)
        command.add_argument("--launcher", type=Path, default=default_launcher())
        command.add_argument("--resume", action="store_true")

    status = subparsers.add_parser("status")
    status.add_argument("--state", type=Path, required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "status":
            result = summarize_state(read_json(arguments.state))
        elif arguments.command == "start":
            result = start_detached(
                arguments.manifest.resolve(),
                arguments.state.resolve(),
                arguments.launcher.resolve(),
                resume=arguments.resume,
            )
        else:
            state = run_workflow(
                arguments.manifest.resolve(),
                arguments.state.resolve(),
                arguments.launcher.resolve(),
                resume=arguments.resume,
            )
            result = summarize_state(state)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except WorkflowError as error:
        print(json.dumps({"status": "error", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
