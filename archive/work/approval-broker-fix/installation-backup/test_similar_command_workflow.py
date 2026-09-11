#!/usr/bin/env python3
"""Isolated regression test for the normal-DeepAPI similar-command workflow."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BROKER_PATH = SCRIPT_DIR / "accessible_approval_broker.py"
ANALYZER_PATH = SCRIPT_DIR / "similar_command_analyzer.py"


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helper_payload(operation: str, token: str) -> dict[str, Any]:
    return {
        "tool_name": "Bash",
        "tool_input": {
            "command": f"/usr/bin/python3 {ANALYZER_PATH} {operation} --token {token}",
        },
    }


def begin_similar(broker: Any, action: dict[str, Any]) -> tuple[str, str, str]:
    request = broker.request_external_action("mcp__applescript__applescript_execute", action)
    approval_id = request["id"]
    hook = broker._user_prompt_submit(
        {"session_id": "isolated-test-session", "prompt": f"allow similar {approval_id}"}
    )
    context = hook["hookSpecificOutput"]["additionalContext"]
    match = re.search(r"prepare-research --token ([a-f0-9]{32,64})", context)
    if match is None:
        raise AssertionError("Broker did not return a prepare-research token")
    return approval_id, match.group(1), context


def begin_always_and_similar(
    broker: Any,
    action: dict[str, Any],
) -> tuple[str, str, str, str]:
    request = broker.request_external_action("mcp__applescript__applescript_execute", action)
    approval_id = request["id"]
    hook = broker._user_prompt_submit(
        {
            "session_id": "isolated-test-session",
            "prompt": f"allow always and similar {approval_id}",
        }
    )
    context = hook["hookSpecificOutput"]["additionalContext"]
    match = re.search(r"prepare-research --token ([a-f0-9]{32,64})", context)
    persistence_match = re.search(r"persist-exact --token ([a-f0-9]{32,64})", context)
    if match is None or persistence_match is None:
        raise AssertionError("Broker did not return both combined-flow tokens")
    return approval_id, match.group(1), persistence_match.group(1), context


def authorize(broker: Any, operation: str, token: str) -> None:
    if broker._authorize_helper(helper_payload(operation, token)) is not True:
        raise AssertionError(f"Broker did not authorize {operation}")


def evidence_envelope(
    prepared: dict[str, Any],
    *,
    status: str,
    completeness: str,
    terminal_status: str,
    source: str,
    request_id: str,
    workflow_id: str | None = None,
) -> dict[str, Any]:
    provenance = f"DeepAPI request {request_id}"
    workflow_ids = [] if workflow_id is None else [workflow_id]
    if workflow_id is not None:
        provenance += f" in workflow {workflow_id}"
    report = (
        f"{provenance} used the direct source {source}. "
        f"Approval binding {prepared['reportSchema']['approvalBinding']}. "
        "The published report explains the exact action semantics, persistent scope, safer "
        "alternatives, non-matching actions, rollback behavior, and worst plausible harm. "
        "It separates sourced facts from inference and preserves unresolved uncertainty. "
        "This repeated detail makes the isolated fixture long enough to exercise the complete "
        "report gate without pretending that a one-line assertion is sufficient evidence."
    )
    schema = prepared["reportSchema"]
    return {
        "approvalId": schema["approvalId"],
        "researchNonce": schema["researchNonce"],
        "packetDigest": schema["packetDigest"],
        "approvalBinding": schema["approvalBinding"],
        "status": status,
        "completeness": completeness,
        "terminalStatus": terminal_status,
        "report": report,
        "sources": [source],
        "requestIds": [request_id],
        "workflowIds": workflow_ids,
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="accessible-similar-test.") as temporary:
        root = Path(temporary)
        os.environ["CODEX_ACCESSIBLE_APPROVAL_STATE_DIR"] = str(root / "state")
        os.environ["ACCESSIBLE_APPROVAL_RESEARCH_INBOX_ROOT"] = str(root / "research-inbox")
        os.environ["ACCESSIBLE_APPROVAL_RULES_FILE"] = str(root / "rules" / "default.rules")
        os.environ["ACCESSIBLE_APPROVAL_APPLESCRIPT_POLICY_FILE"] = str(root / "applescript-policy.json")
        os.environ["ACCESSIBLE_APPROVAL_WRAPPER_POLICY_FILE"] = str(root / "command-wrappers.json")
        os.environ["ACCESSIBLE_APPROVAL_BACKUP_ROOT"] = str(root / "backups")
        os.environ["ACCESSIBLE_APPROVAL_PERSISTENCE_LOCK_FILE"] = str(root / "persistence.lock")
        os.environ["ACCESSIBLE_APPROVAL_TEST_MODE"] = "1"
        os.environ["ACCESSIBLE_APPROVAL_PROVENANCE_FIXTURE"] = json.dumps(
            [
                "request-test-1",
                "request-test-partial",
                "request-test-invalid",
                "request-test-combined",
                "request-test-replay-a",
                "request-test-replay-b",
                "request-test-private",
                "request-test-short",
            ]
        )

        proposal_fixture = root / "proposal.json"
        proposal_fixture.write_text(
            json.dumps(
                {
                    "researchSummary": "Primary sources support an exact-script scope.",
                    "originalRisk": "The script can register a persistent user service.",
                    "candidates": [
                        {
                            "id": "C1",
                            "title": "Exact AppleScript",
                            "kind": "applescript_exact",
                            "persistentScope": "Only the exact original AppleScript.",
                            "matches": ["The exact normalized script within the timeout."],
                            "doesNotMatch": ["Changed scripts or longer timeouts."],
                            "worstCase": "A replaced fixed target could gain user persistence.",
                            "riskLevel": "high",
                            "prefix": [],
                            "appleScriptCode": "",
                            "maxTimeout": 60,
                            "useOriginalAction": True,
                            "evidenceUrls": ["https://example.com/reference"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        os.environ["ACCESSIBLE_APPROVAL_APP_SERVER_FIXTURE"] = str(proposal_fixture)

        broker = load_module("accessible_approval_broker_test", BROKER_PATH)
        analyzer = load_module("similar_command_analyzer_test", ANALYZER_PATH)
        isolated_default = analyzer._configured_path(
            "ACCESSIBLE_APPROVAL_UNUSED_TEST_PATH",
            Path.home() / ".codex" / "live-policy.json",
        )
        assert isolated_default.resolve().is_relative_to(root.resolve())
        fake_secret = "Bearer TEST_SECRET_VALUE_123456"
        action = {
            "code_snippet": "do shell script \"/bin/launchctl bootstrap gui/501 /tmp/example.plist\"",
            "timeout": 60,
            "authorization": fake_secret,
        }

        approval_id, token, context = begin_similar(broker, action)
        assert "normal DeepAPI research workflow" in context
        authorize(broker, "prepare-research", token)
        prepared = analyzer.prepare_research(token)
        packet_json = json.dumps(prepared["researchPacket"], ensure_ascii=False)
        assert "TEST_SECRET_VALUE_123456" not in packet_json
        assert analyzer.REDACTION in packet_json
        report_path = Path(prepared["reportPath"])
        assert report_path.is_file()
        assert report_path.stat().st_mode & 0o777 == 0o600

        analyzer._atomic_write(
            report_path,
            json.dumps(evidence_envelope(
                prepared,
                status="succeeded",
                completeness="complete",
                terminal_status="FINISHED",
                source="https://example.com/reference",
                request_id="request-test-1",
                workflow_id="workflow-test-1",
            ))
            + "\n",
            0o600,
        )
        authorize(broker, "accept-research", token)
        accepted = analyzer.accept_research(token)
        assert accepted["deepapi"]["completeness"] == "complete"
        assert accepted["nextCommand"].endswith(f"synthesize --token {token}")
        assert not report_path.exists()

        authorize(broker, "synthesize", token)
        synthesized = analyzer.synthesize(token)
        candidates = synthesized["proposal"]["candidates"]
        assert candidates[0]["id"] == "C1"
        assert candidates[0]["persistable"] is True
        assert candidates[0]["coversOriginal"] is True
        stale_choice = broker._user_prompt_submit(
            {"session_id": "isolated-test-session", "prompt": f"allow once {approval_id}"}
        )
        assert "ACCESSIBLE_APPROVAL_UNAVAILABLE" in (
            stale_choice["hookSpecificOutput"]["additionalContext"]
        )
        failed_selection = broker._user_prompt_submit(
            {
                "session_id": "isolated-test-session",
                "prompt": f"allow selected {approval_id} C1",
            }
        )
        failed_apply_match = re.search(
            r"apply --token ([a-f0-9]{32,64})",
            failed_selection["hookSpecificOutput"]["additionalContext"],
        )
        if failed_apply_match is None:
            raise AssertionError("Broker did not return the failed-apply test token")
        failed_apply_token = failed_apply_match.group(1)
        failed_policy = Path(os.environ["ACCESSIBLE_APPROVAL_APPLESCRIPT_POLICY_FILE"])
        failed_policy.parent.mkdir(parents=True, exist_ok=True)
        failed_policy.write_text("{not-json", encoding="utf-8")
        os.chmod(failed_policy, 0o600)
        authorize(broker, "apply", failed_apply_token)
        try:
            analyzer.apply_selected(failed_apply_token)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Malformed policy did not fail candidate application")
        failed_policy.unlink()
        post_failure_deny = broker._user_prompt_submit(
            {"session_id": "isolated-test-session", "prompt": f"deny {approval_id}"}
        )
        assert "ACCESSIBLE_APPROVAL_DENIED" in (
            post_failure_deny["hookSpecificOutput"]["additionalContext"]
        )

        partial_id, partial_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"partial\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", partial_token)
        partial = analyzer.prepare_research(partial_token)
        partial_path = Path(partial["reportPath"])
        analyzer._atomic_write(
            partial_path,
            json.dumps(evidence_envelope(
                partial,
                status="partial",
                completeness="partial",
                terminal_status="PARTIAL",
                source="https://example.com/partial",
                request_id="request-test-partial",
            ))
            + "\n",
            0o600,
        )
        authorize(broker, "accept-research", partial_token)
        partial_result = analyzer.accept_research(partial_token)
        assert partial_result["nextCommand"] is None
        authorize(broker, "prepare-research", partial_token)

        invalid_id, invalid_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"invalid\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", invalid_token)
        invalid = analyzer.prepare_research(invalid_token)
        invalid_path = Path(invalid["reportPath"])
        analyzer._atomic_write(
            invalid_path,
            json.dumps(evidence_envelope(
                invalid,
                status="succeeded",
                completeness="complete",
                terminal_status="FINISHED",
                source="https://example.com/reference?api_key=TEST_SECRET_VALUE_123456",
                request_id="request-test-invalid",
            ))
            + "\n",
            0o600,
        )
        authorize(broker, "accept-research", invalid_token)
        try:
            analyzer.accept_research(invalid_token)
        except RuntimeError as error:
            assert str(error) in {
                "The research report appears to contain a credential value.",
                "Every research source must be a public HTTP(S) URL without credentials.",
            }
        else:
            raise AssertionError("Credential-bearing source URL was accepted")

        replay_a_id, replay_a_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"replay-a\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", replay_a_token)
        replay_a = analyzer.prepare_research(replay_a_token)
        replay_b_id, replay_b_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"replay-b\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", replay_b_token)
        replay_b = analyzer.prepare_research(replay_b_token)
        replayed_envelope = evidence_envelope(
            replay_a,
            status="succeeded",
            completeness="complete",
            terminal_status="FINISHED",
            source="https://example.com/replay",
            request_id="request-test-replay-a",
        )
        analyzer._atomic_write(
            Path(replay_b["reportPath"]),
            json.dumps(replayed_envelope) + "\n",
            0o600,
        )
        authorize(broker, "accept-research", replay_b_token)
        try:
            analyzer.accept_research(replay_b_token)
        except RuntimeError as error:
            assert "approval ID does not match" in str(error)
        else:
            raise AssertionError("A report envelope was replayed across approvals")
        assert replay_a_id != replay_b_id

        private_id, private_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"private-source\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", private_token)
        private = analyzer.prepare_research(private_token)
        analyzer._atomic_write(
            Path(private["reportPath"]),
            json.dumps(evidence_envelope(
                private,
                status="succeeded",
                completeness="complete",
                terminal_status="FINISHED",
                source="http://127.0.0.1/private",
                request_id="request-test-private",
            ))
            + "\n",
            0o600,
        )
        authorize(broker, "accept-research", private_token)
        try:
            analyzer.accept_research(private_token)
        except RuntimeError as error:
            assert "public HTTP(S) URL" in str(error)
        else:
            raise AssertionError("A private source URL was accepted")

        short_id, short_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"short-report\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", short_token)
        short = analyzer.prepare_research(short_token)
        short_envelope = evidence_envelope(
            short,
            status="succeeded",
            completeness="complete",
            terminal_status="FINISHED",
            source="https://example.com/short",
            request_id="request-test-short",
        )
        short_envelope["report"] = "request-test-short https://example.com/short"
        analyzer._atomic_write(
            Path(short["reportPath"]),
            json.dumps(short_envelope) + "\n",
            0o600,
        )
        authorize(broker, "accept-research", short_token)
        try:
            analyzer.accept_research(short_token)
        except RuntimeError as error:
            assert "too short" in str(error)
        else:
            raise AssertionError("A trivial self-declared report was accepted")

        hash_id, hash_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"hash-pin\"", "timeout": 30},
        )
        original_digest = broker._analyzer_digest
        broker._analyzer_digest = lambda: "0" * 64
        try:
            assert broker._authorize_helper(helper_payload("prepare-research", hash_token)) is False
        finally:
            broker._analyzer_digest = original_digest
        assert hash_id

        cleanup_id, cleanup_token, _ = begin_similar(
            broker,
            {"code_snippet": "display dialog \"cleanup\"", "timeout": 30},
        )
        authorize(broker, "prepare-research", cleanup_token)
        cleanup_prepared = analyzer.prepare_research(cleanup_token)
        cleanup_path = Path(cleanup_prepared["reportPath"])
        assert cleanup_path.exists()
        broker._user_prompt_submit(
            {"session_id": "isolated-test-session", "prompt": f"deny {cleanup_id}"}
        )
        assert not cleanup_path.exists()

        symlink_target = root / "symlink-target.json"
        analyzer._atomic_write(symlink_target, "{}\n", 0o600)
        symlink_path = root / "symlink-inbox.json"
        symlink_path.symlink_to(symlink_target)
        try:
            analyzer._read_research_inbox(symlink_path)
        except RuntimeError as error:
            assert "opened safely" in str(error)
        else:
            raise AssertionError("A symlink research inbox was accepted")

        proposal_base = {
            "title": "Non-persistable test candidate",
            "kind": "unsupported",
            "persistentScope": "Test scope.",
            "matches": [],
            "doesNotMatch": [],
            "worstCase": "No persistence should occur.",
            "riskLevel": "low",
            "prefix": [],
            "appleScriptCode": "",
            "maxTimeout": 60,
            "useOriginalAction": False,
            "evidenceUrls": [],
        }
        duplicate_proposal = analyzer._validate_proposal(
            {
                "researchSummary": "Test",
                "originalRisk": "Test",
                "candidates": [
                    {**proposal_base, "id": "C2"},
                    {**proposal_base, "id": "C1"},
                    {**proposal_base, "id": "C1"},
                ],
            },
            {"tool_name": "Other", "tool_input": {}},
            [],
        )
        candidate_ids = [item["id"] for item in duplicate_proposal["candidates"]]
        assert candidate_ids == ["C2", "C1", "C3"]
        assert len(candidate_ids) == len(set(candidate_ids))

        assert analyzer._shell_tokens(
            {"tool_name": "Other", "tool_input": {"command": "/bin/rm /tmp/example"}}
        ) == []
        assert analyzer._original_applescript(
            {"tool_name": "Other", "tool_input": {"code_snippet": "display dialog \"x\""}}
        ) is None

        original_rule_check = analyzer._direct_rule_effective
        analyzer._direct_rule_effective = lambda _prefix: True
        try:
            prefix_candidate = {
                **proposal_base,
                "id": "C1",
                "kind": "codex_prefix",
                "prefix": ["git", "status"],
                "evidenceUrls": ["https://example.com/evidence"],
            }
            prefix_result = analyzer._validate_proposal(
                {
                    "researchSummary": "Test",
                    "originalRisk": "Test",
                    "candidates": [prefix_candidate],
                },
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status && /bin/rm /tmp/example"},
                },
                ["https://example.com/evidence"],
            )
            assert prefix_result["candidates"][0]["coversOriginal"] is False
        finally:
            analyzer._direct_rule_effective = original_rule_check

        timeout_candidate = {
            **proposal_base,
            "id": "C1",
            "kind": "applescript_exact",
            "appleScriptCode": "display dialog \"timeout\"",
            "maxTimeout": 30,
            "evidenceUrls": ["https://example.com/evidence"],
        }
        timeout_result = analyzer._validate_proposal(
            {
                "researchSummary": "Test",
                "originalRisk": "Test",
                "candidates": [timeout_candidate],
            },
            {
                "tool_name": "mcp__applescript__applescript_execute",
                "tool_input": {
                    "code_snippet": "display dialog \"timeout\"",
                    "timeout": 60,
                },
            },
            ["https://example.com/evidence"],
        )
        assert timeout_result["candidates"][0]["persistable"] is True
        assert timeout_result["candidates"][0]["coversOriginal"] is False
        assert timeout_result["candidates"][0]["appleScriptCode"] == "display dialog \"timeout\""

        redaction_cases = {
            "Basic dXNlcjpwYXNzd29yZA==": "dXNlcjpwYXNzd29yZA==",
            "curl -u user:password https://example.com": "user:password",
            "curl -H 'Cookie: session=secretvalue' https://example.com": "session=secretvalue",
            "mysql -pPASSWORD": "PASSWORD",
            "https://example.com/?x-amz-signature=secretvalue": "secretvalue",
            "curl -d '{\"password\":\"jsonsecret\"}' https://example.com": "jsonsecret",
            "-----BEGIN PRIVATE KEY-----\nprivatekeymaterial\n-----END PRIVATE KEY-----": "privatekeymaterial",
        }
        for raw, secret in redaction_cases.items():
            assert secret not in analyzer.redact_text(raw)
        try:
            analyzer._research_packet(
                {
                    "authorization": "Bearer TEST_SECRET_VALUE_123456",
                    "command": "login alice second-unlabeled-credential",
                }
            )
        except RuntimeError as error:
            assert "cannot be redacted safely" in str(error)
        else:
            raise AssertionError("A mixed recognized and unlabeled credential context was accepted")

        malformed_policy = Path(os.environ["ACCESSIBLE_APPROVAL_APPLESCRIPT_POLICY_FILE"])
        malformed_policy.write_text("{not-json", encoding="utf-8")
        try:
            analyzer._load_applescript_policy()
        except RuntimeError as error:
            assert "unreadable" in str(error)
        else:
            raise AssertionError("A malformed AppleScript policy was treated as empty")
        malformed_policy.unlink()
        malformed_policy.write_text(
            json.dumps({
                "version": 1,
                "gatewaySha256": analyzer._file_sha256(analyzer.APPLESCRIPT_GATEWAY),
                "allowAll": True,
                "entries": [{"digest": "bad", "maxTimeout": 60}],
            }),
            encoding="utf-8",
        )
        try:
            analyzer._load_applescript_policy()
        except RuntimeError as error:
            assert "malformed entry" in str(error)
        else:
            raise AssertionError("A malformed entry survived beside allowAll true")
        malformed_policy.unlink()
        malformed_policy.write_text(
            json.dumps({
                "version": 1,
                "gatewaySha256": analyzer._file_sha256(analyzer.APPLESCRIPT_GATEWAY),
                "allowAll": "false",
                "entries": [],
            }),
            encoding="utf-8",
        )
        try:
            analyzer._load_applescript_policy()
        except RuntimeError as error:
            assert "allowAll" in str(error)
        else:
            raise AssertionError("A string allowAll value was accepted")
        malformed_policy.unlink()

        combined_action = {
            "code_snippet": "display dialog \"combined\"",
            "timeout": 60,
        }
        combined_id, combined_token, persistence_token, combined_context = begin_always_and_similar(
            broker,
            combined_action,
        )
        assert "one identical execution" in combined_context
        pre_persistence_retry = broker.request_external_action(
            "mcp__applescript__applescript_execute",
            combined_action,
        )
        assert pre_persistence_retry["behavior"] == "deny"
        assert pre_persistence_retry["id"] == combined_id
        authorize(broker, "persist-exact", persistence_token)
        busy_denial = broker._user_prompt_submit(
            {"session_id": "isolated-test-session", "prompt": f"deny {combined_id}"}
        )
        assert "ACCESSIBLE_APPROVAL_BUSY" in (
            busy_denial["hookSpecificOutput"]["additionalContext"]
        )
        persisted = analyzer.persist_exact(persistence_token)
        assert persisted["retryAuthorizedByPolicy"] is True
        policy = analyzer._load_applescript_policy()
        assert policy["allowAll"] is False
        assert any(
            entry.get("digest") == analyzer.applescript_digest(combined_action["code_snippet"])
            and entry.get("maxTimeout") == combined_action["timeout"]
            for entry in policy["entries"]
        )

        authorize(broker, "prepare-research", combined_token)
        combined_prepared = analyzer.prepare_research(combined_token)
        combined_report_path = Path(combined_prepared["reportPath"])
        analyzer._atomic_write(
            combined_report_path,
            json.dumps(evidence_envelope(
                combined_prepared,
                status="succeeded",
                completeness="complete",
                terminal_status="FINISHED",
                source="https://example.com/reference",
                request_id="request-test-combined",
            ))
            + "\n",
            0o600,
        )
        authorize(broker, "accept-research", combined_token)
        combined_accepted = analyzer.accept_research(combined_token)
        assert combined_accepted["nextCommand"] is not None
        authorize(broker, "synthesize", combined_token)
        analyzer.synthesize(combined_token)
        selection = broker._user_prompt_submit(
            {
                "session_id": "isolated-test-session",
                "prompt": f"allow selected {combined_id} C1",
            }
        )
        selection_context = selection["hookSpecificOutput"]["additionalContext"]
        apply_match = re.search(r"apply --token ([a-f0-9]{32,64})", selection_context)
        if apply_match is None:
            raise AssertionError("Broker did not return a combined-flow apply token")
        apply_token = apply_match.group(1)
        assert broker._authorize_helper(helper_payload("apply", apply_token)) is True
        assert broker._authorize_helper(helper_payload("apply", apply_token)) is False
        original_open_lock = analyzer._open_persistence_lock
        analyzer._open_persistence_lock = lambda: (_ for _ in ()).throw(
            RuntimeError("preflight lock failure")
        )
        try:
            analyzer.apply_selected(apply_token)
        except RuntimeError as error:
            assert "preflight lock failure" in str(error)
        else:
            raise AssertionError("Preflight apply failure did not propagate")
        finally:
            analyzer._open_persistence_lock = original_open_lock

        retry_selection = broker._user_prompt_submit(
            {
                "session_id": "isolated-test-session",
                "prompt": f"allow selected {combined_id} C1",
            }
        )
        retry_match = re.search(
            r"apply --token ([a-f0-9]{32,64})",
            retry_selection["hookSpecificOutput"]["additionalContext"],
        )
        if retry_match is None:
            raise AssertionError("Preflight failure did not restore proposal_ready")
        retry_apply_token = retry_match.group(1)
        authorize(broker, "apply", retry_apply_token)
        combined_applied = analyzer.apply_selected(retry_apply_token)
        assert combined_applied["coversOriginal"] is True
        assert combined_applied["retryOriginal"] is False

        print(
            json.dumps(
                {
                    "status": "passed",
                    "completeApprovalId": approval_id,
                    "partialApprovalId": partial_id,
                    "invalidApprovalId": invalid_id,
                    "redaction": "passed",
                    "inboxPermissions": "0600",
                    "completeAcceptance": "passed",
                    "partialContinuation": "passed",
                    "credentialUrlRejection": "passed",
                    "duplicateCandidateIds": "passed",
                    "crossToolCoverage": "passed",
                    "alwaysAndSimilar": "passed",
                    "combinedRetryDeduplication": "passed",
                    "persistExactDenyRace": "passed",
                    "reportBinding": "passed",
                    "privateSourceRejection": "passed",
                    "shortReportRejection": "passed",
                    "analyzerHashPin": "passed",
                    "symlinkInboxRejection": "passed",
                    "exactCoverage": "passed",
                    "applescriptTimeoutCoverage": "passed",
                    "expandedRedaction": "passed",
                    "mixedCredentialRejection": "passed",
                    "malformedPolicyRejection": "passed",
                    "singleUseApply": "passed",
                    "staleProposalChoiceRejection": "passed",
                    "failedApplyRecovery": "passed",
                    "preflightApplyRecovery": "passed",
                    "denialInboxCleanup": "passed",
                    "testDefaultIsolation": "passed",
                    "fixtureSynthesis": "passed",
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
