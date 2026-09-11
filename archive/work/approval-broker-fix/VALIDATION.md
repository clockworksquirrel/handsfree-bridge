# Isolated validation checkpoint

Both suites passed on 2026-09-11. No SSH command, AppleScript execution, paid research, live approval handler invocation, or live grant mutation was performed by these tests. All approval-state fixtures were confined to temporary test directories.

The current [SSH_HOST] inspection is explicitly tested as still unsupported for saved approval. Its stable identity and one-time approval flow pass in the isolated fixture. This is not a successful live registration test or proof that the original requested operation is fixed.

## New regression suite

Command: `/usr/bin/python3 test_exact_command_approvals.py`

Exit code: 0

```text
test_actual_ssh_host_inspection_is_stable_but_saved_scope_is_still_unsupported (__main__.BrokerTests) ... ok
test_applescript_defaults_and_line_endings_reuse_request (__main__.BrokerTests) ... ok
test_arguments_and_cwd_remain_identity (__main__.BrokerTests) ... ok
test_changed_binary_invalidates_scope (__main__.BrokerTests) ... ok
test_changed_environment_invalidates_scope_without_storing_values (__main__.BrokerTests) ... ok
test_combined_scope_does_not_approve_proposals (__main__.BrokerTests) ... ok
test_description_is_not_identity (__main__.BrokerTests) ... ok
test_helper_envelope_does_not_accept_extra_commands (__main__.BrokerTests) ... ok
test_once_requires_user_submission_and_is_consumed (__main__.BrokerTests) ... ok
test_other_tools_keep_meaningful_description_fields (__main__.BrokerTests) ... ok
test_pending_binding_change_gets_new_request (__main__.BrokerTests) ... ok
test_persistent_command_uses_original_execution_path (__main__.BrokerTests) ... ok
test_policy_malformed_or_revoked_denies (__main__.BrokerTests) ... ok
test_similar_proposals_do_not_create_blanket_or_alternate_executor_scopes (__main__.BrokerTests) ... ok
test_unsupported_options_are_not_advertised (__main__.BrokerTests) ... ok
test_wrapped_text_and_other_tasks_cannot_grant (__main__.BrokerTests) ... ok
test_existing_applescript_exact_semantics (__main__.MatcherTests) ... ok
test_ssh_remote_shell_expansion_is_not_saved (__main__.MatcherTests) ... ok

----------------------------------------------------------------------
Ran 18 tests in 0.322s

OK
```

## Existing workflow suite

Command: `/usr/bin/python3 test_similar_command_workflow.py`

Exit code: 0

Synthetic test approval IDs omitted.

```json
{
  "status": "passed",
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
  "fixtureSynthesis": "passed"
}
```

