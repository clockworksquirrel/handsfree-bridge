# Accessibility Approval

Start with [the assessment and proposed change](ASSESSMENT.md). It covers the confirmed approval failure, support for shell commands and AppleScript, the proposed scope of saved permissions, AppleScript edge cases visible in the local code, and the required validation.

[Evidence and references](EVIDENCE.md) records the non-secret observations and selected source excerpts. References point to the inspected installed source files. No external research sources are claimed.

## Completion status

- Completed: read-only approval-handler and persistence review, targeted comparison of the blocked command records, a parser-only check, and a concrete implementation proposal.
- Not performed: changes to the installed approval system, live approval tests, AppleScript execution, paid or external research, or the [SSH_HOST] skill edit.
- External research remains blocked by the unresolved [SSH_HOST] inspection approval. Research must use DeepAPI and the required Blackboard/Scout workflow once access is available.
- The original pending request is only removal of the five-source requirement from the [SSH_HOST] DeepAPI copy. Its Blackboard/Scout workflow must remain unchanged.

## Delivery

Requested destination:

`[PRIVATE_BUNDLE_ROOT]`

Prepared fallback destination, inside this task's writable workspace:

`[WORKSPACE_ROOT]/output/Accessibility Approval`

The requested destination is outside this task's permitted write roots. The originating task can copy this complete folder there. It has not been copied by this task, and no destination folder was replaced.

The initial report remains at `[WORKSPACE_ROOT]/output/approval-broker-assessment-archived.md`. The assessment in this bundle is a copy. Only report artifacts were created or edited. Live configuration, policies, approval records, credentials, and remote files remain untouched.

The bundle deliberately excludes approval IDs, grants, helper tokens, raw session history, raw state files, private script bodies, and credentials. Proposed changes are written in the assessment; no implementation patch or test-pass claim is included.
