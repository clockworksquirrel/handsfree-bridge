# Incomplete implementation checkpoint

The requested fixes are not complete and must not be shipped or packaged as finished work.

## Implemented in the staged copy

- Shell approval identity ignores only explanatory `description` text. Command arguments and trusted working-directory context remain part of the identity.
- AppleScript request identity uses the same line-ending normalization and default timeout as the existing gateway. Changed application names, source, or meaningful timeout changes remain distinct.
- Prompt choices reflect whether a saved scope is supported. Unsupported cases receive a reason instead of unusable “always” options.
- Saved exact-command policies are implemented for qualifying literal routine commands and a restricted SSH read-operation form. They bind command, working directory, executable/configuration fingerprints, and inherited environment. They never create grants without a valid user-submission event and the existing single-use persistence helper flow.
- Persistence helper parsing accepts the host's shell envelope only when its inner command is exactly the authorized helper invocation. Additional commands are rejected.
- New “similar” proposals cannot select blanket AppleScript access or replace a blocked direct invocation with a different wrapper executor. Existing installed policies were not modified.

Files under `after/` are working copies. The installed broker, its configuration and grants, the local DeepAPI launcher, and remote files have not changed.

## Validation

[VALIDATION.md](VALIDATION.md) records 18 passing isolated regression tests and a passing existing workflow suite. The tests execute neither SSH nor AppleScript and do not touch live approval state. [changes.patch](changes.patch) contains the reviewed working diff against the preserved `before/` snapshot.

## Original triggering case is still unresolved

The actual saved action is the bare command:

```text
[USER_HOME]/.agents/skills/deepapi/scripts/remote-deepapi.sh inspect
```

The saved `Bash` input contains this command and its description. Earlier commentary describing the saved command itself as a login-shell wrapper was inaccurate. The host's executor may use its normal shell startup, but that wrapper is not present in the inspected saved command field.

The current matcher deliberately does not persist this launcher script. The dedicated regression test proves that changing its description no longer creates a new request, that a directly submitted one-time approval works in an isolated fixture, and that saved approval for this exact operation remains unsupported. A passing test here documents the missing case; it is not proof of full task completion.

The local launcher chooses its SSH destination using `DEEPAPI_SSH_HOST`, defaulting to `[SSH_HOST]`. The diagnostic shell currently resolved that default to `[SSH_HOST]`. Local startup-file metadata showed sourced files and evaluated command output, but those dependencies were not fully audited and bound to execution. Their contents and credentials were not copied into artifacts. A generic static command rule is insufficient evidence that the effective launcher, interpreter, host, and routing environment at execution time remain inside the intended scope.

Further work requires a reviewed adapter for this existing operation and a defensible execution-context boundary. The original invocation must not be replaced or routed through another executor merely to escape approval. Any proposed launcher change would be a distinct design decision, not an implicit expansion of the broker-only changes.

## Approval delivery and external research are still blocked

The existing registration trigger is a genuine `UserPromptSubmit` event in the task owning the request. Forwarded task messages fail the exact-message parser or do not enter that registration path. No supported callable host operation was exposed to this task for creating an authenticated user-approval event. The model must not simulate that event or write grant records itself. The new tests preserve this boundary.

Automatic approval review rejected both the [SSH_HOST] inspection and the standard popup request. No later successful registration is evidenced. Those blocked operations have not been retried during this implementation phase. External AppleScript research through DeepAPI has therefore not run. Local code findings and isolated tests are not a substitute for that research.

The original remote request also remains pending: remove only the five-source requirement from the [SSH_HOST] DeepAPI copy while retaining Blackboard/Scout and any separate query requirement.

## Delivery remains paused

The earlier report and draft `output/Accessibility Approval` folder are interim artifacts and have been preserved. Final collection and copying are paused until the requested implementation and verification are complete. No final bundle was delivered to the originating task's requested destination.
