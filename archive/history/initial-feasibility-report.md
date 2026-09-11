# Approval broker assessment and proposed change

Date: 2026-09-11

Status: Local code review complete. Implementation and external AppleScript research have not started. Only this report was added; no approval code, settings, grant records, credentials, or remote files were changed.

## Answer and scope

Both action types can be supported in [OWNER]'s broker. The actual types are `Bash`, which carries a shell command and includes this SSH launcher invocation, and `mcp__applescript__applescript_execute`, which carries AppleScript source and a timeout. SSH is not a separate registered tool type.

The smallest useful change is to add exact saved approval for supported shell commands, retain exact AppleScript approval, and show only options the implementation supports. Reducing prompts across different AppleScript parameters needs a separately defined operation with validated parameters. Comparing arbitrary scripts for similar meaning is not an adequate approval boundary.

This is a proposal, not authorization to change approval controls. Passwordless sudo is [OWNER]'s reported environment capability. It does not register broker approval or remove restrictions imposed by Codex, the sandbox, or macOS. No privileged capability was probed.

## Verified findings

1. **The reply-registration problem is separate from persistence.** `UserPromptSubmit` invokes the broker. The parser requires a whole-message approval phrase and looks in the submitting task's records. Its only cross-session fallback is the AppleScript gateway's shared session. A forwarded delegation does not match the parser. Inspection records remained pending and had not expired when checked. A code-only parser check accepted a plain approval message and rejected the delegation wrapper; no broker handler or grant-writing function was executed for that check.
   Sources: hook configuration `[USER_HOME]/.codex/hooks.json:26`, reply handler `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:665`.

2. **The prompts offer options that this shell action cannot use.** The rejection message always offers all five choices. Both persistent choices call `_has_exact_applescript_scope`, which requires the AppleScript tool type. The persistence helper independently rejects other types. `allow similar` accepts shell actions, but it starts research and candidate selection rather than immediately authorizing the blocked action.
   Sources: prompt text `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:318`, type check `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:345`, choice handling `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:610`, persistence helper `[USER_HOME]/.agents/skills/accessible-approvals/scripts/similar_command_analyzer.py:1436`.

3. **Explanation changes generated different inspection IDs.** The three inspected saved inputs had identical `command` values. Only `description` differed. The broker hashes the entire input, including that explanation. The saved shell input contained `command` and `description`, but no working-directory field. It therefore must not be treated as a complete execution-context record. Approval IDs and live records are intentionally omitted from this report.
   Source: action fingerprint `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:88`, plus targeted read-only comparisons of those three records.

4. **AppleScript reuse currently means the same normalized source.** The gateway normalizes line endings and matches a source hash plus a maximum timeout. It does not normalize whitespace, comments, identifiers, or parameter values. It validates the policy's ownership, permissions, schema, and gateway hash. Changes to gateway code invalidate the policy. The expected `applescript-policy.json` file was absent when checked, so this gateway had no persisted script entries to reuse. The command-wrapper policy file was also absent; this does not establish whether separate Codex prefix rules exist.
   Sources: normalization `[USER_HOME]/.agents/skills/accessible-approvals/scripts/applescript_approval_gateway.py:69`, policy matching `[USER_HOME]/.agents/skills/accessible-approvals/scripts/applescript_approval_gateway.py:152`.

5. **Command persistence already has a different path.** The analyzer can propose native command-prefix rules after research and explicit candidate selection. It can also convert a candidate into a different wrapper invocation when a direct rule would not be effective. This proposal does not use that conversion to get past a blocking decision. An exact saved command should be checked on the existing execution path.
   Sources: candidate validation `[USER_HOME]/.agents/skills/accessible-approvals/scripts/similar_command_analyzer.py:997`, wrapper execution `[USER_HOME]/.agents/skills/accessible-approvals/scripts/approved_command_wrapper.py:87`.

## Proposed implementation

### First change: truthful options and exact saved commands

- Add a shared action classifier used by the prompt, choice handler, persistence helper, and matcher. Unsupported actions must not advertise an effective “always” choice.
- Keep explanatory text out of command identity. Retain every execution-relevant field. Capture the working directory from trusted hook metadata where available; do not infer it from an agent-written description. Decline persistence when required context is unavailable.
- Add a versioned exact-command policy checked by the existing permission hook. Bind a supported command to its executable or script, exact arguments or full shell body, relevant working directory, and known target/context restrictions. Pin reviewed script dependencies where their contents determine the operation. Changing them must invalidate the saved scope or follow an explicitly approved update policy.
- For the inspection example, the intended reusable scope is the specific DeepAPI launcher inspection on [SSH_HOST]. It must not authorize other SSH hosts, other launcher operations, arbitrary commands, or a different program installed at the same path. The launcher accepts an environment-based host override, so exact command text alone cannot prove the destination. Resolve that issue before advertising persistent support for this example.
- For unsupported dynamic shell expressions or execution context, retain one-time approval. Do not turn an exact shell action into an interpreter-wide prefix rule.
- Extend `persist_exact` to handle the supported shell type with the existing single-use authorization, backup, atomic-write, and rollback pattern. Keep AppleScript and shell policy types distinct. Provide a way to inspect and revoke saved scopes.
- Preserve the semantics of the choices. “Always” saves one supported scope. “Similar” proposes separately reviewable scopes. “Always and similar” saves the supported exact scope and starts that proposal workflow. Research findings never grant permission by themselves.
- A broker match removes only the broker's own repeated approval requirement. Do not disable outer review or switch executors when another control rejects the operation.

Likely files: `accessible_approval_broker.py`, `similar_command_analyzer.py`, and the existing test file, plus a small shared matcher module only if necessary to avoid divergent matching rules. The persisted command policy would be created only after valid user approval, not during installation.

### Separate change: reusable routine AppleScript operations

Keep arbitrary AppleScript on exact-source approval. For actions that legitimately need changing parameters, expose a small, explicit operation catalog backed by fixed reviewed scripts and validated inputs. Each saved scope names the application, operation, allowed targets and parameters, and data destination where relevant. Do not use a keyword blacklist or loose source-text matching to authorize arbitrary scripts.

| Intended operation | Proposed reusable boundary |
| --- | --- |
| Read an approved application's window information | Named application and named read operation; no inherited permission to export private results |
| Activate a named application | Verified application identity and activation only |
| Change a particular reversible preference | Named setting, allowed values, and named application |
| Send, delete, upload, or export data | Its own explicit scope covering recipients, targets, destinations, and allowed repetition, or one-time approval |
| Execute a shell command, nested script, or external script file | Separate executable/script scope; no inherited routine UI permission |

This extension requires AppleScript research and separate implementation review. It is larger than the missing shell persistence branch.

## AppleScript edge cases established by the local matcher

The following are consequences of the inspected code. Detailed AppleScript and macOS platform behavior has not been externally verified in this task.

| Case | Current behavior or gap | Proposed handling |
| --- | --- | --- |
| Different line endings | Normalize to the same source hash | Retain this behavior |
| Changed whitespace, comments, literal app name, path, or parameter | Different source hash | Reuse stable scripts; use validated operation parameters for deliberate variation |
| Same script, changed timeout | Reuse only within the saved maximum | Keep the limit visible in the approved scope |
| Application identity | No independent app-identity check; only script text is matched | Verify the named app for an operation template rather than trusting a display name alone |
| Dynamic source, nested execution, or external scripts | No semantic inspection or dependency check in the policy matcher | Do not infer their behavior from an unchanged outer script hash |
| Indirect shell execution | The matcher has no separate shell category; the test fixture itself includes `do shell script` | Review and bind the underlying executable and arguments when defining a reusable operation |
| UI scripting, current selection, frontmost window, or clipboard input | These are not represented separately in the policy key | Define and verify the runtime target for a reusable operation; changed data must not silently broaden a sending/deletion scope |
| Gateway or referenced helper changes | Gateway changes invalidate the saved policy; referenced helpers are not independently pinned by the AppleScript entry | Preserve gateway validation and explicitly define dependency/update handling |

Sources: gateway checks and execution `[USER_HOME]/.agents/skills/accessible-approvals/scripts/applescript_approval_gateway.py:152`, shell-bearing fixture `[USER_HOME]/.agents/skills/accessible-approvals/scripts/test_similar_command_workflow.py:175`.

## Verification required before implementation ships

The existing test file includes checks for cross-tool coverage, compound-command coverage, AppleScript timeout coverage, single-use helper authorization, malformed policies, and persistence rollback. These checks were inspected, not run in this assessment. They do not establish live AppleScript behavior or voice-to-task approval registration.

Add focused isolated tests for supported and unsupported choices, exact shell persistence, explanation-only changes, changed working directory/host/arguments/helper contents, expiry/revocation, and both native-hook and AppleScript-gateway enforcement. Verify that selected broader candidates cannot grant themselves permission and that blocked external decisions do not cause executor substitution. For operation templates, test parameter injection, changed app or runtime target, nested execution, and changes from reading to sending/deleting.

The supported submission path must also work end to end. Forwarded text must not become a grant merely because it contains an approval phrase. Supporting approvals from the voice task requires an authenticated host event tied to the destination task and exact action. No such callable acceptance operation was exposed in this task.

Source: existing coverage examples `[USER_HOME]/.agents/skills/accessible-approvals/scripts/test_similar_command_workflow.py:469`.

## Outstanding research and original task

No external research request ran. DeepAPI through [SSH_HOST] remains blocked by the approval handler, and no alternative search or remote executor was used. The pending external research covers Apple's application targeting, dynamic and nested AppleScript, `do shell script`, UI scripting, Automation/Accessibility permissions, and practical bounded-operation patterns. It must use the required DeepAPI discovery and Blackboard/Scout workflow and publish the resulting report before research-dependent implementation.

The original request is still pending: remove only the five-source requirement from the live [SSH_HOST] DeepAPI skill and directly governing references, preserving Blackboard/Scout and any separate query requirement. No remote skill or local mirror has changed.

Next steps: review this proposed scope, establish working host-originated approval registration, complete the blocked research, and then authorize any approval-behavior changes. The report itself does not activate any new permission.
