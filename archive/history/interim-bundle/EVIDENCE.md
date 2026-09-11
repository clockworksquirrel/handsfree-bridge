# Evidence and source references

Inspected on 2026-09-11. This file contains local-code evidence only. It is not a DeepAPI or externally sourced AppleScript research report.

## Observed configuration and state

| Observation | Evidence |
| --- | --- |
| One broker handles permission requests and submitted user messages | `[USER_HOME]/.codex/hooks.json` registers `accessible_approval_broker.py` under `PermissionRequest` and `UserPromptSubmit` |
| Pending inspection requests had not been approved or expired when checked | Targeted read-only inspection found `pending` status and no approval timestamps; every inspected record was younger than the configured 30-minute pending lifetime |
| Changed explanation produced a changed approval identity | All pairwise comparisons among the three inspection requests found identical `command` values; only `description` differed |
| Saved shell input did not contain working-directory context | Field names were exactly `command` and `description`; this does not prove the original hook event lacked a top-level working directory |
| No existing gateway script policy was available | `[USER_HOME]/.codex/accessible-approvals/applescript-policy.json` did not exist at inspection |
| No existing command-wrapper policy was available | `[USER_HOME]/.codex/accessible-approvals/command-wrappers.json` did not exist at inspection; separate native command-prefix rules were not audited |
| The configured AppleScript tool uses the reviewed gateway | The `mcp_servers.applescript` entry in `[USER_HOME]/.codex/config.toml` launches `applescript_approval_gateway.py` |
| A standard escalated request was blocked | The preserved tool response was `ACCESSIBLE_APPROVAL_REQUIRED`; the command did not run and there is no evidence that a popup appeared |
| Passwordless sudo is reported by [OWNER] | Accepted as user-provided context, not probed and not treated as broker permission |

No live approval IDs, records, helper tokens, or action payloads were copied into this bundle.

## Approval identity and reply matching

The action fingerprint includes the whole tool input, which explains why a description-only change creates a different identity. Source, line 88 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:88`

```python
def _canonical_action(tool_name: str, tool_input: Any) -> bytes:
    return json.dumps(
        {"tool_name": tool_name, "tool_input": tool_input},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", "surrogatepass")
```

The parser requires a full-message match before it attempts any record lookup. Source, line 665 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:665`

```python
stripped = prompt.strip()
selection = SELECTION_RE.fullmatch(stripped)
# The alternative approval parser likewise uses:
match = APPROVAL_RE.fullmatch(stripped)
if match is None:
    return None
```

A read-only check extracted the actual regular expression using Python's syntax parser and evaluated it without importing or executing the broker's handlers. A plain approval phrase matched; the same phrase enclosed in the observed delegation format did not. No approval state was created, edited, or consumed.

The reply handler first looks up the submitting session. Its fallback is the fixed external AppleScript session, and that fallback accepts only records whose origin is `applescript_gateway`. It does not look up another Codex task's shell request. Source, line 684 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:684`

The available session-log metadata did not provide a trace proving whether `UserPromptSubmit` fired for each forwarded message. The verified conclusion is narrower: the current parser rejects the observed wrapped format, the lookup is session-bound, and the saved inspection records remained pending. Direct submission is the configured supported trigger; a successful end-to-end direct approval was not tested here.

## Supported types and misleading prompt choices

`_has_exact_applescript_scope` begins with this restriction. Source, line 345 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:345`

```python
if record.get("tool_name") != "mcp__applescript__applescript_execute":
    return False
```

Both persistent choices call this check. The helper independently raises an error when `_original_applescript` does not recognize the action. Helper source, line 1447 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/similar_command_analyzer.py:1447`

The rejection-message generator nevertheless offers `allow once`, `allow similar`, `allow always`, `allow always and similar`, and `deny` for every blocked action. The proposed prompt change is to display capabilities that the actual action classifier supports. Prompt source, line 318 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/accessible_approval_broker.py:318`

## AppleScript matching and execution

Only line endings are normalized. Source, line 69 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/applescript_approval_gateway.py:69`

```python
def _normalize_code(code: str) -> str:
    return code.replace("\r\n", "\n").replace("\r", "\n")
```

Persistent entries match a script digest and a timeout ceiling. The matcher has no separate application identity, current document, selection, shell command, nested script, or data-destination field. Source, line 152 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/applescript_approval_gateway.py:152`

After approval, the gateway writes the supplied source to a temporary file and invokes `osascript` with it. This assessment did not invoke the gateway or execute AppleScript. Source, line 194 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/applescript_approval_gateway.py:194`

The existing test fixture includes AppleScript containing `do shell script`. That establishes its relevance to this installation, but the fixture is not live verification of AppleScript platform semantics. Fixture, line 175 `[USER_HOME]/.agents/skills/accessible-approvals/scripts/test_similar_command_workflow.py:175`

## Persistence and test references

- Shell token extraction `[USER_HOME]/.agents/skills/accessible-approvals/scripts/similar_command_analyzer.py:914`
- Candidate validation and wrapper conversion `[USER_HOME]/.agents/skills/accessible-approvals/scripts/similar_command_analyzer.py:997`
- Exact AppleScript persistence and rollback `[USER_HOME]/.agents/skills/accessible-approvals/scripts/similar_command_analyzer.py:1436`
- Command-wrapper prefix matching `[USER_HOME]/.agents/skills/accessible-approvals/scripts/approved_command_wrapper.py:87`
- Existing compound-command and timeout checks `[USER_HOME]/.agents/skills/accessible-approvals/scripts/test_similar_command_workflow.py:469`
- Existing combined persistence workflow checks `[USER_HOME]/.agents/skills/accessible-approvals/scripts/test_similar_command_workflow.py:604`

Test code was inspected, not executed. Production approval records were never changed. No external source citations are supplied because the required DeepAPI research could not run.
