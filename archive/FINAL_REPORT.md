# Completed approval and DeepAPI changes

Completed 2026-09-11.

## Universal broker mode

[OWNER]'s final choice was universal coverage, replacing the earlier [SSH_HOST]-only design. The installed custom broker now uses `no_prompt` mode for its normal tool requests, including SSH commands on any host, arbitrary shell commands and arguments, AppleScript, and other native MCP tool families.

The mode is configured at `[USER_HOME]/.codex/accessible-approvals/broker-policy.json`. This is an explicit user-owned setting, not a collection of fabricated per-action grants. Argument validation and internal helper-token integrity checks remain active. The mode does not change task authorization, tool availability, Codex sandbox settings, macOS privacy permissions, or remote-server policy.

Installed files under `[USER_HOME]/.agents/skills/accessible-approvals/scripts/`:

- `broker_policy.py`
- `accessible_approval_broker.py`
- `similar_command_analyzer.py`
- `test_universal_broker.py`
- `test_similar_command_workflow.py`

The installed code also fixes description-only changes creating a fresh shell approval identity in prompt mode. Meaningful command and working-directory changes remain distinct there. AppleScript default timeouts and line endings are normalized consistently. Unsupported exact-persistence choices are no longer offered for shell actions in prompt mode. Similar-command proposals do not substitute another executor when an external rule blocks direct persistence.

Installation completed through the supported executor after genuine user approval and a user-provided full-access task profile. The installer did not change that profile, platform settings, credential files, or live approval-grant records. It installed the requested broker mode last and retained a recoverable prior version.

Live backup: `[WORKSPACE_ROOT]/work/approval-broker-fix/installation-backup`.

No DeepAPI launcher hardening was installed. The launcher remains byte-for-byte unchanged. Earlier scoped code and launcher proposals are retained as superseded drafts.

## Five-search and source-count rules

The five-source minimum originally existed in the Mac's shared skill, not the [SSH_HOST] canonical skill. It was removed after [OWNER] approved that location correction. [OWNER] then clarified that the five-search rule also needed removal; that is now complete.

Changed active instructions:

- Mac canonical shared file: `[USER_HOME]/.agents/skills/deepapi/SKILL.md`.
- Local Codex view: `[USER_HOME]/.codex/skills/deepapi` remains a symlink to that shared directory and sees the same file. No divergent duplicate was created.
- [SSH_HOST] canonical source: `[REMOTE_HOME]/.agents/skills/deepapi/SKILL.md`.
- [SSH_HOST] governing reference: `[REMOTE_HOME]/.agents/skills/deepapi/references/deep-research.md`.

These active instructions now choose searches according to the question and available evidence, with no fixed minimum. The existing Blackboard/Scout instructions, citation requirements, API validation, and rate limits remain intact. The Mac Scout handoff was verified unchanged after its discovery paragraph.

Remote backup: `[REMOTE_HOME]/.agents/skill-backups/deepapi/search-minimum-8oknfeyq`. Exact before-and-after copies are also included in this delivery.

The vendor's hosted API guidance was not modified. Other standalone remote harness installations were not silently rewritten; this change targets the configured canonical [SSH_HOST] source and shared Mac skill.

## Durability through the normal updater

The existing updater preserves customized `SKILL.md` files but replaces managed references. The customized source router now explicitly gives the no-minimum rule precedence over numeric query-count recommendations in managed references and capability guidance.

An isolated execution of the actual updater, using a local fixture with the old upstream reference wording, confirmed that the customized router survives unchanged while the reference refreshes. Thus the effective no-minimum instruction survives the existing update flow. The edited reference text itself is not guaranteed to survive a future refresh; an upstream five-search sentence may reappear there, but it is overridden by the preserved source rule. Updates were not disabled or broadly forked.

## Verification

- 16 universal broker/gateway tests passed against installed code.
- The existing similar-command workflow suite passed against installed code.
- 3 installer tests passed, including rollback and concurrent-edit protection.
- The ordinary-updater persistence test passed in an isolated fixture, with no network or live-install changes.
- All five installed files match the reviewed universal implementation.
- The active broker mode reads as `no_prompt` from the expected policy location.
- The shared skill and Codex link match; the skill validator passed.
- Live [SSH_HOST] source and reference hashes match the reviewed edits, and neither enforces five searches.
- The original [SSH_HOST] inspection succeeded. Required DeepAPI research also completed.

No destructive shell commands or live AppleScript UI-control actions were executed merely to test broad permission coverage. Those tests exercised decisions in isolated state; real [SSH_HOST] inspection and research provided the live access checks.

## Research and delivery

The complete research synthesis is `work/applescript-research/RESEARCH_REPORT.md`. It was published in the task before final packaging. It uses primary Apple documentation, distinguishes archived language guidance from current settings help, and explains the permissions and authentication prompts that remain outside the custom broker.

Three Scouts completed through the shared Blackboard workflow, with their complete findings and request provenance retained. A task-local compatibility copy followed DeepAPI's current polling contract without the obsolete client cutoff. Installed transport scripts were not changed.

All task-created reports, code, tests, patches, backups, research records, and prior drafts are collected in the delivery folder. Originals remain in place. Copy verification and documented exclusions are recorded in `INVENTORY.json`. Raw account/billing metadata, full third-party documentation text, bytecode caches, and the transient workflow lock are not redistributed. Research answers, source links, statuses, request IDs, and metadata counterparts remain available. No live approval-grant stores, helper tokens, credentials, or unrelated history were collected.

The earlier checkpoint and interim-bundle files are historical records. Their statements about incomplete work and old quotas are superseded by this report; they are not active configuration.
