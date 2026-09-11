# Universal approval mode: installation pending

[OWNER]'s latest request replaces the per-host design with universal coverage. The implemented mode applies to every tool handled by his custom broker, including SSH commands on any host, arbitrary shell commands and arguments, AppleScript, and native MCP tools. This is deliberately broad. It does not authorize unrelated tasks, change tool schemas, or replace Codex/macOS controls.

## Current implementation

Current source: `universal-after/`.

- New `broker_policy.py` reads an owner-only policy setting. Missing policy preserves prompting; `no_prompt` skips this broker's per-action prompts. Malformed, linked, or unsafe policy files do not enable the mode.
- The native permission hook and AppleScript gateway share that setting. Universal decisions do not create per-action grant records.
- Prompt mode retains exact-action approval, with the description-only identity bug fixed and unsupported persistent choices omitted.
- Internal persistence helpers still validate their tokens. Action text and forwarded model messages cannot change the mode or manufacture registrations.
- “Similar” proposals no longer substitute an alternate executor when an external rule prevents direct persistence.
- The original [SSH_HOST] launcher command is covered by universal mode without changing the launcher. The scoped matcher and proposed launcher hardening under `after/` are superseded drafts, not installation inputs.

## Verification

- 16 universal-mode tests passed using the installed AppleScript gateway Python, including the complete gateway's decision and argument validation.
- The existing similar-command workflow suite passed.
- 3 installation tests passed, including rollback after an injected setting-write failure and preservation of concurrent user edits.
- Read-only installation preflight returned `ready`; reviewed staged hashes and original installed hashes matched.
- Tests used only temporary state and simulated actions. No SSH, AppleScript action, or paid research ran during validation.

Reviewed diff: [universal-changes.patch](universal-changes.patch).

Installer: [install_universal_broker.py](install_universal_broker.py). Its default invocation is read-only. `--install` backs up the original code, installs five reviewed files, and creates `[USER_HOME]/.codex/accessible-approvals/broker-policy.json` with `mode` set to `no_prompt` last. It does not edit platform settings, credentials, the DeepAPI launcher, or approval grant records.

## Actual blocker

The normal escalated installation request was rejected by the currently installed approval broker with `ACCESSIBLE_APPROVAL_REQUIRED`. The installer did not run. No installed files or live mode setting changed. A genuine host-registered approval for that installation request is required; forwarded messages and model-generated grants are not substitutes.

The earlier [SSH_HOST] inspection was also rechecked and rejected under this task's current permissions. External DeepAPI research and the remote removal of only the five-source requirement remain pending. Blackboard/Scout must remain intact. No remote files have changed.

Final packaging remains paused. Preserve the earlier draft reports and scoped implementation, but do not present them as the finished design or a completed bundle.
