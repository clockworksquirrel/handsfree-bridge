---
name: deepapi
description: Use DeepAPI for open-web search, deep research, website and platform scraping, public-site browser actions, email workflows, image generation, transcription, account checks, and persistent agent state. Use whenever a task calls for the supported DeepAPI capabilities. This machine has no local DeepAPI credentials; inspect and execute the full integration through the authorized SSH host [SSH_HOST].
---

# DeepAPI via [SSH_HOST]

Treat `[SSH_HOST]:[REMOTE_HOME]/.agents/skills/deepapi` as the canonical DeepAPI integration. Do not assume a local DeepAPI installation, environment file, API key, endpoint contract, or balance.

Use the shared launcher at:

```bash
launcher="$HOME/.agents/skills/deepapi/scripts/remote-deepapi.sh"
```

## Start Every DeepAPI Task

1. Run `"$launcher" inspect` before any mutation or paid request. Confirm the remote hostname is `[SSH_HOST]` and note the live skill version.
2. Run `"$launcher" read-skill` and follow the remote `SKILL.md` as the source of truth.
3. Read the workflow reference selected by the remote router with `"$launcher" read-reference <name>`. Supported names are `deep-research`, `scraping`, `browse-web`, `send-email`, `generate-image`, and `manage-agent-state`.
4. Run `"$launcher" update` once per day at the first DeepAPI use, after the read-only inspection. Do not wait for the updater.
5. Execute API requests with the launcher so authentication and the skill-version header are added only on `[SSH_HOST]`.

## Make Requests

Use a read request directly:

```bash
"$launcher" request GET /v1/balance
```

Send a JSON body over standard input for a POST. Include only fields documented by the current remote reference. Start paid or unfamiliar work with the documented `dryRun` option when available.

Cost preference: minimize actual cost per call by choosing the narrowest endpoint, avoiding redundant calls, and sizing result/depth parameters to the task. Unless the user explicitly supplies a budget, do not invent an aggregate monetary cap, do not stop a workflow solely because of cumulative cost, and omit optional `maxCostUsd` / `maxCostMicrousd` fields. Service-required or service-default per-call allowances remain part of the API contract and are not a workflow stopping rule.

```bash
printf '%s' "$payload" | "$launcher" request POST /v1/search/web
```

The launcher allows a request to run for 24 hours by default and keeps its SSH
transport alive for the same interval. Set `DEEPAPI_REQUEST_TIMEOUT_SECONDS=0`
for no client-side request timeout, or set a positive number of seconds for a
shorter task-specific ceiling. This does not change DeepAPI's server-side limits.

The launcher generates a new idempotency key for each POST. Follow polling, retry, feedback, cost-cap, and news rules from the current remote `SKILL.md`; do not reconstruct those rules from memory.

## Mandatory search-to-scout handoff

Every open-web research pass has two required stages. First, run the documented set of at
least five distinct `/v1/search/web` queries, choose strong direct source
URLs, and fetch the pages needed for evidence. This is source discovery, not a finished
research result.

As soon as those sources are identified, start a task-local Blackboard/Scout workflow with
`scripts/research-workflow.py`. Give scouts separate, non-overlapping claims or source groups
and use later dependent stages when the research question needs synthesis across their
findings. A critic scout is optional. Add one when claims are contested, sources disagree, or
the decision is important enough to warrant adversarial checking; do not require one for every
query. The dependency ledger must carry the discovered URLs, established facts,
uncertainties, and request IDs so later phases extend the first stage instead of repeating it.

Do not skip the Blackboard/Scout stage because the lookup appears quick or because the first
pages seem sufficient. Do not make an implementation, configuration, or other substantive
decision from the discovery stage alone. Finish the dependent workflow and publish its full
research report first. This requirement applies to research that uses open-web search; it does
not turn account checks, status reads, or non-research API actions into research projects.

## Requested Deliverables

Materialize every deliverable the user requests; an API response, inline chat content, or a remote-only result does not count as delivery by itself.

- Prefer saving each deliverable as a verified, non-empty file in the active task workspace, using the workspace's artifact directory when one is defined.
- Return a clickable local file link for every local deliverable. If local materialization is genuinely unavailable or the result must remain hosted, return a direct downloadable URL instead.
- When DeepAPI returns a downloadable artifact URL, download and verify the artifact locally when access, licensing, and security constraints permit. Otherwise provide the direct URL and disclose any known authentication or expiration requirement.
- Preserve the format the user requested. Validate the file structure and open or render it when the format has a supported verification workflow.
- Never expose credentials or place secrets in filenames, URLs, artifacts, or handoff text.
- If delivery is blocked, state exactly which deliverable is missing and why; do not describe the task as complete.

## Deep Research Chat Deliverables

Immediately after **each completed DeepAPI research pass**—including web search, scraping for evidence, `POST /v1/research/deep`, and multi-call scout workflows—publish that pass's complete, full research report directly in the chat **before** making or applying any implementation, configuration, or other substantive decision based on it. A research pass is one bounded research question or coordinated workflow intended to produce one report; do not treat individual calls inside the same coordinated pass as separate reports. An executive summary or abbreviated synthesis alone is not sufficient. Treat `output.completeness: "partial"` as useful evidence and label the boundary clearly.

This report is a hard sequencing gate: do not make research-backed edits first and explain them afterward, and do not defer every pass's explanation into one final cumulative report. If implementation or configuration work later reveals a distinct research need, pause that work, run a new separate research pass, publish a separate complete report for that pass, and only then act on its findings.

### 12,000-character error-recovery continuation rule

Apply this rule globally and operation-agnostically to every DeepAPI operation and every resulting response, report, evidence packet, manifest field, Blackboard dependency handoff, or downstream handoff to a coordinator, scout, reviewer, or other receiving agent. It applies equally to `research.deep`, ordinary `search.web`, all scrape/platform endpoints, browser actions, email operations, image generation, transcription, account/state operations, and any future DeepAPI capability. Preserve and synthesize the complete original content first, then attempt one complete delivery to the intended recipient. Do not preemptively split solely because the response is estimated or known to exceed 12,000 characters.

Only when the receiving context, API, model, or tool returns an actual size, context, truncation, or processing error that prevents complete delivery, retry the same preserved content as at least two numbered sequential parts, each no longer than 12,000 characters. Never truncate, summarize away, rerun, recharge, or silently omit material merely to fit. State the total part count when known, preserve source links, request IDs, uncertainty, exact ordering, and all substantive content, and end every non-final part with a concise continuation marker such as `Continuation: part 2 of 3 follows.` Deliver every part to the same recipient and obtain or verify receipt of all parts before it acts.

A bounded `sharedContextChars` snapshot that actually truncates or rejects a Blackboard dependency counts as a processing failure and triggers the ordered continuation path; the bounded snapshot is not a substitute for complete delivery. This is output/transport recovery only, not permission to duplicate a DeepAPI research request.

### Time-limit partial-response recovery

Apply this operation-agnostically when a DeepAPI operation reaches its documented response-duration limit and returns useful but incomplete material. This is separate from, and does not replace, the full-delivery-first and actual-receiver-error multipart recovery rules above. Preserve the partial result immutably with its route, capability, request ID, status, `output.completeness` or partial reason, sources, completed scope, unresolved scope, errors, timestamps, assumptions, and uncertainty. Never discard it, present it as complete, or silently rerun work it already finished.

Immediately prepare a concise, source-grounded continuation packet for a fresh agent or a new, narrower DeepAPI operation with a new task/question ID and idempotency key. Carry forward the verified findings and citations, state the exact response-duration boundary and missing scope, and explicitly prohibit duplicating the completed portion. If the prior request's outcome is transport-indeterminate rather than a terminal partial response, do not resubmit it blindly; preserve and reconcile that uncertainty first under the existing indeterminate-request rules.

After the continuation completes, synthesize its result with the preserved partial response. Maintain provenance for both, surface contradictions instead of overwriting either result, preserve residual uncertainty, and apply the normal report and downstream review gates to the combined evidence.

Require every DeepAPI-backed agent or scout prompt to request one explicit status signal at the end of its scoped answer: `TERMINAL_STATUS: FINISHED`, `TERMINAL_STATUS: PARTIAL`, `TERMINAL_STATUS: BLOCKED`, or `TERMINAL_STATUS: FAILED`. `FINISHED` requires all assigned scope and citations. A response-duration boundary with useful unfinished work must be `PARTIAL` and retain `output.completeness`, `partialReason`, and request provenance. For non-agent endpoints, use the documented terminal envelope and completeness fields; elapsed client wait alone is never completion.

For a DeepAPI-backed agent/scout with the documented 120-second `research.deep` response cap, run the work in successive **multiples of two minutes**, with one fresh time-capped agent or operation per two-minute multiple. After any cycle terminates partial because of the cap, immediately preserve the result, prepare a concise source-grounded packet containing established findings/citations and only the unfinished scope, and launch the next fresh agent or narrower operation with a new task/question ID and idempotency key. Continue successive two-minute multiples while terminal cycles remain partial. Never rerun completed scope or discard earlier cycles. Stop only on explicit `FINISHED`, `BLOCKED`, or `FAILED`; operations with a different documented cap follow their own contract, and genuinely asynchronous operations continue through their documented polling `next` rather than this response-cap cycle.

Only after the cycle chain ends may the coordinator synthesize every preserved cycle with the prior research ledger. `BLOCKED` and `FAILED` are non-success outcomes and must follow their recovery/escalation paths. Preserve provenance, contradictions, and residual uncertainty across the complete chain.

### Request-rate waves

Keep request-rate admission separate from the two-minute response/synthesis-cycle protocol. Under the currently published 60-request-per-rolling-minute API-key limit, reserve one request for the required live preflight and admit at most 59 production calls in an otherwise empty rolling window. Always use the lower published workspace/key limit and subtract existing timestamped reservations; 59 is not a workflow-total limit or permission to saturate a provider.

Track actual request timestamps in the process-locked rolling-window ledger instead of assuming a fixed one-minute sleep resets quota. Preserve completed and pending state after each wave. If more calls are needed, resume with another bounded wave only when timestamp-based capacity returns, following `retryAfterSecs` and the live rate contract. Never raise local concurrency to bypass the provider quota.

- Prefer one complete, cumulative, chat-ready report for each pass over disconnected API responses, phase summaries, or an abbreviated synthesis.
- Include the research question and scope, executive summary, detailed evidence-backed findings, direct source links, competing explanations, relevant code snippets when useful, implementation implications or next actions, remaining uncertainty and disagreements, and the DeepAPI `requestId`, `status`, and completeness where applicable.
- For every DeepAPI call that yields source material, include clickable Markdown links to the final direct source URLs for every factual claim drawn from that material. Do not substitute bare URLs, search-result pages, uncited source names, or fabricated links. When a non-source call (for example balance, capability, status, or a failed request) has no public source URL, say that explicitly rather than inventing a citation.
- Keep credentials, raw private memory, unrelated request history, private logs, and other secrets out of the chat report.
- Make every pass report complete and keep the final chat response self-contained. A final summary may refer back to earlier pass reports but does not replace their required pre-action publication; an API envelope, remote result, or artifact link alone does not satisfy delivery.
- Do not create or require a PDF unless the user explicitly requests one. If requested, follow the active PDF or artifact workflow and also summarize the useful outcome in chat.
- Do not present a failed call with no findings as a successful report. If an earlier phase produced useful evidence, synthesize it in chat and state the failure boundary concisely.

## Long Research Compatibility Workflow

DeepAPI's current `research.deep` route can still end an individual provider run at the official 120-second response-duration limit. The live `research.deep` capability contract verified on 2026-08-18 exposes no `maxTime`, response-duration, timeout, or polling field that can expand one response to five minutes; its polling mode is `none`. Do not change the integration to 300 seconds or claim five-minute responses are supported unless a later live capability contract explicitly adds a server-side duration control. `DEEPAPI_REQUEST_TIMEOUT_SECONDS` and SSH/client timeouts are transport waits only and cannot extend the provider's 120-second response limit.

The same 2026-08-18 official-contract audit found no supported custom/passthrough/experimental override: the `research.deep` request schema has `additionalProperties: false` and permits only `query`, `context`, `instructions`, `maxCostUsd`, `maxCostMicrousd`, and `dryRun`; its only operation-specific request header is `Idempotency-Key`. No documented research job, queue, callback, webhook, provider-option, enterprise-duration, or alternate asynchronous endpoint is exposed. `GET /v1/requests/{requestId}` is valid for operations that return a polling `next`, but `research.deep` returns a terminal envelope and no polling `next`, so status retrieval does not extend that response. The current account-info response also exposes no duration/timeout override. Do not probe unsupported fields when this closed schema remains current.

Treat response-duration limits per operation: inspect the live capability contract for the exact endpoint before claiming or configuring a different limit. Preserve the verified 120-second `research.deep` limit unless that operation's contract changes; if another DeepAPI operation explicitly documents a different supported server-side duration, follow that operation-specific contract rather than projecting the `research.deep` limit onto it.

For a complex research task that benefits from longer total execution, use `scripts/research-workflow.py` as a resumable client-managed compatibility layer. This does not extend one server-side request; it makes a long workflow reliable by running independent focused research questions, persisting every response, and resuming only questions that are still `pending`. Each question receives a stable idempotency key when its state is created, but a terminal `failed` or `indeterminate` question is never reissued automatically.

When the user explicitly supplies `maxCostUsd`, it is a per-call spend ceiling, not a duration control. Otherwise omit it. The live Deep Research request schema has no `maxTime` field. Never claim that raising cost or the outer SSH/client timeout extends the provider deadline.

Create a task-local manifest without secrets:

```json
{
  "name": "browser regression research",
  "maxConcurrency": "auto",
  "failFast": true,
  "autoContinue": true,
  "coordination": {
    "mode": "barrier",
    "compression": "grug",
    "sharedContextChars": 12000
  },
  "questions": [
    {
      "id": "chromium-scout",
      "phase": 0,
      "role": "primary-source scout",
      "query": "Research the Chromium lifecycle boundary...",
      "context": "Only the relevant compact background...",
      "instructions": "Return primary sources and code snippets."
    },
    {
      "id": "chromium-critic",
      "phase": 1,
      "role": "citation critic",
      "dependsOn": ["chromium-scout"],
      "query": "Test the inherited claims against their exact sources."
    }
  ]
}
```

Start it as a durable background workflow and poll its compact status:

```bash
workflow="$HOME/.agents/skills/deepapi/scripts/research-workflow.py"
python3 "$workflow" start \
  --manifest output/deepapi-research/manifest.json \
  --state output/deepapi-research/state.json
python3 "$workflow" status --state output/deepapi-research/state.json
```

If the local process or network is interrupted, resume without duplicating succeeded calls:

```bash
python3 "$workflow" start \
  --resume \
  --manifest output/deepapi-research/manifest.json \
  --state output/deepapi-research/state.json
```

### Auto-continue, timeouts, and follow-up work

`autoContinue: true` continues the same workflow only while safe `pending` work remains. After a `concurrency_wave` deferral it starts the next admitted wave; after `rate_window_budget` it waits for the recorded rolling-window delay (at most 60 seconds per wait) and re-enters with `--resume` semantics. The manifest hash must still match the state file, succeeded results are skipped, and each pending question keeps the idempotency key created in that state.

It does **not** retry a question that reached the 120-second request deadline. A returned timeout becomes `failed` with its response/error and any `requestId` preserved; a process or batch transport loss leaves a formerly running question `indeterminate` because the remote outcome cannot safely be assumed. With `failFast: true`, either condition records `scheduler.stopReason` and stops automatic queue refill. Pending dependents remain blocked because barriers unlock only from `succeeded` dependencies.

To continue the research after a timeout, preserve the useful answer, sources, request ID, exact error, and missing scope from the old state as compact context, then create narrower follow-up questions with **new IDs in a new manifest and state file**. Do not edit the old manifest in place (its hash is bound to its state), reuse the timed-out ID, or blindly resubmit an indeterminate request. The new workflow can fan those follow-ups out concurrently and join them through ordinary `dependsOn` barriers.

Use `status` to report the boundary explicitly. Its summary includes overall status, per-question state counts, and `scheduler.stopReason`, including `first_error`, `indeterminate_transport`, `dependency_blocked`, `rate_window_budget`, or `concurrency_wave`. When automatic continuation cannot proceed, return the relevant request ID/error, identify preserved evidence, list blocked/pending questions, and name the new follow-up manifest/state if one was created.

### Blackboard model in plain language

Treat every research question as a scout and the state file as a shared research notebook. Before a scout starts, the runner gives it a bounded snapshot of the **succeeded** findings from the earlier scouts named in its `dependsOn` list. After it finishes, the runner atomically records its scoped response, sources, completeness, request ID, status, error, and timestamps. Later reducers or critics read those completed dependency records so they can extend or challenge prior work instead of repeating it.

This is a barriered notebook, not a live group chat. Scouts in the same concurrent wave all start from the same earlier-phase snapshot and cannot see one another's mid-call progress. The manifest must be an acyclic dependency graph; every dependency must be in an earlier numbered phase; and the scheduler runs only the lowest ready phase. Completion order inside a wave does not decide truth. Put potentially conflicting scouts in parallel, then add a later reducer/critic that depends on all of them and is instructed to preserve disagreements, prefer primary sources, and cite the evidence chosen. The runner bounds and may truncate dependency excerpts; it does not automatically resolve semantic conflicts.

The durable state contains the manifest hash, scheduler/stop reason, and for each question its status, stable idempotency key, request ID, timestamps, dependency/phase/role metadata, terminal response, and runner error. Store only task-relevant public research context and minimal non-secret code. Exclude API keys, credential files, private memory, unrelated account/request history, personal browser state, and any secret placed in source material.

After a capacity deferral, `autoContinue` reopens this same notebook and starts only ready `pending` scouts, so succeeded work is reused. After a terminal timeout, the failed entry is written to the notebook but default fail-fast stops continuation; it is not passed through a `dependsOn` barrier because only success unlocks dependents. Create a new follow-up notebook with narrower scout IDs and copy a compact, explicit carry-forward record: confirmed findings and sources, failed request ID/error, unresolved scope, and next leads. If transport outcome is `indeterminate`, do not guess or resubmit blindly; report that boundary and reconcile externally before any retry.

- Prefer 3-6 questions for ordinary research. A four-scout-plus-reducer layout is only a compact pattern, not a cap or a default ceiling. For broad, contested, multi-provider, or implementation-critical research, actively create as many distinct, non-overlapping scouts as the evidence requires. Partition them by claim, provider, primary-source class, implementation surface, jurisdiction, time period, or adversarial hypothesis; do not ask redundant scouts the same repeated question. Intentional independent verification must use a meaningfully different evidence path and be labeled as a critic or corroboration task.
- For a genuinely large workflow, set `maxConcurrency` to `"auto"`: the runner uses a process-locked rolling-minute ledger, reads `/v1/me` only when the ledger has preflight capacity, reserves that preflight plus admitted work, and uses the remaining published key allowance. With the current 60-request limit and an empty companion ledger, at most 59 calls are admitted. This is a rolling-window admission ceiling, not a provider guarantee of 59 simultaneous paid jobs, a required scout count, or permission to saturate capacity. Let evidence needs determine the scout count while keeping every call narrow and economical.
- Carry concurrent research through one authenticated SSH session and perform the HTTP fan-out inside an in-memory [SSH_HOST] batch worker. This avoids SSH `MaxStartups`, `MaxSessions`, and macOS control-socket path limits while keeping all credentials remote.
- Do not launch more questions than the rolling rate-window budget. Leave excess questions pending for a later `--resume`, or use `autoContinue: true` in a detached workflow to wait for capacity and continue safely.
- Keep `failFast` enabled unless the user explicitly asks otherwise. The first failed call prevents additional queued calls from starting; already-running calls finish and persist safely. The remote batch returns unlaunched question IDs to pending state.
- Model cross-call communication as a blackboard with barriers. Add `dependsOn`, `phase`, and `role` to questions. A dependent phase starts only after every declared dependency succeeds, then receives a bounded JSON ledger of those completed answers, request IDs, sources, URLs, and completeness.
- For dozens of tasks, use a reducer/critic tree: independent scouts -> small-group evidence reducers -> contradiction/citation critics -> final synthesizer. Scale the tree depth with the evidence, preserve source lineage and disagreements at each barrier, and never overload one reducer or make one final task depend directly on 59 uncompressed answers.
- Use `coordination.compression: "grug"` for internal coordination prompts: terse fragments, no greetings, filler, hedging, or repetition. Preserve exact search queries, URLs, paths, identifiers, code, numbers, quotations, citations, and errors. Keep user-facing deliverables in normal readable prose. Do not claim hidden-reasoning-token savings.
- Keep questions independent and narrowly scoped; synthesize their successful outputs after the workflow settles.
- Never put credentials, unrelated account data, or private memory in a manifest or state file.
- Resume and auto-continue launch only `pending` items. Failed, timed-out, interrupted, or transport-indeterminate items retain their evidence and are never reissued automatically. Split them into smaller new tasks with new IDs in a new manifest/state.
- Treat `partial` workflow status as useful evidence and include it in the complete cumulative chat report with the failed question clearly labeled.
- The runner writes durable local state, not DeepAPI server jobs. Continue advocating for the submitted backend `202 + next` queued-worker design.

## Safety

- Keep all credentials on `[SSH_HOST]`. Never read, print, copy, download, or log `~/.deepapi/env` or any API key.
- Never enable shell tracing around the launcher or remote requests.
- Never install DeepAPI credentials on this machine as part of normal use.
- Perform read-only inspection before updates or API calls.
- Stop for user approval before sending email. Honor a monetary cap only when the user explicitly sets one; otherwise keep calls economical without stopping solely because of cumulative cost.
- Do not copy remote memory, request logs, user data, or unrelated skills.
- If SSH, the remote skill, the updater, or credentials are unavailable, stop and report the exact missing component. Do not fall back to local credentials.
