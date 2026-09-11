# AppleScript and universal broker approvals

Completed 2026-09-11. This is the final research synthesis; raw Scout records are retained separately and are not all independently endorsed.

## Result

Universal mode removes the custom broker's approval step for its shell, SSH, AppleScript, and other tool requests. That is a local implementation finding supported by installed-code tests. It does not configure macOS privacy permissions, application authentication, or remote-server access.

Apple distinguishes Automation, which controls whether an app can control another app, from Accessibility, which permits access to and control of the user interface. Apple's current instructions put them in separate sections of System Settings → Privacy & Security. A broker setting does not enable either. [Automation](https://support.apple.com/guide/mac-help/allow-apps-to-control-other-apps-on-mac-mchl07817563/mac), [Accessibility](https://support.apple.com/en-in/guide/mac-help/mh43185/mac).

Consequently, a new or unauthorized requesting app or target may still need an OS decision or encounter a denial. The responsible application depends on the launch arrangement. This research did not inspect the Mac's existing privacy grants or establish that every application is already authorized. No privacy grants were changed.

## Language and application edge cases

AppleScript can identify applications by name, bundle identifier, or path. Apple documents that application references are evaluated as a script runs. A bundle identifier is an application selector, not an integrity hash of executable contents. The latter distinction is an inference from those different identifiers. [Application reference](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/reference/ASLR_classes.html).

Runtime script evaluation can accept text or a file. External script loading obtains code and handlers from another file. Unchanged outer source can therefore behave differently when generated text, parameters, or loaded dependencies change. That conclusion follows from the documented language behavior. The chosen universal mode does not request a new broker approval for each variation, but it does not make outside source content into user instructions. [Commands reference](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/reference/ASLR_cmds.html), [Loading script libraries](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/reference/ASLR_load_script.html).

UI scripting depends on a running process and its element hierarchy. Apple's examples explicitly select a process, locate windows and controls, and sometimes bring an application forward. Permission does not make the current window, selection, focus, or menu layout stable. A failed or misdirected UI action is therefore not necessarily a permission problem. This task did not execute UI-control tests. [UI scripting guide](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/AutomatetheUserInterface.html).

## Shell execution and privileges

AppleScript's shell command accepts a string. Values concatenated into it may be interpreted as shell syntax. Apple recommends quoted-form conversion for data passed as arguments; broad approval does not replace correct argument handling. [Calling command-line tools](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/CallCommandLineUtilities.html).

Apple's archived TN2065 describes use of `/bin/sh`, with no automatic reading of interactive Terminal configuration. It also explains that the environment is inherited from the process hosting the script. The useful distinction is that inherited values can exist, but Terminal customizations cannot be assumed. Explicit executable paths and deliberately supplied environment values reduce these differences. [TN2065](https://developer.apple.com/library/archive/technotes/tn2065/_index.html).

The same note distinguishes AppleScript administrator authentication from sudo's policy and documents passwordless sudo for covered commands. [OWNER]'s reported passwordless-sudo capability was accepted as reported context, not probed or changed. It does not establish Automation, Accessibility, or remote-server permission. No password was embedded in a script. The note's historical authentication-caching timing is not treated as a guarantee for the current machine. [TN2065](https://developer.apple.com/library/archive/technotes/tn2065/_index.html).

## Operational implications

Identify which component owns an interruption. A broker approval message concerns the broker or its policy. A macOS privacy dialog concerns the requesting app's OS permission. A command's own authentication prompt or remote rejection belongs to that command or service. Removing the first does not satisfy the others. This is a synthesis of the separate mechanisms, not a claim that all possible prompts were tested.

Malformed inputs and invalid internal helper tokens still fail validation. Universal mode changes the broker's prompt policy; it is not permission for the agent to perform unrelated tasks. No per-host launcher change is needed or installed under the final universal design.

## Evidence quality and limits

Five discovery searches were performed under the rule in force when this pass began. That search-count requirement has since been removed from the configured source and local skills. Five focused Apple pages were fetched, three Scouts handled distinct scopes, and three more primary Apple references were fetched to verify remaining claims. Completed research calls were not repeated.

The Scouts all returned succeeded, complete, and `TERMINAL_STATUS: FINISHED`. Their source arrays included many irrelevant or secondary links, including malformed examples. Those arrays were not treated as proof. This synthesis uses directly retrieved Apple documentation. Third-party claims about detailed library search order, caching, and particular permission-reset behavior were not adopted as current-system guarantees.

Language guides and TN2065 are archived. Current Apple Support pages supply the settings guidance. The report is not a live audit of every application, OS permission, SSH host, or privileged operation. Both document-retrieval requests returned all requested pages without reported truncation. A cut-off Scout display was recovered in seven ordered parts from the already preserved complete result.

## Provenance

Blackboard workflow: `[REDACTED_ID]`.

| Step | DeepAPI request ID | Result |
| --- | --- | --- |
| Discovery 1 | `[REDACTED_ID]` | succeeded |
| Discovery 2 | `[REDACTED_ID]` | succeeded |
| Discovery 3 | `[REDACTED_ID]` | succeeded |
| Discovery 4 | `[REDACTED_ID]` | succeeded |
| Discovery 5 | `[REDACTED_ID]` | succeeded |
| Five-page retrieval | `[REDACTED_ID]` | succeeded; five returned |
| App identity and dependencies Scout | `[REDACTED_ID]` | succeeded; complete; FINISHED |
| Shell and privileges Scout | `[REDACTED_ID]` | succeeded; complete; FINISHED |
| macOS permissions Scout | `[REDACTED_ID]` | succeeded; complete; FINISHED |
| Primary verification | `[REDACTED_ID]` | succeeded; three returned |

The research used DeepAPI through the authorized [SSH_HOST] route. A task-local copy of the supplied workflow followed the live polling contract without the old 120-second client cutoff. Installed transport scripts were not changed. Account/billing summaries and full third-party documentation pages are excluded from the delivered research data; source links, request IDs, complete Scout answers, and the relevant provenance remain available.
