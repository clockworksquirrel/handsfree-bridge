# Public-copy changes and verification

Prepared on 2026-09-11 for `clockworksquirrel/handsfree-bridge`.

## What changed for publication

The original completed development folder was preserved. This repository is a separate public copy with a fresh Git history.

- Private home/workspace paths, the owner's personal name, the private SSH destination, and operational request identifiers were replaced with placeholders. Test identifiers containing the private host name were generalized.
- The original development record is under `archive/`. Its reports describe a historical installation, not the machine reading them now. Old installers, patches, and hashes must not be applied unchanged.
- The final seven Python source/test files were copied into `src/`. The similar-command test now creates a temporary launcher fixture for hashing instead of reading a launcher from the original machine. Runtime behavior was not changed for publication.
- The fresh `prompt.md` is an installation request with bracketed environment choices, backed by the current code and explicit compatibility limits. It is not a transcript export.
- Apache 2.0 covers original contributions. Eight complete provider-owned snapshots were replaced by source pointers because their redistribution license was unverified. See [third-party notices](../THIRD_PARTY_NOTICES.md).
- Broken private-path citations became plain placeholder references. Links in the copied delivery README were corrected for its archive location.
- No live credential store, grant store, user policy file, private research log, or unrelated conversation was a publication input. Raw fetched third-party pages remain outside this repository. Generated Python caches are ignored.

The archive's historical inventory is not a checksum list for this release. [PUBLIC_EXPORT_MANIFEST.json](../PUBLIC_EXPORT_MANIFEST.json) records the current public files and their SHA-256 hashes. It excludes itself, Git metadata, and generated caches.

## Checks run on the public copy

The checks below ran with Python 3.11.14. The gateway import used MCP 1.6.0 and Pydantic 2.11.3. These versions record the environment used, not a recommendation to install old dependencies.

| Check | Result |
| --- | --- |
| `python3 -m unittest discover -s src -p 'test_universal_broker.py' -v` | 16 tests passed, including the gateway import and decision test. |
| `python3 src/test_similar_command_workflow.py` | Passed with temporary state, synthetic research records, and a local launcher fixture. No paid research was called. |
| `python3 examples/policy_demo.py` | Printed both expected decisions; no shell, SSH, or UI action executed. |
| Gitleaks directory scan with full redaction | No credential findings. |
| Gitleaks staged-file scan with full redaction | No credential findings. |
| Targeted privacy and local-link review | No unresolved personal-path/host/name findings or broken local Markdown links. Five synthetic private-key fixtures were verified as non-key test literals. |
| Manifest against Git's staged contents | All 95 publication files accounted for, including the manifest itself. |

The additional privacy review checks private path/name/host remnants, broken local Markdown links, and manifest hashes. Fake private-key strings deliberately test redaction and are not working credentials. Scanners cannot prove that every sensitive value is absent; future changes need the same human review.

## What was not established

No fresh end-to-end installation on a second computer was performed. Windows, every AI tool, and every assistive technology are not certified or universally tested. The archive contains earlier test reports, but those are separate from the public-copy checks above. There is no guarantee of virality or security from passing these tests.

The custom broker can omit its own approval prompts. It cannot remove prompts enforced by the operating system, applications, authentication, or an AI service.
