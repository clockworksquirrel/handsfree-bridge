# Contributing

Start with a focused issue explaining the interaction or integration you want to improve. Keep private commands, paths, credentials, and medical information out of reports.

Good contributions include:

- A supported adapter for a named AI harness and version.
- Tests for an operating system or integration that has not been verified.
- Fewer unnecessary steps in a voice or assistive workflow.
- Clearer setup, failure, and recovery instructions.
- Tests showing that invalid configuration or untrusted text cannot manufacture approval.

For code changes, describe the behavior before and after, run the relevant tests, and state what you did not test. Use temporary state. Do not exercise destructive commands or live accounts just to demonstrate a policy decision.

Preserve the distinction between broker policy and platform permissions. Contributions must not hide payloads, forge consent, or route a rejected operation through another executor to evade a safeguard.

The archive is a development record. Improve current code and documentation in `src/`, `docs/`, and `prompt.md`; do not silently rewrite historical evidence.
