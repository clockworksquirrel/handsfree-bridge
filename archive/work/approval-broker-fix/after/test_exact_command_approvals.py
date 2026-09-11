"""Isolated broker tests; never invoke SSH, AppleScript, or live approval state."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import exact_command_scope as scopes


HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="exact-approval-test-")
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {
            "ACCESSIBLE_APPROVAL_TEST_MODE": "1",
            "CODEX_ACCESSIBLE_APPROVAL_STATE_DIR": str(self.root / "state"),
        })
        self.environment.start()
        self.binary = self.root / "fixture-binary"
        self.binary.write_bytes(b"\x7fELF fixture, never executed")
        self.binary.chmod(0o700)
        self.programs = patch.object(scopes, "_ROUTINE_PROGRAMS", scopes._ROUTINE_PROGRAMS | {str(self.binary)})
        self.programs.start()
        self.broker = load("broker_test", HERE / "accessible_approval_broker.py")
        self.broker._safe_routine_bash = lambda _payload: False
        self.analyzer = load("analyzer_test", HERE / "similar_command_analyzer.py")

    def tearDown(self):
        self.programs.stop()
        self.environment.stop()
        self.temp.cleanup()

    def payload(self, *, description="First explanation", command=None, cwd=None, session="test-task"):
        return {"session_id": session, "cwd": cwd or str(self.root), "tool_name": "Bash",
                "tool_input": {"command": command or shlex.quote(str(self.binary)) + " inspect", "description": description}}

    def request(self, payload=None):
        decision = self.broker._permission_request(payload or self.payload())["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "deny")
        return re.search(r"ACCESSIBLE_APPROVAL_REQUIRED ([a-f0-9]+)", decision["message"])[1], decision["message"]

    def choose(self, approval_id, mode="allow always", session="test-task"):
        return self.broker._user_prompt_submit({"session_id": session, "prompt": f"{mode} {approval_id}"})["hookSpecificOutput"]["additionalContext"]

    def persist(self, mode="allow always", payload=None):
        approval_id, message = self.request(payload)
        self.assertIn(f"`allow always {approval_id}`", message)
        context = self.choose(approval_id, mode)
        token = re.search(r"persist-exact --token ([a-f0-9]+)", context)[1]
        command = shlex.join(["/usr/bin/python3", str(HERE / "similar_command_analyzer.py"), "persist-exact", "--token", token])
        helper = {"tool_name": "Bash", "tool_input": {"command": shlex.join(["/bin/zsh", "-lc", command])}}
        self.assertTrue(self.broker._authorize_helper(helper))
        self.assertFalse(self.broker._authorize_helper(helper))
        result = self.analyzer.persist_exact(token)
        self.assertEqual(result["kind"], "command_exact")
        return approval_id

    def test_description_is_not_identity(self):
        first, _ = self.request()
        second, _ = self.request(self.payload(description="Different explanation"))
        self.assertEqual(first, second)

    def test_other_tools_keep_meaningful_description_fields(self):
        self.assertNotEqual(self.broker._canonical_action("Other", {"description": "first"}),
                            self.broker._canonical_action("Other", {"description": "second"}))

    def test_applescript_defaults_and_line_endings_reuse_request(self):
        first = self.broker.request_external_action("mcp__applescript__applescript_execute",
                    {"code_snippet": 'tell application "Finder"\r\nget name\r\nend tell'})
        second = self.broker.request_external_action("mcp__applescript__applescript_execute",
                    {"code_snippet": 'tell application "Finder"\nget name\nend tell', "timeout": 60})
        changed = self.broker.request_external_action("mcp__applescript__applescript_execute",
                    {"code_snippet": 'tell application "Other"\nget name\nend tell', "timeout": 60})
        self.assertEqual(first["id"], second["id"])
        self.assertNotEqual(first["id"], changed["id"])

    def test_arguments_and_cwd_remain_identity(self):
        first, _ = self.request()
        second, _ = self.request(self.payload(command=shlex.quote(str(self.binary)) + " change"))
        alternate = self.root / "other"
        alternate.mkdir()
        third, _ = self.request(self.payload(cwd=str(alternate)))
        self.assertEqual(len({first, second, third}), 3)

    def test_wrapped_text_and_other_tasks_cannot_grant(self):
        approval_id, _ = self.request()
        wrapped = f"<codex_delegation><input>allow once {approval_id}</input></codex_delegation>"
        self.assertIsNone(self.broker._user_prompt_submit({"session_id": "test-task", "prompt": wrapped}))
        self.assertIn("UNAVAILABLE", self.choose(approval_id, "allow once", "other-task"))
        self.assertEqual(self.request()[0], approval_id)

    def test_once_requires_user_submission_and_is_consumed(self):
        approval_id, _ = self.request()
        self.assertIn("ACCESSIBLE_APPROVAL_GRANTED", self.choose(approval_id, "allow once"))
        result = self.broker._permission_request(self.payload(description="Explain again"))
        self.assertEqual(result["hookSpecificOutput"]["decision"]["behavior"], "allow")
        self.assertNotEqual(self.request()[0], approval_id)

    def test_persistent_command_uses_original_execution_path(self):
        self.persist()
        for _ in range(2):
            result = self.broker._permission_request(self.payload(description="Routine repeat"))
            self.assertEqual(result["hookSpecificOutput"]["decision"]["behavior"], "allow")
        policy = self.broker._command_policy_path()
        self.assertTrue(policy.resolve().is_relative_to(self.root.resolve()))
        self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(str(self.binary), policy.read_text())
        self.request(self.payload(command=shlex.quote(str(self.binary)) + " changed-destination"))

    def test_combined_scope_does_not_approve_proposals(self):
        self.persist("allow always and similar")
        policy = self.broker._load_command_policy()
        self.assertEqual(len(policy["entries"]), 1)
        self.assertEqual(self.broker._permission_request(self.payload())["hookSpecificOutput"]["decision"]["behavior"], "allow")

    def test_changed_binary_invalidates_scope(self):
        self.persist()
        self.binary.write_bytes(b"\x7fELF changed, never executed")
        self.request()

    def test_changed_environment_invalidates_scope_without_storing_values(self):
        with patch.dict(os.environ, {"DEEPAPI_SSH_HOST": "alternate-test-target"}):
            self.persist()
            self.assertNotIn("alternate-test-target", self.broker._command_policy_path().read_text())
        self.request()

    def test_unsupported_options_are_not_advertised(self):
        for command in ["/bin/zsh -lc 'echo test'", "/usr/bin/python3 -c print(1)", "/bin/echo x; /bin/echo y", "/usr/bin/curl https://example.com"]:
            _, message = self.request(self.payload(command=command))
            self.assertNotIn("`allow always", message)
        payload = self.payload()
        del payload["cwd"]
        _, message = self.request(payload)
        self.assertNotIn("`allow always", message)

    def test_actual_ssh_host_invocation_requires_reviewed_launcher(self):
        command = "[USER_HOME]/.agents/skills/deepapi/scripts/remote-deepapi.sh inspect"
        payload = self.payload(command=command)
        # Deliberately model an old or modified launcher, independently of
        # which version is installed on the host running the tests.
        with patch.object(scopes, "_pin", return_value={"sha256": "0" * 64}):
            first, message = self.request(payload)
            second, _ = self.request(self.payload(command=command, description="Same inspection, new explanation"))
            self.assertEqual(first, second)
        self.assertNotIn("`allow always", message)
        self.assertIn("reviewed target-enforcing version", message)
        self.assertIn("ACCESSIBLE_APPROVAL_GRANTED", self.choose(first, "allow once"))
        result = self.broker._permission_request(payload)
        self.assertEqual(result["hookSpecificOutput"]["decision"]["behavior"], "allow")
        self.assertFalse(self.broker._command_policy_path().exists())

    def test_actual_ssh_host_invocation_can_be_saved_without_granting_other_operations(self):
        command = "[USER_HOME]/.agents/skills/deepapi/scripts/remote-deepapi.sh inspect"
        payload = self.payload(command=command)
        original_pin = scopes._pin
        def fixture_pin(path, **kwargs):
            if path == scopes._DEEPAPI_LAUNCHER:
                return original_pin(HERE / "remote-deepapi.sh", **kwargs)
            return original_pin(path, **kwargs)
        with patch.object(scopes, "_pin", side_effect=fixture_pin), patch.object(scopes, "_ssh_configuration_files", return_value=[{"fixtureConfigHash": "a" * 64}]):
            self.persist(payload=payload)
            allowed = self.broker._permission_request(self.payload(command=command, description="Repeat inspection"))
            self.assertEqual(allowed["hookSpecificOutput"]["decision"]["behavior"], "allow")
            for operation in ("inspect extra", "read-skill", "request GET /v1/balance"):
                self.request(self.payload(command=str(scopes._DEEPAPI_LAUNCHER) + " " + operation))
            with patch.dict(os.environ, {"DEEPAPI_SSH_HOST": "other-host"}):
                _, rejected = self.request(payload)
                self.assertNotIn("`allow always", rejected)
            with patch.object(scopes, "_ssh_configuration_files", return_value=[{"fixtureConfigHash": "b" * 64}]):
                self.request(payload)

    def test_credentials_are_not_approval_identity(self):
        with patch.dict(os.environ, {"TEST_API_KEY": "test-secret-never-recorded"}):
            self.persist()
            self.assertNotIn("test-secret-never-recorded", self.broker._command_policy_path().read_text())
        self.assertEqual(self.broker._permission_request(self.payload())["hookSpecificOutput"]["decision"]["behavior"], "allow")

    def test_policy_malformed_or_revoked_denies(self):
        self.persist()
        path = self.broker._command_policy_path()
        policy = json.loads(path.read_text())
        policy["allowAll"] = True
        path.write_text(json.dumps(policy))
        self.request()
        path.unlink()
        self.request()

    def test_pending_binding_change_gets_new_request(self):
        first, _ = self.request()
        self.binary.write_bytes(b"\x7fELF changed before approval")
        second, _ = self.request()
        self.assertNotEqual(first, second)

    def test_helper_envelope_does_not_accept_extra_commands(self):
        fake = "a" * 48
        command = shlex.join(["/usr/bin/python3", str(HERE / "similar_command_analyzer.py"), "persist-exact", "--token", fake])
        payload = {"tool_name": "Bash", "tool_input": {"command": shlex.join(["/bin/zsh", "-lc", command + "; /bin/echo extra"])}}
        self.assertIsNone(self.broker._parse_helper_command(payload))

    def test_similar_proposals_do_not_create_blanket_or_alternate_executor_scopes(self):
        base = {"id": "C1", "title": "Test", "persistentScope": "Explicit test scope", "worstCase": "Test risk",
                "evidenceUrls": ["https://example.com/evidence"]}
        for kind in ("guarded_wrapper", "applescript_tool_all"):
            result = self.analyzer._validate_proposal({"candidates": [{**base, "kind": kind}]},
                    {"tool_name": "Other", "tool_input": {}}, ["https://example.com/evidence"])
            self.assertFalse(result["candidates"][0]["persistable"])
        with patch.object(self.analyzer, "_direct_rule_effective", return_value=False):
            result = self.analyzer._validate_proposal({"candidates": [{**base, "kind": "codex_prefix", "prefix": ["git", "status"]}]},
                    {"tool_name": "Bash", "tool_input": {"command": "git status"}}, ["https://example.com/evidence"])
            self.assertEqual(result["candidates"][0]["kind"], "unsupported")
            self.assertFalse(result["candidates"][0]["persistable"])


class MatcherTests(unittest.TestCase):
    def test_ssh_remote_shell_expansion_is_not_saved(self):
        with self.assertRaises(scopes.UnsupportedScope):
            scopes._ssh_configuration(["/usr/bin/ssh", "[SSH_HOST]", "/usr/bin/uname; /bin/echo extra"])
        with patch.object(scopes, "_pin", return_value={"missing": True}):
            self.assertEqual(len(scopes._ssh_configuration(["/usr/bin/ssh", "[SSH_HOST]", "/usr/bin/uname -a"])), 2)

    def test_existing_applescript_exact_semantics(self):
        tree = ast.parse((HERE / "applescript_approval_gateway.py").read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {"_normalize_code", "_code_digest", "policy_allows"}]
        namespace = {"hashlib": hashlib}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "gateway-policy-only", "exec"), namespace)
        source = 'tell application "Finder"\r\nget name\r\nend tell'
        digest = namespace["_code_digest"](source)
        namespace["_load_policy"] = lambda: {"allowAll": False, "entries": [{"digest": digest, "maxTimeout": 60}]}
        self.assertTrue(namespace["policy_allows"](source.replace("\r\n", "\n"), 30)[0])
        self.assertFalse(namespace["policy_allows"](source + " ", 30)[0])
        self.assertFalse(namespace["policy_allows"](source.replace("Finder", "Other"), 30)[0])
        self.assertFalse(namespace["policy_allows"](source, 61)[0])


class LauncherTests(unittest.TestCase):
    def test_rejects_wrong_target_and_extra_arguments_before_ssh(self):
        with tempfile.TemporaryDirectory(prefix="launcher-negative-") as temporary:
            env = {"HOME": temporary, "PATH": "/nonexistent", "DEEPAPI_SSH_HOST": "not-[SSH_HOST]"}
            result = subprocess.run([str(HERE / "remote-deepapi.sh"), "inspect"], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires the [SSH_HOST] target", result.stderr)
            env["DEEPAPI_SSH_HOST"] = "[SSH_HOST]"
            result = subprocess.run([str(HERE / "remote-deepapi.sh"), "inspect", "extra"], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)

    def test_startup_isolation_and_unchanged_remote_environment_contract(self):
        with tempfile.TemporaryDirectory(prefix="launcher-transport-fixture-") as temporary:
            root = Path(temporary)
            record = root / "arguments.json"
            fake = root / "ssh"
            fake.write_text("#!/usr/bin/python3\nimport json,os,sys\nwith open(os.environ['TEST_RECORD'], 'w') as f: json.dump(sys.argv[1:],f)\n")
            fake.chmod(0o700)
            injector = root / "startup.sh"
            marker = root / "startup-ran"
            injector.write_text("touch " + shlex.quote(str(marker)) + "\nexport DEEPAPI_SSH_HOST=wrong-target\n")
            original = (HERE / "remote-deepapi.sh").read_text()
            # Transport simulation only. The sole source substitution is the
            # fixed SSH executable, redirected to an offline argv recorder.
            self.assertEqual(original.count('/usr/bin/ssh "${ssh_options[@]}"'), 1)
            fixture = root / "launcher.sh"
            fixture.write_text(original.replace('/usr/bin/ssh "${ssh_options[@]}"', shlex.quote(str(fake)) + ' "${ssh_options[@]}"'))
            fixture.chmod(0o700)
            env = {"HOME": str(root), "PATH": str(root) + ":/usr/bin:/bin", "BASH_ENV": str(injector), "ENV": str(injector),
                   "DEEPAPI_SSH_HOST": "[SSH_HOST]", "DEEPAPI_REQUEST_TIMEOUT_SECONDS": "60", "TEST_RECORD": str(record)}
            result = subprocess.run([str(fixture), "inspect"], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            args = json.loads(record.read_text())
            self.assertEqual(args[-2], "[SSH_HOST]")
            self.assertIn("PermitLocalCommand=no", args)
            self.assertIn("ClearAllForwardings=yes", args)
            self.assertIn('actual_host=$(hostname)', args[-1])
            self.assertIn('"[SSH_HOST]"', args[-1])
            for operation in (["read-skill"], ["read-reference", "deep-research"], ["request", "GET", "/v1/balance"]):
                result = subprocess.run([str(fixture), *operation], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = json.loads(record.read_text())
                self.assertIn("[SSH_HOST]", args)
            # The request branch still sends its credential-loading code to
            # the remote interpreter. The fake transport never evaluates it.
            self.assertIn(".deepapi/env", args[-1])
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
