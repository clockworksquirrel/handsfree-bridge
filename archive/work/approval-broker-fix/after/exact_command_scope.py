"""Build bounded, non-executing descriptions of persistable shell actions.

This module never grants permission or executes a command. Unsupported shell
programs remain eligible for one-time approval through the normal broker.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import pwd
import re
import shlex
import stat
from pathlib import Path
from typing import Any


class UnsupportedScope(ValueError):
    pass


# Only these routine operations have an initial saved-command adapter. Being
# a native binary alone says nothing about a program's code-loading or export
# behavior. Other programs require one-time approval or a reviewed adapter.
_ROUTINE_PROGRAMS = frozenset({
    "/bin/pwd", "/usr/bin/uname", "/usr/bin/whoami", "/usr/bin/id",
    "/bin/ls", "/bin/cat", "/usr/bin/stat", "/usr/bin/ssh",
})

_DEEPAPI_LAUNCHER = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".agents/skills/deepapi/scripts/remote-deepapi.sh"
_REVIEWED_INSPECT_LAUNCHER_SHA256 = "b89a446e060f0ea5257470605dafa281a3c23a78723b15eee9feaa93c385e5a4"


def _inspect_launcher_pins(argv: list[str]) -> list[dict[str, Any]]:
    if argv != [str(_DEEPAPI_LAUNCHER), "inspect"]:
        raise UnsupportedScope("Only the exact DeepAPI inspection operation has a saved scope.")
    if os.environ.get("DEEPAPI_SSH_HOST", "[SSH_HOST]") != "[SSH_HOST]":
        raise UnsupportedScope("Saved inspection requires the [SSH_HOST] destination.")
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise UnsupportedScope("An elevated identity needs a separate approval.")
    launcher = _pin(_DEEPAPI_LAUNCHER, executable=True)
    if launcher["sha256"] != _REVIEWED_INSPECT_LAUNCHER_SHA256:
        raise UnsupportedScope("The launcher needs the reviewed target-enforcing version before saved approval.")
    # This reviewed version has an absolute /bin/bash -p shebang, rejects an
    # alternate runtime host or extra arguments, and invokes absolute SSH and
    # grep paths. BASH_ENV/imported functions cannot alter its startup.
    pins = [launcher, *[_pin(Path(p), executable=True) for p in ("/bin/bash", "/usr/bin/ssh", "/usr/bin/grep")]]
    pins.extend(_ssh_configuration_files())
    return pins


def canonical_input(tool_name: str, tool_input: Any) -> Any:
    if tool_name == "Bash" and isinstance(tool_input, dict):
        return {key: value for key, value in tool_input.items() if key != "description"}
    if tool_name == "mcp__applescript__applescript_execute" and isinstance(tool_input, dict):
        result = dict(tool_input)
        result.setdefault("timeout", 60)
        if isinstance(result.get("code_snippet"), str):
            result["code_snippet"] = result["code_snippet"].replace("\r\n", "\n").replace("\r", "\n")
        return result
    return tool_input


def _literal_argv(command: str) -> list[str]:
    # Reject expansions even in quotes. That is intentionally conservative.
    if any(char in command for char in "\n\r\x00$`*?[]{}~"):
        raise UnsupportedScope("Dynamic shell input requires one-time approval.")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        argv = list(lexer)
    except ValueError as error:
        raise UnsupportedScope("The shell command could not be parsed.") from error
    if not argv or any(token and all(c in ";&|<>()" for c in token) for token in argv):
        raise UnsupportedScope("Compound commands and redirections require one-time approval.")
    if not Path(argv[0]).is_absolute():
        raise UnsupportedScope("A saved command requires an absolute executable path.")
    return argv


def _pin(path: Path, *, optional: bool = False, executable: bool = False) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsupportedScope("A command dependency is not a regular file.")
        if executable and (not metadata.st_mode & 0o111 or not os.access(resolved, os.X_OK)):
            raise UnsupportedScope("The command path is not executable.")
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except FileNotFoundError:
        if optional:
            return {"path": str(path), "missing": True}
        raise UnsupportedScope("A command dependency is missing.")
    except OSError as error:
        raise UnsupportedScope("A command dependency cannot be inspected.") from error
    return {"path": str(path), "resolved": str(resolved), "sha256": digest}


def _ssh_configuration(argv: list[str]) -> list[dict[str, Any]]:
    # Scope only the simple ssh HOST REMOTE-COMMAND form. Additional SSH
    # options can redirect execution and need a separately reviewed adapter.
    if len(argv) < 3 or argv[1].startswith("-"):
        raise UnsupportedScope("This SSH option form is not supported for saved approval.")
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", argv[1]):
        raise UnsupportedScope("The SSH destination must be literal.")
    remote = _literal_argv(" ".join(argv[2:]))
    if remote[0] not in {"/bin/pwd", "/usr/bin/uname", "/usr/bin/whoami", "/usr/bin/id", "/bin/ls", "/bin/cat", "/usr/bin/stat"}:
        raise UnsupportedScope("This remote operation needs a reviewed dependency scope before persistence.")
    return _ssh_configuration_files()


def _ssh_configuration_files() -> list[dict[str, Any]]:
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    roots = [Path("/etc/ssh/ssh_config"), account_home / ".ssh" / "config"]
    pins: list[dict[str, Any]] = []
    seen: set[str] = set()

    def visit(path: Path, depth: int) -> None:
        if depth > 8:
            raise UnsupportedScope("SSH configuration includes are too deeply nested.")
        key = str(path.absolute())
        if key in seen:
            return
        seen.add(key)
        pin = _pin(path, optional=True)
        pins.append(pin)
        if pin.get("missing"):
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            for line in lines:
                fields = shlex.split(line, comments=True)
                if not fields:
                    continue
                first, separator, value = fields[0].partition("=")
                if separator:
                    fields = [first, value, *fields[1:]]
                directive = fields[0].lower()
                if directive in {"proxycommand", "localcommand", "knownhostscommand", "localforward", "remoteforward", "dynamicforward"}:
                    raise UnsupportedScope("SSH configuration executes another command or creates forwarding.")
                if directive == "match" and re.search(r"\bexec\b", line, re.IGNORECASE):
                    raise UnsupportedScope("SSH Match exec requires one-time approval.")
                if directive != "include":
                    continue
                for pattern in fields[1:]:
                    if "%" in pattern or "$" in pattern:
                        raise UnsupportedScope("Dynamic SSH includes are not supported.")
                    include = Path(str(account_home) + pattern[1:]) if pattern.startswith("~/") else Path(pattern)
                    if not include.is_absolute():
                        include = (Path("/etc/ssh") if str(path).startswith("/etc/ssh/") else account_home / ".ssh") / include
                    matched = sorted(glob.glob(str(include)))
                    pins.append({"include": str(include), "matches": matched})
                    for child in matched:
                        visit(Path(child), depth + 1)
        except (OSError, UnicodeError, ValueError) as error:
            raise UnsupportedScope("SSH configuration cannot be bound safely.") from error

    for root in roots:
        visit(root, 0)
    return pins


_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "env",
    "python", "python3", "perl", "ruby", "node", "osascript", "sudo", "su",
}


def build_scope(action: dict[str, Any]) -> dict[str, Any]:
    if action.get("tool_name") != "Bash":
        raise UnsupportedScope("This is not a shell-command action.")
    tool_input = action.get("tool_input")
    context = action.get("execution_context")
    if not isinstance(tool_input, dict) or set(tool_input) - {"command", "description"}:
        raise UnsupportedScope("Unrecognized execution fields require one-time approval.")
    if not isinstance(context, dict) or set(context) != {"cwd"}:
        raise UnsupportedScope("Trusted working-directory context is missing.")
    cwd = context.get("cwd")
    if not isinstance(cwd, str) or not Path(cwd).is_absolute() or not Path(cwd).is_dir():
        raise UnsupportedScope("The working directory is unavailable.")
    command = tool_input.get("command")
    if not isinstance(command, str) or not command:
        raise UnsupportedScope("The command is missing.")
    if any(os.environ.get(key) for key in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES")):
        raise UnsupportedScope("Environment-based code loading requires one-time approval.")
    argv = _literal_argv(command)
    is_inspection = argv[0] == str(_DEEPAPI_LAUNCHER)
    pins = _inspect_launcher_pins(argv) if is_inspection else []
    if not is_inspection and any(os.environ.get(key) for key in ("BASH_ENV", "ENV")):
        raise UnsupportedScope("Environment-based shell startup requires one-time approval.")
    if not is_inspection and argv[0] in {"/bin/sh", "/bin/bash", "/bin/zsh"}:
        if len(argv) != 3 or argv[1] != "-c":
            raise UnsupportedScope("Login or interactive shell startup requires one-time approval.")
        if argv[0] != "/bin/sh":
            raise UnsupportedScope("This shell's startup environment is not supported for saved approval.")
        pins.append(_pin(Path(argv[0]), executable=True))
        argv = _literal_argv(argv[2])
    if not is_inspection and (Path(argv[0]).name in _INTERPRETERS or re.match(r"^(python|node|perl|ruby)[0-9.]*$", Path(argv[0]).name)):
        raise UnsupportedScope("Interpreter or elevation commands require one-time approval.")
    if not is_inspection and argv[0] not in _ROUTINE_PROGRAMS:
        raise UnsupportedScope("This program needs a reviewed operation adapter before saved approval.")
    if not is_inspection:
        executable = Path(argv[0])
        pins.append(_pin(executable, executable=True))
        with executable.open("rb") as source:
            is_script = source.read(2) == b"#!"
        if is_script:
            raise UnsupportedScope("External scripts need a reviewed dependency scope before persistence.")
        if executable.name == "ssh":
            pins.extend(_ssh_configuration(argv))
    # Do not inspect API-key variables or credential files to fingerprint an
    # action. These are the non-secret execution/routing inputs for adapters.
    keys = ("HOME", "SHELL", "PATH", "ZDOTDIR", "SSH_AUTH_SOCK", "SSH_ASKPASS", "DISPLAY")
    env = {key: os.environ.get(key) for key in keys}
    env["DEEPAPI_SSH_HOST"] = os.environ.get("DEEPAPI_SSH_HOST", "[SSH_HOST]")
    return {
        "kind": "command_exact",
        "actionDigest": hashlib.sha256(json.dumps({
            "tool_name": "Bash", "tool_input": canonical_input("Bash", tool_input),
            "execution_context": {"cwd": str(Path(cwd).resolve())},
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "bindingsDigest": hashlib.sha256(json.dumps({
            "files": pins, "environment": env,
            "identity": [os.getuid(), os.geteuid(), os.getgid(), os.getegid()],
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }
