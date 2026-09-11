"""Install the reviewed user-selected broker mode through normal host permissions.

Default: read-only preflight. --install replaces only the listed broker files
and creates the requested mode setting. No grant records or platform settings
are changed. The host must authorize this installer before it can write.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile


ROOT = Path(__file__).resolve().parent
STAGED = ROOT / "universal-after"
LIVE = Path("[USER_HOME]/.agents/skills/accessible-approvals/scripts")
POLICY = Path("[USER_HOME]/.codex/accessible-approvals/broker-policy.json")
POLICY_BYTES = b'{"version":1,"mode":"no_prompt"}\n'
INSTALL_ORDER = ("broker_policy.py", "similar_command_analyzer.py", "accessible_approval_broker.py", "test_similar_command_workflow.py", "test_universal_broker.py")
FILES = {
    "accessible_approval_broker.py": {
        "after": "317186122448dcdf81e4660b364ddd0f2504e58ec72da2d42c0543252d0745d8",
        "before": "4cde2396117a3a5cb485ee4a9e37782241ae17b0e4997372d5e1f9c4548faef7"
    },
    "broker_policy.py": {
        "after": "e2d244b9d0389be159bbeb0b64d0e6e8442e25bb2e11df578afb87d7f4e94e4b",
        "before": None
    },
    "similar_command_analyzer.py": {
        "after": "37bb766d2c1c086ecc9ab071fee6e78c0cb6132d8e18ebde8469b62b81cea0f0",
        "before": "48cbf6b0ab82c8a7e82cad426c6baa2286d6677b0c204fa64a0f9cc527aa6409"
    },
    "test_similar_command_workflow.py": {
        "after": "dc7dc742e279b5d2d56c59b3694e80a36f39a1969387a358a05cccf3872d454f",
        "before": "385e7b0efae4b3de63b0e5c7b30ddbd18187b27a891c1c729cbb26ee1ffce6ba"
    },
    "test_universal_broker.py": {
        "after": "9bdc86e0ed66eb9f527e4761e537c47b01f96143ce43675802940068c132c7d5",
        "before": None
    }
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path) -> tuple[bytes, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise RuntimeError(f"Refusing an unsafe or unexpected file: {path.name}")
    return path.read_bytes(), stat.S_IMODE(info.st_mode)


def preflight() -> dict:
    if not LIVE.is_dir() or LIVE.is_symlink() or not POLICY.parent.is_dir() or POLICY.parent.is_symlink():
        raise RuntimeError("The expected installed directories are unavailable or linked.")
    if os.path.lexists(POLICY):
        raise RuntimeError("A broker policy now exists. Reinspect it before replacing any user setting.")
    for name in INSTALL_ORDER:
        expected = FILES[name]
        staged, _ = read_regular(STAGED / name)
        if digest(staged) != expected["after"]:
            raise RuntimeError(f"Staged file changed after review: {name}")
        ast.parse(staged, filename=name)
        target = LIVE / name
        if expected["before"] is None:
            if os.path.lexists(target):
                raise RuntimeError(f"A new-file destination already exists: {name}")
        else:
            current, _ = read_regular(target)
            if digest(current) != expected["before"]:
                raise RuntimeError(f"Installed file changed after inspection: {name}")
    return {"status": "ready", "files": list(INSTALL_ORDER), "mode": "no_prompt", "scope": "all tools handled by this user-owned broker", "policy": str(POLICY), "platform_settings_changed": False}


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    fd, filename = tempfile.mkstemp(prefix=".broker-install-", dir=path.parent)
    temporary = Path(filename)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def install() -> dict:
    plan = preflight()
    backup = Path(tempfile.mkdtemp(prefix="universal-install-backup-", dir=ROOT))
    originals = {}
    for name in INSTALL_ORDER:
        if FILES[name]["before"] is not None:
            originals[LIVE / name] = read_regular(LIVE / name)
            shutil.copy2(LIVE / name, backup / name)
        else:
            originals[LIVE / name] = None
    originals[POLICY] = None
    (backup / "RESTORE.json").write_text(json.dumps({"originalPolicy": "absent", "originalFiles": {name: FILES[name]["before"] for name in INSTALL_ORDER}}, indent=2) + "\n")
    written = []
    try:
        # Code first, requested no-prompt mode last. Never temporarily enable
        # a permissive mode against an incomplete code installation.
        for name in INSTALL_ORDER:
            target = LIVE / name
            original = originals[target]
            if original is None:
                if os.path.lexists(target):
                    raise RuntimeError(f"Concurrent file appeared: {name}")
            elif digest(read_regular(target)[0]) != FILES[name]["before"]:
                raise RuntimeError(f"Concurrent edit detected: {name}")
            data, _ = read_regular(STAGED / name)
            if digest(data) != FILES[name]["after"]:
                raise RuntimeError(f"Concurrent staged edit detected: {name}")
            write_atomic(target, data, original[1] if original is not None else 0o600)
            written.append((target, digest(data)))
        if os.path.lexists(POLICY):
            raise RuntimeError("A broker setting appeared during installation.")
        write_atomic(POLICY, POLICY_BYTES, 0o600)
        written.append((POLICY, digest(POLICY_BYTES)))
        for target, expected in written:
            if digest(read_regular(target)[0]) != expected:
                raise RuntimeError(f"Installed verification failed: {target.name}")
    except Exception as error:
        conflicts = []
        for target, expected in reversed(written):
            try:
                if digest(read_regular(target)[0]) != expected:
                    conflicts.append(target.name)
                    continue
                original = originals[target]
                if original is None:
                    target.unlink()
                else:
                    write_atomic(target, *original)
            except Exception:
                conflicts.append(target.name)
        raise RuntimeError(f"Installation failed; backup retained at {backup}. Rollback conflicts: {conflicts}. Cause: {error}") from error
    return {**plan, "status": "installed", "backup": str(backup), "grant_records_changed": False, "launcher_changed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    print(json.dumps(install() if args.install else preflight(), indent=2))
