"""Apply only the reviewed DeepAPI search-count edits over the authorized SSH route."""
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent
payload = {
    "SKILL.md": {"before": "aa1ca4fb9b1fd3ba942ef2af71d6fd2d0ba1ee33ea36a059fa2f1d001a065af4", "text": (ROOT / "remote-after/SKILL.md").read_text()},
    "references/deep-research.md": {"before": "d744e6574f89b55f80519afcab5a92abee8fd4b066ea26ea42d000eab001a3e2", "text": (ROOT / "remote-after/deep-research.md").read_text()},
}
remote = r'''
import hashlib, json, os, shutil, stat, sys, tempfile
from pathlib import Path
root = Path("[REMOTE_HOME]/.agents/skills/deepapi")
items = json.load(sys.stdin)
if set(items) != {"SKILL.md", "references/deep-research.md"}:
    raise SystemExit("Unexpected target set")
originals = {}
for name, item in items.items():
    path = root / name
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid():
        raise SystemExit("Unsafe target type or owner")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != item["before"]:
        raise SystemExit("Source changed since inspection: " + name)
    originals[name] = (content, stat.S_IMODE(meta.st_mode))
backup_root = Path("[REMOTE_HOME]/.agents/skill-backups/deepapi")
backup_root.mkdir(parents=True, exist_ok=True)
backup = Path(tempfile.mkdtemp(prefix="search-minimum-", dir=backup_root))
for name in items:
    saved = backup / name
    saved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / name, saved)
def write(path, content, mode):
    fd, temporary = tempfile.mkstemp(prefix=".search-rule-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
changed = []
try:
    for name, item in items.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != item["before"]:
            raise RuntimeError("Concurrent source change")
        write(root / name, item["text"].encode(), originals[name][1])
        changed.append(name)
    result = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in items}
    if any(result[name] != hashlib.sha256(items[name]["text"].encode()).hexdigest() for name in items):
        raise RuntimeError("Verification mismatch")
except Exception:
    for name in changed:
        if (root / name).read_bytes() == items[name]["text"].encode():
            write(root / name, *originals[name])
    raise
print(json.dumps({"status":"updated", "backup":str(backup), "files":result}))
'''
result = subprocess.run(["ssh", "[SSH_HOST]", "python3 -c " + shlex.quote(remote)], input=json.dumps(payload), text=True, capture_output=True, check=False)
print(result.stdout, end="")
if result.stderr:
    print(result.stderr, file=__import__("sys").stderr, end="")
raise SystemExit(result.returncode)
