"""Test the ordinary updater against local fixtures, without network or live writes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent

with tempfile.TemporaryDirectory(prefix="deepapi-update-policy-test-") as temporary:
    root = Path(temporary)
    install = root / "installation"
    target = install / ".agents/skills/deepapi"
    (target / "references").mkdir(parents=True)
    (install / ".deepapi").mkdir()
    source = ROOT / "remote-after/SKILL.md"
    shutil.copy2(source, target / "SKILL.md")
    shutil.copy2(ROOT / "remote-after/deep-research.md", target / "references/deep-research.md")
    updater = install / ".deepapi/update-skill.sh"
    shutil.copy2(ROOT / "updater-inspected.sh", updater)
    hosted = root / "hosted/deepapi-skill"
    (hosted / "deepapi/references").mkdir(parents=True)
    upstream = {
        "SKILL.md": (ROOT / "remote-before/SKILL.md").read_bytes(),
        "references/deep-research.md": (ROOT / "remote-before/deep-research.md").read_bytes(),
        "VERSION.txt": b"8d3db9c52227\n",
    }
    entries = ["8d3db9c52227"]
    for name, content in upstream.items():
        (hosted / "deepapi" / name).write_bytes(content)
        entries.append(hashlib.sha256(content).hexdigest() + " deepapi/" + name + " " + name)
    (hosted / "MANIFEST.txt").write_text("\n".join(entries) + "\n")
    binary = root / "bin"
    binary.mkdir()
    fake_curl = binary / "curl"
    fake_curl.write_text("#!/usr/bin/python3\nimport os,shutil,sys\nfrom pathlib import Path\na=sys.argv[1:]\nu=next(x for x in a if x.startswith('https://fixture.invalid/'))\np=Path(os.environ['FIXTURE_WEB_ROOT'])/u.removeprefix('https://fixture.invalid/')\nshutil.copyfile(p,a[a.index('-o')+1])\n")
    # Python 3.9+ is available to this test fixture; it never opens a socket.
    fake_curl.chmod(0o700)
    env = dict(os.environ)
    env.update({"DEEPAPI_INSTALL_HOME": str(install), "DEEPAPI_API_BASE_URL": "https://fixture.invalid",
                "FIXTURE_WEB_ROOT": str(root / "hosted"), "PATH": str(binary) + os.pathsep + env.get("PATH", "/usr/bin:/bin")})
    env.pop("DEEPAPI_FORCE_SKILL_UPDATE", None)
    env.pop("BASH_ENV", None)
    env.pop("ENV", None)
    completed = subprocess.run(["/bin/bash", str(updater)], env=env, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr or completed.stdout)
    preserved = (target / "SKILL.md").read_bytes() == source.read_bytes()
    reference_refreshed = (target / "references/deep-research.md").read_bytes() == upstream["references/deep-research.md"]
    text = (target / "SKILL.md").read_text()
    override = "there is no fixed minimum number of searches" in text and "takes precedence over numeric query-count recommendations" in text
    assert preserved and reference_refreshed and override
    print(json.dumps({"status": "passed", "customized_router_preserved": preserved,
                      "managed_reference_refreshed": reference_refreshed,
                      "effective_no_minimum_override_preserved": override,
                      "network_used": False, "live_installations_changed": False,
                      "updater_output": completed.stdout.strip()}, indent=2))
