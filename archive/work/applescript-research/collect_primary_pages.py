"""Retain a complete API result privately while printing only source metadata.

The private source cache is for analysis, not final redistribution of Apple's
full documentation pages. The report and source inventory cite those pages.
"""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
environment = dict(os.environ)
environment["DEEPAPI_REQUEST_TIMEOUT_SECONDS"] = "0"
request = (ROOT / "primary-verification-request.json").read_text()
completed = subprocess.run([str(ROOT / "runtime/remote-deepapi.sh"), "batch-request", "POST", "/v1/scrape/website"],
                           input=request, text=True, capture_output=True, env=environment, check=False)
response = json.loads(completed.stdout)
cache = ROOT / "private-source-cache"
cache.mkdir(mode=0o700, exist_ok=True)
destination = cache / "primary-verification.json"
with destination.open("w") as handle:
    json.dump(response, handle, ensure_ascii=False)
destination.chmod(0o600)
for item in response.get("results", []):
    result = item["response"]
    print(json.dumps({"requestId":result.get("requestId"), "status":result.get("status"), "error":result.get("error"),
                      "next":result.get("next"), "urlOutcomes":result.get("urlOutcomes"),
                      "pages":[{"url":p.get("url"), "title":p.get("title"), "truncated":p.get("truncated"),
                                "characters":len(p.get("markdown") or p.get("text") or "")}
                               for p in result.get("output") or []]}, ensure_ascii=False))
