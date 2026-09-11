#!/bin/bash -p
set -euo pipefail

# Do not inherit a different effective identity under Bash's startup isolation.
if [ "$EUID" -ne "$UID" ]; then
  printf 'DeepAPI launcher requires matching real and effective user IDs.\n' >&2
  exit 2
fi

host="${DEEPAPI_SSH_HOST:-[SSH_HOST]}"
request_timeout_seconds="${DEEPAPI_REQUEST_TIMEOUT_SECONDS:-86400}"
if ! printf '%s' "$request_timeout_seconds" | /usr/bin/grep -Eq '^[0-9]+$'; then
  printf 'DEEPAPI_REQUEST_TIMEOUT_SECONDS must be a non-negative integer.\n' >&2
  exit 2
fi
idempotency_key_override="${DEEPAPI_IDEMPOTENCY_KEY:-}"
if [ -n "$idempotency_key_override" ] \
  && ! printf '%s' "$idempotency_key_override" | /usr/bin/grep -Eq '^[A-Za-z0-9._~-]{8,128}$'; then
  printf 'DEEPAPI_IDEMPOTENCY_KEY must be 8-128 URL-safe characters.\n' >&2
  exit 2
fi
# Keep the [SSH_HOST] transport alive for long research jobs. ConnectTimeout only
# limits the initial SSH handshake; ServerAliveCountMax * ServerAliveInterval is
# a 24-hour tolerance for an otherwise unresponsive connection.
ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=2880
)

usage() {
  printf '%s\n' \
    'Usage:' \
    '  remote-deepapi.sh inspect' \
    '  remote-deepapi.sh read-skill' \
    '  remote-deepapi.sh read-reference <deep-research|scraping|browse-web|send-email|generate-image|manage-agent-state>' \
    '  remote-deepapi.sh update' \
    '  remote-deepapi.sh browser-fetch' \
    '  remote-deepapi.sh request <GET|POST|DELETE> </v1/path>' \
    '  remote-deepapi.sh batch-request POST </v1/path>' \
    '' \
    'Requests time out after 24 hours by default. Set DEEPAPI_REQUEST_TIMEOUT_SECONDS=0 for no timeout.' >&2
  exit 2
}

command_name="${1:-}"

case "$command_name" in
  inspect)
    if [ "$#" -ne 1 ] || [ "$host" != "[SSH_HOST]" ]; then
      printf 'inspect requires the [SSH_HOST] target and no additional arguments.\n' >&2
      exit 2
    fi
    /usr/bin/ssh "${ssh_options[@]}" -o PermitLocalCommand=no -o ClearAllForwardings=yes "$host" 'set -eu
      actual_host=$(hostname)
      [ "$actual_host" = "[SSH_HOST]" ] || { printf "unexpected_host=%s\n" "$actual_host"; exit 20; }
      skill_dir="$HOME/.agents/skills/deepapi"
      [ -r "$skill_dir/SKILL.md" ] || { printf "skill=missing\n"; exit 21; }
      [ -r "$skill_dir/VERSION.txt" ] || { printf "version=missing\n"; exit 22; }
      printf "host=%s\n" "$actual_host"
      printf "skill=%s\n" "$skill_dir"
      printf "version="
      sed -n "1p" "$skill_dir/VERSION.txt"
      printf "updater="
      if [ -x "$HOME/.deepapi/update-skill.sh" ]; then printf "present\n"; else printf "missing\n"; fi'
    ;;
  read-skill)
    ssh "${ssh_options[@]}" "$host" 'cat "$HOME/.agents/skills/deepapi/SKILL.md"'
    ;;
  read-reference)
    reference_name="${2:-}"
    case "$reference_name" in
      deep-research|scraping|browse-web|send-email|generate-image|manage-agent-state) ;;
      *) usage ;;
    esac
    ssh "${ssh_options[@]}" "$host" "cat \"\$HOME/.agents/skills/deepapi/references/$reference_name.md\""
    ;;
  update)
    ssh "${ssh_options[@]}" "$host" '(bash "$HOME/.deepapi/update-skill.sh") >/dev/null 2>&1 &'
    ;;
  browser-fetch)
    remote_python='import http.client
import ipaddress
import json
import socket
import subprocess
import sys
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 32768
ALLOWED_FIELDS = {"url", "mode", "timeoutMs", "networkIdle", "waitSelector"}
ALLOWED_MODES = {"plain", "stealthy", "playwright"}

def fail(message):
    print(json.dumps({"error": message, "status": "rejected"}))
    raise SystemExit(2)

raw_input = sys.stdin.read(MAX_INPUT_BYTES + 1)
if len(raw_input.encode("utf-8")) > MAX_INPUT_BYTES:
    fail("browser-fetch input exceeds 32768 bytes")
try:
    request = json.loads(raw_input)
except Exception as error:
    fail(f"browser-fetch input must be valid JSON: {error}")
if not isinstance(request, dict):
    fail("browser-fetch input must be a JSON object")
unknown = sorted(set(request) - ALLOWED_FIELDS)
if unknown:
    fail("unsupported browser-fetch fields: " + ", ".join(unknown))

url = request.get("url")
if not isinstance(url, str) or not url:
    fail("url is required")
parts = urlsplit(url)
if parts.scheme not in {"http", "https"} or not parts.hostname:
    fail("url must be a public http(s) URL")
if parts.username is not None or parts.password is not None:
    fail("credentials in URLs are not allowed")
try:
    addresses = {
        item[4][0].split("%", 1)[0]
        for item in socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    }
except Exception as error:
    fail(f"url hostname could not be resolved: {error}")
if not addresses:
    fail("url hostname resolved to no addresses")
for address in addresses:
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        fail("url hostname resolved to an invalid address")
    if not parsed_address.is_global:
        fail("browser-fetch is limited to public network addresses")

mode = str(request.get("mode") or "stealthy").lower()
if mode not in ALLOWED_MODES:
    fail("mode must be one of: plain, stealthy, playwright")
timeout_ms = request.get("timeoutMs", 60000)
if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1000 <= timeout_ms <= 120000:
    fail("timeoutMs must be an integer from 1000 through 120000")
network_idle = request.get("networkIdle", False)
if not isinstance(network_idle, bool):
    fail("networkIdle must be a boolean")
wait_selector = request.get("waitSelector")
if wait_selector is not None and (not isinstance(wait_selector, str) or len(wait_selector) > 1000):
    fail("waitSelector must be a string of at most 1000 characters")

payload = {
    "url": url,
    "mode": mode,
    "timeout": timeout_ms,
    "network_idle": network_idle,
    "proxy": None,
}
if wait_selector:
    payload["wait_selector"] = wait_selector

forwarder = r"""
import http.client
import json
import sys

payload = sys.stdin.read()
request = json.loads(payload)
timeout_seconds = max(1, int(request.get("timeout", 60000) / 1000) + 5)
connection = http.client.HTTPConnection("127.0.0.1", 3780, timeout=timeout_seconds)
connection.request("POST", "/scrape", body=payload, headers={"Content-Type": "application/json"})
response = connection.getresponse()
body = response.read()
sys.stdout.buffer.write(body)
raise SystemExit(0 if 200 <= response.status < 300 else 22)
"""

try:
    completed = subprocess.run(
        ["docker", "exec", "-i", "[SSH_HOST]-scrapling", "python", "-c", forwarder],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        timeout=(timeout_ms / 1000) + 15,
        check=False,
    )
except subprocess.TimeoutExpired:
    fail("browser-fetch exceeded its local execution timeout")
if completed.stdout:
    sys.stdout.write(completed.stdout)
if completed.stderr:
    sys.stderr.write(completed.stderr[-2000:])
raise SystemExit(completed.returncode)'

    remote_script='set +x
set -eu
remote_python=$1
python3 -c "$remote_python"'

    printf -v remote_script_quoted '%q' "$remote_script"
    printf -v remote_python_quoted '%q' "$remote_python"
    ssh "${ssh_options[@]}" "$host" "zsh -c $remote_script_quoted -- $remote_python_quoted"
    ;;
  batch-request)
    method="${2:-}"
    api_path="${3:-}"
    method=$(printf '%s' "$method" | tr '[:lower:]' '[:upper:]')
    [ "$method" = "POST" ] || usage
    case "$api_path" in
      /v1/*) ;;
      *) usage ;;
    esac
    if ! printf '%s' "$api_path" | grep -Eq '^/v1/[-A-Za-z0-9._~:/?%=&+]+$'; then
      printf 'Invalid DeepAPI path.\n' >&2
      exit 2
    fi
    batch_timeout_seconds="$request_timeout_seconds"
    if [ "$batch_timeout_seconds" -eq 0 ] || [ "$batch_timeout_seconds" -gt 120 ]; then
      batch_timeout_seconds=120
    fi

    remote_python='import concurrent.futures
import json
import os
import subprocess
import sys

api_path = sys.argv[1]
timeout_seconds = int(sys.argv[2])
base_url = os.environ["DEEPAPI_API_BASE_URL"].rstrip("/")
spec = json.load(sys.stdin)
items = spec.get("requests", [])
max_concurrency = max(1, min(int(spec.get("maxConcurrency", 1)), len(items)))
fail_fast = bool(spec.get("failFast", True))

def failed_response(code, message):
    return {
        "requestId": None,
        "status": "failed",
        "output": None,
        "error": {"code": code, "message": message[-1000:], "retryable": False},
    }

WORKER_CODE = r"""
import json
import os
import sys
import urllib.error
import urllib.request

base_url = sys.argv[1]
api_path = sys.argv[2]
timeout_seconds = int(sys.argv[3])
spec = json.load(sys.stdin)
body = json.dumps(spec["payload"], ensure_ascii=False).encode("utf-8")
request = urllib.request.Request(
    base_url + api_path,
    data=body,
    method="POST",
    headers={
        "Authorization": "Bearer " + os.environ["DEEPAPI_API_KEY"],
        "X-DeepAPI-Skill-Version": os.environ["DEEPAPI_SKILL_VERSION"],
        "Content-Type": "application/json",
        "Idempotency-Key": spec["idempotencyKey"],
    },
)
try:
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read()
except urllib.error.HTTPError as error:
    raw = error.read()
except Exception as error:
    print(json.dumps({
        "requestId": None,
        "status": "failed",
        "output": None,
        "error": {
            "code": "remote_http_error",
            "message": f"{type(error).__name__}: {error}"[-1000:],
            "retryable": False,
        },
    }))
    raise SystemExit(0)
sys.stdout.buffer.write(raw)
"""

def call(item):
    child_input = json.dumps({
        "payload": item["payload"],
        "idempotencyKey": item["idempotencyKey"],
    }, ensure_ascii=False)
    try:
        completed = subprocess.run(
            [sys.executable, "-c", WORKER_CODE, base_url, api_path, str(timeout_seconds)],
            input=child_input,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        response_value = failed_response(
            "client_request_timeout",
            f"The client stopped this research call at its absolute {timeout_seconds}-second deadline.",
        )
    else:
        try:
            parsed = json.loads(completed.stdout)
            response_value = parsed if isinstance(parsed, dict) else None
        except Exception as error:
            response_value = failed_response("invalid_remote_json", str(error))
    if response_value is None:
        response_value = failed_response("empty_remote_response", "DeepAPI returned no JSON body.")
    return {
        "questionId": item["questionId"],
        "response": response_value,
    }

results = []
next_index = 0
stopped_for_failure = False
if items:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrency) as executor:
        active = {}

        def submit_next():
            global next_index
            if next_index >= len(items):
                return False
            item = items[next_index]
            next_index += 1
            active[executor.submit(call, item)] = item["questionId"]
            return True

        for _ in range(max_concurrency):
            if not submit_next():
                break
        while active:
            done, _ = concurrent.futures.wait(
                active,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            completed_count = 0
            for future in done:
                active.pop(future)
                result = future.result()
                results.append(result)
                if result["response"].get("status") not in {"succeeded", "dry_run"}:
                    stopped_for_failure = stopped_for_failure or fail_fast
                completed_count += 1
            if not stopped_for_failure:
                for _ in range(completed_count):
                    if not submit_next():
                        break

deferred_question_ids = [item["questionId"] for item in items[next_index:]]

order = {item["questionId"]: index for index, item in enumerate(items)}
results.sort(key=lambda item: order[item["questionId"]])
successes = sum(
    item["response"].get("status") in {"succeeded", "dry_run"}
    for item in results
)
status = "succeeded" if successes == len(results) else ("partial" if successes else "failed")
print(json.dumps({
    "status": status,
    "requestCount": len(results),
    "results": results,
    "deferredQuestionIds": deferred_question_ids,
}, ensure_ascii=False))'

    remote_script='set +x
set -eu
api_path=$1
request_timeout_seconds=$2
remote_python=$3

if [ -z "${DEEPAPI_API_BASE_URL:-}" ] || [ -z "${DEEPAPI_API_KEY:-}" ]; then
  source "$HOME/.deepapi/env"
fi
if [ -z "${DEEPAPI_API_BASE_URL:-}" ] || [ -z "${DEEPAPI_API_KEY:-}" ]; then
  printf "DeepAPI credentials are unavailable on [SSH_HOST].\n" >&2
  exit 23
fi
export DEEPAPI_API_BASE_URL DEEPAPI_API_KEY
DEEPAPI_SKILL_VERSION=$(sed -n "1p" "$HOME/.agents/skills/deepapi/VERSION.txt")
export DEEPAPI_SKILL_VERSION
python3 -c "$remote_python" "$api_path" "$request_timeout_seconds"'

    printf -v remote_script_quoted '%q' "$remote_script"
    printf -v api_path_quoted '%q' "$api_path"
    printf -v request_timeout_quoted '%q' "$batch_timeout_seconds"
    printf -v remote_python_quoted '%q' "$remote_python"
    ssh "${ssh_options[@]}" "$host" "zsh -c $remote_script_quoted -- $api_path_quoted $request_timeout_quoted $remote_python_quoted"
    ;;
  request)
    method="${2:-}"
    api_path="${3:-}"
    method=$(printf '%s' "$method" | tr '[:lower:]' '[:upper:]')
    case "$method" in
      GET|POST|DELETE) ;;
      *) usage ;;
    esac
    case "$api_path" in
      /v1/*) ;;
      *) usage ;;
    esac
    if ! printf '%s' "$api_path" | grep -Eq '^/v1/[-A-Za-z0-9._~:/?%=&+]+$'; then
      printf 'Invalid DeepAPI path.\n' >&2
      exit 2
    fi

    remote_script='set +x
set -eu
method=$1
api_path=$2
request_timeout_seconds=$3
idempotency_key_override=$4

if [ -z "${DEEPAPI_API_BASE_URL:-}" ] || [ -z "${DEEPAPI_API_KEY:-}" ]; then
  source "$HOME/.deepapi/env"
fi
if [ -z "${DEEPAPI_API_BASE_URL:-}" ] || [ -z "${DEEPAPI_API_KEY:-}" ]; then
  printf "DeepAPI credentials are unavailable on [SSH_HOST].\n" >&2
  exit 23
fi

skill_version=$(sed -n "1p" "$HOME/.agents/skills/deepapi/VERSION.txt")
base_url=${DEEPAPI_API_BASE_URL%/}

case "$method" in
  GET)
    curl -sS --fail-with-body \
      --max-time "$request_timeout_seconds" \
      --config /dev/fd/3 \
      "$base_url$api_path" 3<<CURL_CONFIG
header = "Authorization: Bearer $DEEPAPI_API_KEY"
header = "X-DeepAPI-Skill-Version: $skill_version"
CURL_CONFIG
    ;;
  POST)
    if [ -n "$idempotency_key_override" ]; then
      idempotency_key=$idempotency_key_override
    elif command -v uuidgen >/dev/null 2>&1; then
      idempotency_key=$(uuidgen)
    else
      idempotency_key=$(sed -n "1p" /proc/sys/kernel/random/uuid)
    fi
    curl -sS --fail-with-body -X POST \
      --max-time "$request_timeout_seconds" \
      --config /dev/fd/3 \
      --data-binary @- \
      "$base_url$api_path" 3<<CURL_CONFIG
header = "Authorization: Bearer $DEEPAPI_API_KEY"
header = "X-DeepAPI-Skill-Version: $skill_version"
header = "Content-Type: application/json"
header = "Idempotency-Key: $idempotency_key"
CURL_CONFIG
    ;;
  DELETE)
    curl -sS --fail-with-body -X DELETE \
      --max-time "$request_timeout_seconds" \
      --config /dev/fd/3 \
      "$base_url$api_path" 3<<CURL_CONFIG
header = "Authorization: Bearer $DEEPAPI_API_KEY"
header = "X-DeepAPI-Skill-Version: $skill_version"
CURL_CONFIG
    ;;
esac'

    printf -v remote_script_quoted '%q' "$remote_script"
    printf -v method_quoted '%q' "$method"
    printf -v api_path_quoted '%q' "$api_path"
    printf -v request_timeout_quoted '%q' "$request_timeout_seconds"
    printf -v idempotency_key_quoted '%q' "$idempotency_key_override"
    ssh "${ssh_options[@]}" "$host" "zsh -c $remote_script_quoted -- $method_quoted $api_path_quoted $request_timeout_quoted $idempotency_key_quoted"
    ;;
  *)
    usage
    ;;
esac
