"""Independent synthetic file-backed build adapter; never native qualification."""

import hashlib
import json
import os
import signal
import sys
from pathlib import Path

import rfc8785


def encode(value):
    return rfc8785.dumps(value)


def digest(value):
    return "sha256:" + hashlib.sha256(encode(value)).hexdigest()


assert sys.argv[1:] == ["invoke"]
assert dict(os.environ) == {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
manifest = json.loads(Path("process.json").read_bytes())
payload = json.loads(Path("request.json").read_bytes())
configuration = json.loads(Path("configuration.json").read_bytes())
assert manifest["format"] == "fishhat.adapter-process/v1"
invocation = payload if manifest["mode"] == "mutation" else payload["input"]["invocation"]
original = invocation["request"]
attempt = invocation["attempt"]
declared_inputs = [json.loads(line) for line in Path("inputs.ndjson").read_bytes().splitlines()]
materials = {}
for name in ("source", "recipe"):
    selected = next(
        item
        for item in declared_inputs
        if item["artifact"]["digest"] == original["input"][name]["digest"]
    )
    materials[name] = Path(selected["path"]).read_bytes()
    assert "sha256:" + hashlib.sha256(materials[name]).hexdigest() == selected["artifact"]["digest"]
    assert len(materials[name]) == original["input"][name]["size_bytes"]
state_path = Path(configuration["endpoint"])
if manifest["mode"] == "mutation":
    previous = json.loads(state_path.read_bytes()) if state_path.exists() else {"writes": 0}
    produced_bytes = b"synthetic-build:" + materials["source"] + b":" + materials["recipe"]
    state_path.write_bytes(
        encode(
            {
                "attempt_id": attempt["attempt_id"],
                "writes": previous["writes"] + 1,
                "artifact_hex": produced_bytes.hex(),
            }
        )
    )
else:
    assert payload["method"] == "reconcile"
    previous = json.loads(state_path.read_bytes())
    assert previous["attempt_id"] == attempt["attempt_id"]
    produced_bytes = bytes.fromhex(previous["artifact_hex"])
mode = original["input"]["destination"] if manifest["mode"] == "mutation" else "normal"
print("synthetic diagnostic", file=sys.stderr)
if mode == "missing-response":
    raise SystemExit(4)
if mode == "timeout":
    ready = Path("output/timeout-ready.pending")
    ready.write_text(attempt["attempt_id"])
    ready.replace("output/timeout-ready")
    signal.pause()
query = original if manifest["mode"] == "mutation" else payload
produced_digest = hashlib.sha256(produced_bytes).hexdigest()
Path("output/artifacts").mkdir()
if mode != "missing-output":
    material_path = Path("output/artifacts") / (produced_digest + ".pending")
    material_path.write_bytes(b"changed output" if mode == "changed-output" else produced_bytes)
    material_path.replace(Path("output/artifacts") / produced_digest)
response = {
    "contract": query["contract"],
    "method": query["method"],
    "request_digest": digest(query),
    "scope": query["input"]["scope"],
    "coverage": "complete",
    "continuation": None,
    "proposal": None,
    "problem": None,
    "output": {
        "artifacts": [
            {
                "digest": "sha256:" + produced_digest,
                "media_type": "application/octet-stream",
                "size_bytes": len(produced_bytes),
            }
        ]
    },
    "effect": {
        "attempt_id": attempt["attempt_id"],
        "input_digest": attempt["input_digest"],
        "acknowledgment": "accepted",
        "task_state": "terminal",
        "effect_certainty": "known",
        "postcondition": "satisfied",
        "native_task": None,
    },
}
data = encode(response)
pending_response = Path("output/response.pending")
pending_response.write_bytes(data)
pending_response.replace("output/response.json")
if mode == "malformed":
    sys.stdout.write("malformed response\n")
else:
    sys.stdout.buffer.write(
        encode(
            {
                "format": "fishhat.adapter-process-result/v1",
                "response": {
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "media_type": "application/json",
                    "size_bytes": len(data),
                },
            }
        )
        + b"\n"
    )
sys.stdout.flush()
if mode == "timeout-after-response":
    ready = Path("output/timeout-ready.pending")
    ready.write_text(attempt["attempt_id"])
    ready.replace("output/timeout-ready")
    signal.pause()
raise SystemExit(9 if mode == "nonzero-after-response" else 0)
