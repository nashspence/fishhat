"""Second independent synthetic build executable, with no project imports."""

from hashlib import sha256
from json import loads
from os import environ
from pathlib import Path
from sys import argv, stderr, stdout
from time import sleep

from rfc8785 import dumps

assert argv[1:] == ["invoke"]
assert sorted(environ.items()) == [("LANG", "C.UTF-8"), ("LC_ALL", "C.UTF-8"), ("TZ", "UTC")]


def serial(record):
    return dumps(record)


meta = loads(Path("process.json").read_text())
message = loads(Path("request.json").read_text())
settings = loads(Path("configuration.json").read_text())
mutation = meta["mode"] == "mutation"
call = message if mutation else message["input"]["invocation"]
request = call["request"] if mutation else message
attempt = call["attempt"]
inputs = {
    row["artifact"]["digest"]: row["path"]
    for row in map(loads, Path("inputs.ndjson").read_text().splitlines())
}
protected = []
for part in ("source", "recipe"):
    selected = call["request"]["input"][part]
    data = Path(inputs[selected["digest"]]).read_bytes()
    assert len(data) == selected["size_bytes"]
    assert "sha256:" + sha256(data).hexdigest() == selected["digest"]
    protected.append(data)
database = Path(settings["endpoint"])
if mutation:
    count = loads(database.read_text())["writes"] if database.exists() else 0
    product = b"synthetic-build:" + b":".join(protected)
    database.write_bytes(
        serial(dict(writes=count + 1, attempt_id=attempt["attempt_id"], artifact_hex=product.hex()))
    )
else:
    assert request["method"] == "reconcile"
    retained = loads(database.read_text())
    assert retained["attempt_id"] == attempt["attempt_id"]
    product = bytes.fromhex(retained["artifact_hex"])
failure = call["request"]["input"]["destination"] if mutation else "normal"
stderr.write("second independent diagnostic\n")
if failure == "missing-response":
    raise SystemExit(4)
if failure == "timeout":
    Path("output/timeout-ready").write_text(attempt["attempt_id"])
    sleep(30)
product_name = sha256(product).hexdigest()
destination = Path("output/artifacts")
destination.mkdir()
if failure != "missing-output":
    temporary = destination / "result.pending"
    temporary.write_bytes(b"different output" if failure == "changed-output" else product)
    temporary.rename(destination / product_name)
result = dict(
    contract=request["contract"],
    method=request["method"],
    request_digest="sha256:" + sha256(serial(request)).hexdigest(),
    scope=request["input"]["scope"],
    coverage="complete",
    continuation=None,
    proposal=None,
    problem=None,
    output=dict(
        artifacts=[
            dict(
                digest="sha256:" + product_name,
                media_type="application/octet-stream",
                size_bytes=len(product),
            )
        ]
    ),
    effect=dict(
        attempt_id=attempt["attempt_id"],
        input_digest=attempt["input_digest"],
        acknowledgment="accepted",
        task_state="terminal",
        effect_certainty="known",
        postcondition="satisfied",
        native_task=None,
    ),
)
result_bytes = serial(result)
temporary_result = Path("output/result.pending")
temporary_result.write_bytes(result_bytes)
temporary_result.rename("output/response.json")
footer = dict(
    format="fishhat.adapter-process-result/v1",
    response=dict(
        digest="sha256:" + sha256(result_bytes).hexdigest(),
        media_type="application/json",
        size_bytes=len(result_bytes),
    ),
)
stdout.buffer.write(b"malformed response\n" if failure == "malformed" else serial(footer) + b"\n")
stdout.flush()
if failure == "timeout-after-response":
    Path("output/timeout-ready").write_text(attempt["attempt_id"])
    sleep(30)
raise SystemExit(9 if failure == "nonzero-after-response" else 0)
