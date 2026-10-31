"""Two independent executable peers exercise one synthetic process protocol."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from io import BytesIO
from pathlib import Path

import pytest
from fishhat_adapters import check_descriptor, process
from fishhat_adapters.process import (
    PROCESS_ARGUMENTS,
    PROCESS_ENVIRONMENT,
    receive_process_result,
    validate_process_launch,
    verify_process_inputs,
    verify_process_outputs,
)
from fishhat_contracts.validation import ContractError, canonical

from scripts.validation_timeouts import Deadline, watchdog
from tests.linear_support import assert_linear, measure
from tests.test_adapter_handoffs import installed, invocation_for, response_for
from tests.test_adapter_invocations import recovered


def expiry_probe(child):
    """Observe intentional expiry after the independent peer established readiness."""
    return child.wait(timeout=0.1)


CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
    ],
    "scope": "fixed executable ABI, exact file custody and response retention across process failure",
    "relationship": "candidate",
    "reason": "Two independent stdlib executables and adversarial byte fixtures establish interoperability only; native authority, sandboxing, durable effects and child supervision remain unqualified.",
    "claims": [],
}


def identity(data, media_type="application/json"):
    return {
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "media_type": media_type,
        "size_bytes": len(data),
    }


def invocation(endpoint="synthetic-state", destination="normal"):
    registry, executor = installed("build", endpoint=endpoint)
    request = {
        "contract": "fishhat.build",
        "method": "build",
        "input": {
            "scope": executor["scope"],
            "source": identity(b"source", "application/octet-stream"),
            "recipe": identity(b"recipe", "application/octet-stream"),
            "destination": destination,
        },
    }
    call = invocation_for(request)
    call["attempt"]["executor"] = executor
    installation, descriptor = registry._installations[executor["installation_digest"]]
    return call, installation, descriptor, {"endpoint": endpoint}


def launch(call, configuration, mode="mutation", inputs=b""):
    payload = call if mode == "mutation" else recovered(call)
    return {
        "format": "fishhat.adapter-process/v1",
        "mode": mode,
        "role": call["attempt"]["executor"]["role"],
        "executor": call["attempt"]["executor"],
        "request": identity(canonical(payload)),
        "configuration": identity(canonical(configuration)),
        "inputs": identity(inputs, "application/x-ndjson"),
        "private_inputs": None,
    }, payload


def run_peer(
    tmp_path,
    peer,
    call,
    installation,
    descriptor,
    configuration,
    *,
    mode="mutation",
    children_quiescent=True,
    peer_prelude="",
    before_ready=None,
):
    work = tmp_path / mode
    work.mkdir()
    (work / "output").mkdir()
    (work / "inputs").mkdir()
    expected_inputs = [call["request"]["input"][name] for name in ("source", "recipe")]
    rows = []
    for name, artifact in zip(("source", "recipe"), expected_inputs, strict=True):
        input_path = "inputs/" + artifact["digest"].removeprefix("sha256:")
        rows.append(canonical({"artifact": artifact, "path": input_path}) + b"\n")
        (work / input_path).write_bytes(name.encode())
    lines = b"".join(rows)
    manifest, payload = launch(call, configuration, mode, lines)
    validate_process_launch(
        manifest,
        payload,
        configuration,
        descriptor=descriptor,
        approved_installation=installation,
        expected_executor=call["attempt"]["executor"],
        expected_private_use=None,
    )
    verify_process_inputs(
        BytesIO(lines),
        identity=manifest["inputs"],
        expected_artifacts=expected_inputs,
        open_artifact=lambda path: (work / path).open("rb"),
    )
    for name, value in (
        ("process.json", manifest),
        ("request.json", payload),
        ("configuration.json", configuration),
    ):
        (work / name).write_bytes(canonical(value))
    (work / "inputs.ndjson").write_bytes(lines)
    template = Path(__file__).parent / "fixtures/adapter-process" / (peer + ".py")
    executable = tmp_path / (peer + "-" + mode)
    executable.write_text("#!" + sys.executable + "\n" + peer_prelude + template.read_text())
    executable.chmod(0o700)
    timed_out = False
    intentional_timeout = mode == "mutation" and call["request"]["input"]["destination"] in {
        "timeout",
        "timeout-after-response",
    }
    with (work / "stdout.bin").open("wb") as stdout, (work / "stderr.bin").open("wb") as stderr:
        child = subprocess.Popen(
            [str(executable), *PROCESS_ARGUMENTS],
            cwd=work,
            env=PROCESS_ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
        )
        try:
            if intentional_timeout:
                if before_ready is not None:
                    before_ready(work, child)
                readiness = work / "output/timeout-ready"
                ready_deadline = Deadline.after(10)
                while not readiness.exists() and child.poll() is None:
                    if not ready_deadline.remaining():
                        pytest.fail("synthetic timeout peer did not establish readiness")
                    time.sleep(0.01)
                assert readiness.read_text() == call["attempt"]["attempt_id"]
                assert (
                    json.loads(Path(configuration["endpoint"]).read_bytes())["attempt_id"]
                    == call["attempt"]["attempt_id"]
                )
            try:
                exit_code = (
                    expiry_probe(child) if intentional_timeout else child.wait(timeout=watchdog(10))
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                child.kill()
                exit_code = child.wait(timeout=watchdog(5))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=watchdog(5))
    response_path = work / "output/response.json"
    with (work / "stdout.bin").open("rb") as output:
        marker = output.read(1025)
    response = response_path.open("rb") if response_path.exists() else BytesIO()
    retained = BytesIO()
    with response:
        receipt = receive_process_result(
            "build",
            call["request"] if mode == "mutation" else payload,
            stdout=marker,
            response_stream=response,
            retained_response=retained,
            exit_code=exit_code,
            timed_out=timed_out,
            children_quiescent=children_quiescent,
            invocation=call,
        )
    assert (work / "stderr.bin").read_bytes()
    material_verified = False
    if receipt.response is not None:
        try:
            verify_process_outputs(
                receipt.response["output"]["artifacts"],
                open_artifact=lambda path: (work / path).open("rb"),
            )
            material_verified = True
        except (ContractError, OSError):
            # Keep the verified response/effect even if its material handoff failed.
            pass
    return receipt, retained.getvalue(), material_verified


@pytest.mark.parametrize("peer", ["independent_a", "independent_b"])
def test_independent_executables_share_one_protocol(tmp_path, monkeypatch, peer):
    monkeypatch.setenv("FISHHAT_HOSTILE_TEST", "must-not-be-inherited")
    state = tmp_path / "native.json"
    call, installation, descriptor, configuration = invocation(str(state))
    receipt, retained, material = run_peer(
        tmp_path, peer, call, installation, descriptor, configuration
    )
    assert receipt.complete and receipt.response["effect"]["postcondition"] == "satisfied"
    assert material and receipt.response["output"]["artifacts"]
    assert canonical(receipt.response) == retained
    replay, _, replay_material = run_peer(
        tmp_path, peer, call, installation, descriptor, configuration, mode="query"
    )
    assert replay.complete and replay.response["method"] == "reconcile"
    assert replay_material and replay.response["output"] == receipt.response["output"]
    assert json.loads(state.read_bytes())["writes"] == 1


@pytest.mark.parametrize("peer", ["independent_a", "independent_b"])
@pytest.mark.parametrize(
    "failure",
    [
        "missing-response",
        "malformed",
        "nonzero-after-response",
        "timeout",
        "timeout-after-response",
        "children",
        "missing-output",
        "changed-output",
    ],
)
def test_uncertain_transport_never_repeats_native_effect_and_keeps_known_response(
    tmp_path, peer, failure
):
    state = tmp_path / "native.json"
    call, installation, descriptor, configuration = invocation(str(state), destination=failure)
    receipt, retained, material = run_peer(
        tmp_path,
        peer,
        call,
        installation,
        descriptor,
        configuration,
        children_quiescent=failure != "children",
    )
    if failure in {"missing-output", "changed-output"}:
        assert receipt.complete and not material
    else:
        assert not receipt.complete
    if failure in {
        "nonzero-after-response",
        "timeout-after-response",
        "children",
        "missing-output",
        "changed-output",
    }:
        assert receipt.response["effect"]["effect_certainty"] == "known"
        assert retained == canonical(receipt.response)
    resolved, _, recovered_material = run_peer(
        tmp_path, peer, call, installation, descriptor, configuration, mode="query"
    )
    assert resolved.complete and recovered_material
    assert json.loads(state.read_bytes())["writes"] == 1
    if receipt.response is not None:
        assert resolved.response["output"] == receipt.response["output"]


@pytest.mark.parametrize("peer", ["independent_a", "independent_b"])
@pytest.mark.parametrize("failure", ["timeout", "timeout-after-response"])
def test_timeout_readiness_is_published_only_after_complete_write(tmp_path, peer, failure):
    state = tmp_path / "native.json"
    call, installation, descriptor, configuration = invocation(str(state), destination=failure)
    peer_prelude = """
from pathlib import Path as _ReadyPath
import time as _ready_time
_ready_write_text = _ReadyPath.write_text

def _pause_ready_write(path, text, *args, **kwargs):
    if path.name.startswith("timeout-ready"):
        with path.open("w", encoding="utf-8") as stream:
            _ReadyPath("output/marker-write-paused").touch()
            while not _ReadyPath("output/marker-write-resume").exists():
                _ready_time.sleep(0.001)
            return stream.write(text)
    return _ready_write_text(path, text, *args, **kwargs)

_ReadyPath.write_text = _pause_ready_write
"""
    observed = []

    def before_ready(work, child):
        paused = work / "output/marker-write-paused"
        deadline = Deadline.after(10)
        while not paused.exists() and child.poll() is None:
            if not deadline.remaining():
                pytest.fail("synthetic readiness writer did not reach the controlled pause")
            time.sleep(0.01)
        assert paused.is_file() and child.poll() is None
        assert not (work / "output/timeout-ready").exists()
        assert json.loads(state.read_bytes())["attempt_id"] == call["attempt"]["attempt_id"]
        observed.append(True)
        (work / "output/marker-write-resume").touch()

    receipt, retained, material = run_peer(
        tmp_path,
        peer,
        call,
        installation,
        descriptor,
        configuration,
        peer_prelude=peer_prelude,
        before_ready=before_ready,
    )
    assert observed == [True] and not receipt.complete
    assert json.loads(state.read_bytes())["writes"] == 1
    if failure == "timeout-after-response":
        assert receipt.response["effect"]["effect_certainty"] == "known"
        assert retained == canonical(receipt.response) and material
    else:
        assert receipt.response is None and not retained and not material


def test_descriptor_must_select_the_fixed_protocol():
    _, _, descriptor, _ = invocation()
    check_descriptor(descriptor)
    descriptor.pop("process_protocol")
    with pytest.raises(ContractError):
        check_descriptor(descriptor)


@pytest.mark.parametrize(
    "change", ["mode", "configuration", "request", "executor", "descriptor", "installation"]
)
def test_launch_rejects_substituted_inputs_and_query_mutation(change):
    call, installation, descriptor, configuration = invocation()
    manifest, payload = launch(call, configuration)
    if change == "mode":
        manifest, payload = launch(call, configuration, mode="query")
        payload = call["request"]
        manifest["request"] = identity(canonical(payload))
    elif change == "configuration":
        configuration["endpoint"] = "different-target"
    elif change == "request":
        payload["request"]["input"]["destination"] = "changed"
    elif change == "executor":
        manifest["executor"] = {**manifest["executor"], "instance_generation": 999}
    elif change == "descriptor":
        descriptor["entrypoint"] = "bin/other-adapter"
    else:
        installation["artifact"]["digest"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError):
        validate_process_launch(
            manifest,
            payload,
            configuration,
            descriptor=descriptor,
            approved_installation=installation,
            expected_executor=call["attempt"]["executor"],
            expected_private_use=None,
        )


@pytest.mark.parametrize(
    "change", ["missing", "extra", "duplicate", "path", "bytes", "truncated-manifest"]
)
def test_protected_input_closure_is_exact_and_complete(change):
    data = b"protected content"
    expected = identity(data, "application/octet-stream")
    entry = {"artifact": expected, "path": "inputs/" + expected["digest"][7:]}
    rows = [entry]
    if change == "missing":
        rows = []
    elif change == "extra":
        rows.append(
            {"artifact": identity(b"other"), "path": "inputs/" + identity(b"other")["digest"][7:]}
        )
    elif change == "duplicate":
        rows *= 2
    elif change == "path":
        entry["path"] = "inputs/" + "f" * 64
    raw = b"".join(canonical(row) + b"\n" for row in rows)
    declared = identity(raw, "application/x-ndjson")
    if change == "truncated-manifest":
        raw = raw[:-1]
    with pytest.raises(ContractError):
        verify_process_inputs(
            BytesIO(raw),
            identity=declared,
            expected_artifacts=[expected],
            open_artifact=lambda _: BytesIO(data + b"extra" if change == "bytes" else data),
        )


def test_repeated_contextual_artifact_identities_share_one_verified_input():
    data = b"one exact byte sequence"
    first = identity(data, "application/json")
    second = identity(data, "application/custom")
    physical = {**first, "media_type": "application/octet-stream"}
    raw = canonical({"artifact": physical, "path": "inputs/" + first["digest"][7:]}) + b"\n"
    opened = []

    def open_artifact(path):
        opened.append(path)
        return BytesIO(data)

    verify_process_inputs(
        BytesIO(raw),
        identity=identity(raw, "application/x-ndjson"),
        expected_artifacts=[first, second, first],
        open_artifact=open_artifact,
    )
    assert opened == ["inputs/" + first["digest"][7:]]
    prefixed = BytesIO(b"unverified prefix\n" + raw)
    prefixed.seek(len(b"unverified prefix\n"))
    with pytest.raises(ContractError, match="byte zero"):
        verify_process_inputs(
            prefixed,
            identity=identity(raw, "application/x-ndjson"),
            expected_artifacts=[first, second],
            open_artifact=open_artifact,
        )
    with pytest.raises(ContractError, match="conflicts"):
        verify_process_inputs(
            BytesIO(raw),
            identity=identity(raw, "application/x-ndjson"),
            expected_artifacts=[first, {**second, "size_bytes": len(data) + 1}],
            open_artifact=open_artifact,
        )
    opened.clear()
    verify_process_outputs([first, second, first], open_artifact=open_artifact)
    assert opened == ["output/artifacts/" + first["digest"][7:]]
    opened.clear()
    verify_process_outputs(
        [first, second],
        open_artifact=open_artifact,
        retained_artifact=lambda key: BytesIO(data) if key == first["digest"] else None,
    )
    assert opened == []
    with pytest.raises(ContractError, match="byte identity"):
        verify_process_outputs(
            [first],
            open_artifact=open_artifact,
            retained_artifact=lambda _: BytesIO(b"x" * len(data)),
        )
    with pytest.raises(ContractError, match="conflicts"):
        verify_process_outputs(
            [first, {**second, "size_bytes": len(data) + 1}], open_artifact=open_artifact
        )


def test_transport_completion_preserves_a_failed_operation_postcondition():
    call, _, _, _ = invocation()
    reply = response_for(call["request"], call["attempt"], {"artifacts": []})
    reply["effect"]["postcondition"] = "not-satisfied"
    encoded = canonical(reply)
    marker = (
        canonical({"format": "fishhat.adapter-process-result/v1", "response": identity(encoded)})
        + b"\n"
    )
    receipt = receive_process_result(
        "build",
        call["request"],
        stdout=marker,
        response_stream=BytesIO(encoded),
        retained_response=BytesIO(),
        exit_code=0,
        timed_out=False,
        children_quiescent=True,
        invocation=call,
    )
    assert receipt.complete
    assert receipt.response["effect"]["postcondition"] == "not-satisfied"


def growth_case(count):
    registry, executor = installed("backup")
    configuration = {"endpoint": "protected-target"}
    installation, descriptor = registry._installations[executor["installation_digest"]]
    artifacts = [
        identity(f"input-{i:04d}".encode(), "application/octet-stream") for i in range(count)
    ]
    request = {
        "contract": "fishhat.backup",
        "method": "store",
        "input": {
            "scope": executor["scope"],
            "repository": "repository:synthetic",
            "object": "object:synthetic",
            "artifacts": artifacts,
        },
    }
    call = invocation_for(request)
    content = {
        "inputs/" + item["digest"][7:]: f"input-{i:04d}".encode()
        for i, item in enumerate(artifacts)
    }
    output_content = {
        "output/artifacts/" + item["digest"][7:]: f"input-{i:04d}".encode()
        for i, item in enumerate(artifacts)
    }
    raw = b"".join(
        canonical({"artifact": item, "path": "inputs/" + item["digest"][7:]}) + b"\n"
        for item in artifacts
    )
    manifest, payload = launch(call, configuration, inputs=raw)
    reply = response_for(
        request,
        call["attempt"],
        {
            "objects": [
                {
                    "handle": "object:synthetic",
                    "repository": "repository:synthetic",
                    "artifacts": artifacts,
                    "completeness": "sealed",
                    "retrieval": "available",
                }
            ]
        },
    )
    encoded = canonical(reply)
    marker = (
        canonical({"format": "fishhat.adapter-process-result/v1", "response": identity(encoded)})
        + b"\n"
    )

    def run():
        validate_process_launch(
            manifest,
            payload,
            configuration,
            descriptor=descriptor,
            approved_installation=installation,
            expected_executor=executor,
            expected_private_use=None,
        )
        verify_process_inputs(
            BytesIO(raw),
            identity=manifest["inputs"],
            expected_artifacts=artifacts,
            open_artifact=lambda path: BytesIO(content[path]),
        )
        receipt = receive_process_result(
            "backup",
            request,
            stdout=marker,
            response_stream=BytesIO(encoded),
            retained_response=BytesIO(),
            exit_code=0,
            timed_out=False,
            children_quiescent=True,
            invocation=call,
        )
        verify_process_outputs(
            artifacts,
            open_artifact=lambda path: BytesIO(output_content[path]),
        )
        return receipt

    return run


def test_process_boundaries_linear_work():
    samples = []
    for count in (16, 64, 256):
        receipt, work = measure(growth_case(count), modules=(process,))
        assert receipt.complete
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    "test_timeout_readiness_is_published_only_after_complete_write": {
        "purpose": "validation-tooling",
        "authority": ["tests/test_adapter_process.py#run_peer"],
        "scope": "synthetic timeout peer readiness under interrupted file publication",
        "relationship": "no-product-claim",
        "reason": "A controlled empty-file write pause verifies fixture synchronization for both independent peers and timeout phases; it does not qualify native process supervision.",
        "claims": [],
    },
    "test_process_boundaries_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            *[
                "packages/fishhat-adapter-protocol/src/fishhat_adapters/process.py#" + name
                for name in (
                    "validate_process_launch",
                    "verify_process_inputs",
                    "verify_process_outputs",
                    "receive_process_result",
                )
            ],
        ],
        "scope": "complete launch, input manifest/artifact and response boundary work over increasing extent",
        "relationship": "scoped-witness",
        "reason": "Deterministic full-extent checks, without native isolation or process cost claims.",
        "claims": [
            "engineering:adapters.process." + name
            for name in (
                "validate_process_launch",
                "verify_process_inputs",
                "verify_process_outputs",
                "receive_process_result",
            )
        ],
    },
}
