"""Portable application approval bytes and state-specific cutover evidence."""

import json
from copy import deepcopy
from hashlib import sha256

import pytest
from fishhat_contracts.application_boundary import application_boundary, validate_release_boundary
from fishhat_contracts.readiness import require_readiness, validate_readiness
from fishhat_contracts.validation import ContractError, digest, strict_yaml, validate

from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/ApplicationBoundaryDigest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/readiness.schema.json",
    ],
    "scope": "portable application boundary approval and resource-specific cutover readiness",
    "relationship": "candidate",
    "reason": "A golden preimage and adverse packets exercise reference joins without native qualification.",
    "claims": [],
}


def sources():
    return [
        strict_yaml((FIXTURES / path).read_text())
        for path in (
            "domain/domain.yaml",
            "host-node-a/host.yaml",
            "demo-app/app.yaml",
            "demo-app/secrets.yaml",
        )
    ]


def test_boundary_projection_vector_and_review_stability():
    domain, host, app, catalogue = sources()
    vector = json.loads((FIXTURES / "release-identity/application-boundary.json").read_text())
    expected = "sha256:b229758aa14534a652587a65439c80a45b32c1bc2d7c7a0e6a38880cec11d1d2"
    assert application_boundary(domain, host, app, catalogue) == vector
    assert digest(vector) == domain["apps"][app["id"]]["boundary_digest"] == expected
    app["datasets"]["state"]["writers"].reverse()
    app["runtime"]["source"]["files"].reverse()
    app["maintenance"]["daily-backup"]["calendar"] = "*-*-* 04:00:00"
    app["purpose"] += " other description"
    app["components"]["web"]["native"] = {"unit": "another-version.container"}
    assert digest(application_boundary(domain, host, app, catalogue)) == expected
    for edit in ("role", "consumer", "grant", "secret-policy"):
        other_app, other_host, other_cat = deepcopy(app), deepcopy(host), deepcopy(catalogue)
        if edit == "role":
            other_app["components"]["database"]["role"] = "primary"
        elif edit == "consumer":
            other_app["secret_bindings"]["other"] = {
                **other_app["secret_bindings"]["database-password"],
                "component": "web",
            }
        elif edit == "grant":
            other_host["grants"]["demo-app-data"]["resources"].append("dataset:extra")
        else:
            other_cat["entries"]["db-password"]["value_policy"] = "fixed"
        assert digest(application_boundary(domain, other_host, other_app, other_cat)) != expected


def test_boundary_requires_independent_approval_and_same_source():
    domain, host, app, catalogue = sources()
    release = json.loads((FIXTURES / "release-identity/release.json").read_text())
    placement = domain["apps"][app["id"]]
    source = domain["sources"][placement["source"]]
    blobs = {
        name: (FIXTURES / "demo-app" / name).read_bytes() for name in ("app.yaml", "secrets.yaml")
    }
    pinned_files = {
        name: {"mode": "100644", "digest": "sha256:" + sha256(data).hexdigest()}
        for name, data in blobs.items()
    }
    app_source = {
        **release["sources"][0],
        "source_id": placement["source"],
        "repository": source["repository"],
        "entrypoint": source["entrypoint"],
        "closure_digest": digest(
            {
                "format": "fishhat.source-closure/v1",
                "entrypoint": "app.yaml",
                "files": pinned_files,
            }
        ),
    }
    release["sources"] = [deepcopy(app_source)]
    release["boundary_digest"] = placement["boundary_digest"]
    context = dict(
        domain=domain,
        host=host,
        expected_app_instance=release["app_instance"],
        app_source=app_source,
        pinned_files=pinned_files,
        app_blob=blobs["app.yaml"],
        catalogue_blob=blobs["secrets.yaml"],
    )

    def verify(**overrides):
        release["digest"] = digest({k: v for k, v in release.items() if k != "digest"})
        validate_release_boundary(
            release, expected_release_digest=release["digest"], **(context | overrides)
        )

    verify()
    for key, substitute in (
        ("source_id", "other"),
        ("entrypoint", "other.yaml"),
        ("commit", "f" * 40),
        ("closure_digest", digest("another tree")),
    ):
        release["sources"][0][key] = substitute
        with pytest.raises(ContractError, match="source"):
            verify()
        release["sources"] = [deepcopy(app_source)]
    for name in ("app_blob", "catalogue_blob"):
        with pytest.raises(ContractError, match="pinned source"):
            verify(**{name: context[name] + b"\n"})
    with pytest.raises(ContractError, match="pinned source"):
        verify(catalogue_blob=None)
    with pytest.raises(ContractError, match="application instance"):
        verify(expected_app_instance="prod:" + "b" * 64)
    placement["boundary_digest"] = digest("another approval")
    with pytest.raises(ContractError, match="approved domain"):
        verify()
    catalogue["repository"]["repository_id"] += 1
    with pytest.raises(ContractError, match="repository mismatch"):
        application_boundary(domain, host, app, catalogue)


def test_readiness_binds_state_cases_exemptions_and_required_material():
    packet = json.loads((FIXTURES / "readiness.json").read_text())
    validate_readiness(packet)
    for state in ("ready", "cutting-over", "accepted"):
        with pytest.raises(ContractError):
            validate("readiness.schema.json", {**packet, "state": state})
    resource = deepcopy(packet["resource"])
    approved_source = json.loads((FIXTURES / "release-identity/release.json").read_text())[
        "sources"
    ][0]
    proof = digest("native restore evidence")
    packet.update(
        state="ready",
        source_refs=[approved_source],
        owner_approval="approval-record",
        max_downtime_seconds=30,
        max_data_loss_seconds=0,
        retention_disposition="retain",
        required_cases=["restore"],
        case_evidence={"restore": {"status": "passed", "evidence": proof, "reason": None}},
        independent_restore_evidence=proof,
    )

    def verify(**overrides):
        args = dict(
            expected_resource=resource,
            expected_state="ready",
            approved_packet_digest=digest(packet),
            required_cases={"restore"},
            approved_exemptions={},
            verified_cases={"restore": proof},
            required_material={"independent_restore_evidence": proof},
        )
        require_readiness(packet, **(args | overrides))

    verify()
    for args in (
        {"expected_state": "accepted"},
        {"expected_resource": {**resource, "id": "other-app"}},
        {"approved_packet_digest": proof},
        {"required_cases": {"restore", "fence"}},
        {"required_material": {"checkpoint": proof}},
        {"required_material": {}},
        {"required_material": {"independent_restore_evidence": digest("stale")}},
        {"verified_cases": {}},
        {"verified_cases": {"restore": digest("stale")}},
    ):
        with pytest.raises(ContractError):
            verify(**args)
    for status in ("failed", "not_run", "missing"):
        case = packet["case_evidence"].pop("restore", {})
        packet["case_evidence"] = (
            {} if status == "missing" else {"restore": {**case, "status": status}}
        )
        with pytest.raises(ContractError):
            verify()
    packet["case_evidence"] = {
        "restore": {"status": "not_applicable", "reason": "no persistent data", "evidence": proof}
    }
    with pytest.raises(ContractError, match="exemption"):
        verify()
    verify(approved_exemptions={"restore": proof})
    packet["state"] = "cutting-over"
    with pytest.raises(ContractError):
        verify(expected_state="cutting-over", approved_exemptions={"restore": proof})
    fence = digest("observed writer exclusion")
    packet["fence_evidence"] = [fence]
    with pytest.raises(ContractError, match="profile-required"):
        verify(expected_state="cutting-over", approved_exemptions={"restore": proof})
    for selected in ({digest("other-fence")}, {fence, digest("omitted-fence")}):
        with pytest.raises(ContractError, match="fence evidence"):
            verify(
                expected_state="cutting-over",
                approved_exemptions={"restore": proof},
                required_material={
                    "independent_restore_evidence": proof,
                    "fence_evidence": selected,
                },
            )
    verify(
        expected_state="cutting-over",
        approved_exemptions={"restore": proof},
        required_material={"independent_restore_evidence": proof, "fence_evidence": {fence}},
    )
