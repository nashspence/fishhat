"""Exact native target intent and evidence for service/software and routing roles."""

from __future__ import annotations

from typing import Any

from .validation import ContractError, canonical, digest


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


def check_target_request(role: str, request: dict[str, Any]) -> None:
    method, inputs = request["method"], request["input"]
    if role in {"service", "software"} and "target" in inputs:
        target = inputs["target"]
        _require(
            target["executor"]["role"] == role
            and target["executor"]["scope"] == inputs["scope"]
            and target["selection"]["instance"] == target["executor"]["instance"]
            and target["namespace"]["facet"] == ("lifecycle" if role == "service" else "software"),
            "SOURCE_TARGET_IDENTITY",
        )
    if role == "network" and method in {"plan", "publish"}:
        rules = inputs["rules"]
        _require(len({item["handle"] for item in rules}) == len(rules), "DUPLICATE_NETWORK_RULE")
        _require(
            len({(item["direction"], item["endpoint"]) for item in rules}) == len(rules),
            "OVERLAPPING_NETWORK_DECISION",
        )
    if role == "ingress" and method in {"plan", "publish"}:
        routes = inputs["routes"]
        _require(len({item["name"] for item in routes}) == len(routes), "DUPLICATE_INGRESS_ROUTE")
        _require(
            len({item["listener"] for item in routes}) == len(routes),
            "OVERLAPPING_INGRESS_LISTENER",
        )
    if role in {"ingress", "network"} and method in {"plan", "publish"}:
        records = "routes" if role == "ingress" else "rules"
        _require(
            inputs["generation_digest" if role == "ingress" else "policy_digest"]
            == digest(
                {
                    "format": "fishhat.routing-generation/v1",
                    "role": role,
                    "target": inputs["target"],
                    records: inputs[records],
                }
            ),
            "PUBLICATION_GENERATION_DIGEST",
        )


def check_target_response(
    role: str,
    request: dict[str, Any],
    response: dict[str, Any],
    attempt: dict[str, Any] | None,
) -> None:
    if role in {"ingress", "network"}:
        _check_routing_response(role, request, response, attempt)
        return
    if role not in {"service", "software"}:
        return
    inputs, output, method = request["input"], response["output"], request["method"]
    if role == "software" and method == "resolve":
        _require(
            output["target"] == inputs["target"]
            and output["requested_held"] == inputs["held"]
            and output["requested_version"] == inputs["version"],
            "SOFTWARE_RESOLUTION_IDENTITY",
        )
        _require(
            response["coverage"] == ("unknown" if output["state"] == "unknown" else "complete")
            and response["continuation"] is None,
            "SOFTWARE_RESOLUTION_COVERAGE",
        )
        return
    records = output["services" if role == "service" else "packages"]
    identities = [canonical(record["target"]["namespace"]) for record in records]
    _require(len(set(identities)) == len(identities), "DUPLICATE_TARGET_OBSERVATION")
    for record in records:
        target = record["target"]
        _require(
            target["executor"]["role"] == role
            and target["executor"]["scope"] == inputs["scope"]
            and target["selection"]["instance"] == target["executor"]["instance"]
            and target["namespace"]["facet"] == ("lifecycle" if role == "service" else "software")
            and ("target" not in inputs or target == inputs["target"])
            and ("binding" not in inputs or target["executor"] == inputs["binding"]),
            "TARGET_OBSERVATION_IDENTITY",
        )
    if role == "service" and method == "apply":
        _check_service_transition(inputs, response, attempt)
    effect = response.get("effect")
    succeeded = effect is not None and (
        effect["task_state"] == "terminal"
        and effect["effect_certainty"] == "known"
        and effect["postcondition"] == "satisfied"
    )
    if succeeded:
        _check_target_success(role, method, inputs, records)


def _check_routing_response(
    role: str,
    request: dict[str, Any],
    response: dict[str, Any],
    attempt: dict[str, Any] | None,
) -> None:
    """Correlate domain replacement evidence without claiming native CAS qualification."""
    inputs, output, method = request["input"], response["output"], request["method"]
    observed, receipt = output["observed"], output["publication"]
    if observed is not None:
        _require(observed["target"] == inputs["target"], "PUBLICATION_OBSERVATION_TARGET")
        _require(
            observed["generation"] is not None or response["coverage"] == "complete",
            "PUBLICATION_ABSENCE_UNVERIFIED",
        )
    if method != "publish":
        _require(receipt is None, "UNREQUESTED_PUBLICATION_RECEIPT")
        _require(
            method != "observe" or response["coverage"] != "complete" or observed is not None,
            "PUBLICATION_OBSERVATION_REQUIRED",
        )
        return
    if receipt is not None:
        before, after = receipt["before"], receipt["after"]
        _require(
            attempt is not None
            and receipt["attempt_id"] == attempt["attempt_id"]
            and receipt["target"] == inputs["target"]
            and before == inputs["expected_previous"]
            and after["digest"]
            == inputs["generation_digest" if role == "ingress" else "policy_digest"],
            "PUBLICATION_RECEIPT_IDENTITY",
        )
        _require(
            before is None
            or (
                after["native_incarnation"] == before["native_incarnation"]
                and after["revision"] != before["revision"]
            ),
            "PUBLICATION_PREDECESSOR_IDENTITY",
        )
        _require(
            response["effect"]["effect_certainty"] != "none",
            "PUBLICATION_RECEIPT_WITHOUT_EFFECT",
        )
    effect = response["effect"]
    succeeded = (
        effect["task_state"] == "terminal"
        and effect["effect_certainty"] == "known"
        and effect["postcondition"] == "satisfied"
    )
    if succeeded:
        _require(
            response["coverage"] == "complete"
            and receipt is not None
            and observed is not None
            and observed["generation"] == receipt["after"],
            "PUBLICATION_SUCCESS_EVIDENCE",
        )


def _check_target_success(
    role: str, method: str, inputs: dict[str, Any], records: list[dict[str, Any]]
) -> None:
    _require(len(records) == 1, "TARGET_RESULT_CARDINALITY")
    record = records[0]
    if role == "service":
        _require(
            all(record[key] == inputs["intent"][key] for key in ("enabled", "activity")),
            "SERVICE_INTENT_NOT_OBSERVED",
        )
    else:
        _require(
            record["held"] == inputs["held"]
            and record["state"] == ("present" if method == "install" else "absent")
            and (
                method != "install"
                or {canonical(value) for value in record["artifacts"]}
                == {canonical(value) for value in inputs["artifacts"]}
            ),
            "SOFTWARE_POLICY_NOT_OBSERVED",
        )


def _check_service_transition(
    inputs: dict[str, Any], response: dict[str, Any], attempt: dict[str, Any] | None
) -> None:
    action, receipt, effect = (
        inputs["intent"]["transition"],
        response["output"]["transition"],
        response["effect"],
    )
    success = (
        effect["task_state"] == "terminal"
        and effect["effect_certainty"] == "known"
        and effect["postcondition"] == "satisfied"
    )
    if action == "ensure":
        _require(receipt is None, "UNREQUESTED_SERVICE_EVENT")
        return
    _require(not success or receipt is not None, "SERVICE_EVENT_EVIDENCE_REQUIRED")
    if receipt is None:
        return
    _require(
        attempt is not None
        and receipt["attempt_id"] == attempt["attempt_id"]
        and receipt["target"] == inputs["target"]
        and receipt["transition"] == action,
        "SERVICE_EVENT_IDENTITY",
    )
    if receipt["outcome"] == "unsupported":
        _require(
            receipt["mode"] is None
            and not receipt["confirmations"]
            and effect["acknowledgment"] == "rejected"
            and effect["task_state"] == "terminal"
            and effect["effect_certainty"] == "none"
            and effect["postcondition"] == "not-satisfied",
            "UNSUPPORTED_SERVICE_EVENT_HAS_EFFECT",
        )
    if success or receipt["outcome"] == "succeeded":
        _require(success and receipt["outcome"] == "succeeded", "SERVICE_EVENT_OUTCOME")
        actions = [item["action"] for item in receipt["confirmations"]]
        _require(
            (receipt["mode"] == "native" and actions == [action])
            or (
                action == "restart"
                and receipt["mode"] == "stop-start"
                and actions == ["stop", "start"]
            ),
            "SERVICE_EVENT_CONFIRMATIONS",
        )
