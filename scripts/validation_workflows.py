"""Resolve repository-controlled Actions budgets before dependent jobs start."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import yaml

from scripts.validation_timeouts import (
    Policy,
    audit_http_watchdog,
    positive,
    repository_policy,
    using,
    uv_http_watchdog,
)

PLATFORM_MINUTES = 360


def job_plan(nominal: float, policy: Policy) -> dict[str, Any]:
    minutes = policy.units(nominal * 60, unit_seconds=60, maximum=PLATFORM_MINUTES)
    with using(policy):
        contacts = {"uv": uv_http_watchdog(), "audit": audit_http_watchdog()}
    return {"minutes": minutes, "contacts": contacts, "policy": policy.report()}


def plan(workflow: dict[str, Any], variables: dict[str, str]) -> dict[str, Any]:
    policy = Policy.resolve(variables)
    budgets: dict[str, Any] = {}
    job_policies: dict[str, Any] = {}
    contacts: dict[str, Any] = {}
    for name, job in workflow["jobs"].items():
        if name == "watchdogs":
            continue
        nominal = positive(job["env"]["FISHHAT_VALIDATION_NOMINAL_MINUTES"])
        factors = job.get("strategy", {}).get("matrix", {}).get("watchdog_scale")
        if factors:
            cases = {factor: job_plan(nominal, Policy(positive(factor))) for factor in factors}
            budgets[name] = {factor: value["minutes"] for factor, value in cases.items()}
            contacts[name] = {factor: value["contacts"] for factor, value in cases.items()}
            job_policies[name] = {factor: value["policy"] for factor, value in cases.items()}
        else:
            value = job_plan(nominal, policy)
            budgets[name], contacts[name], job_policies[name] = (
                value["minutes"],
                value["contacts"],
                value["policy"],
            )
    return {
        "scale": policy.scale,
        "budgets": budgets,
        "contacts": contacts,
        "job_policies": job_policies,
        "observations": policy.report(),
        "platform_ceiling_minutes": PLATFORM_MINUTES,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    policy = repository_policy(
        os.environ["FISHHAT_VALIDATION_SCALE_DEFINED"], os.environ["FISHHAT_VALIDATION_SCALE_VALUE"]
    )
    selected = {"FISHHAT_VALIDATION_TIMEOUT_SCALE": str(policy.scale)}
    workflow = yaml.load(args.workflow.read_text(), Loader=yaml.BaseLoader)
    value = plan(workflow, selected)
    with args.github_output.open("a") as output:
        output.write("contacts=" + json.dumps(value["contacts"], separators=(",", ":")) + "\n")
        output.write("scale=" + str(value["scale"]) + "\n")
        output.write("budgets=" + json.dumps(value["budgets"], separators=(",", ":")) + "\n")
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
