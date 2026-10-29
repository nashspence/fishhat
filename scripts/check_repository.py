from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import Any

from scripts.project_policy import ROOT, read_toml
from scripts.validation_timeouts import invocation, watchdog


def api(path: str, *args: str) -> Any:
    command = ["gh", "api", "--hostname", "github.com", path, *args]
    result = subprocess.run(command, capture_output=True, text=True, timeout=watchdog(30))
    if result.returncode:
        raise RuntimeError("repository control read failed")
    return json.loads(result.stdout) if result.stdout else None


def validate_controls(policy: dict[str, Any], observed: dict[str, Any], scope: str) -> list[str]:
    expected = policy["governance"]
    errors = []
    repo = observed["repository"]
    admin_settings = {
        "allow_auto_merge",
        "allow_merge_commit",
        "allow_rebase_merge",
        "allow_squash_merge",
        "delete_branch_on_merge",
    }
    for key, value in expected["repository"].items():
        if scope == "public" and key in admin_settings:
            continue
        if repo.get(key) != value:
            errors.append("repository setting: " + key)
    if observed["creation"] != {
        "issueCreationPolicy": "COLLABORATORS_ONLY",
        "pullRequestCreationPolicy": "COLLABORATORS_ONLY",
    }:
        errors.append("collaborator-only creation policy")
    active = [
        ruleset
        for ruleset in observed["rulesets"]
        if ruleset.get("enforcement") == "active"
        and "refs/heads/" + expected["branch"]
        in ruleset.get("conditions", {}).get("ref_name", {}).get("include", [])
    ]
    if len(active) != 1:
        errors.append("one active main ruleset required")
    else:
        ruleset = active[0]
        if ruleset.get("bypass_actors"):
            errors.append("main bypass actors")
        rules = {rule["type"]: rule.get("parameters", {}) for rule in ruleset["rules"]}
        for name in (
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "pull_request",
            "required_status_checks",
            "code_scanning",
        ):
            if name not in rules:
                errors.append("main rule: " + name)
        status = rules.get("required_status_checks", {})
        actual = {
            item["context"]: item.get("integration_id")
            for item in status.get("required_status_checks", [])
        }
        desired = dict.fromkeys(expected["required_checks"], expected["workflow_integration_id"])
        if actual != desired or not status.get("strict_required_status_checks_policy"):
            errors.append("required check set or up-to-date policy")
        pull = rules.get("pull_request", {})
        if pull.get("allowed_merge_methods") != ["squash"] or not pull.get(
            "required_review_thread_resolution"
        ):
            errors.append("squash-only resolved PR policy")
        tools = rules.get("code_scanning", {}).get("code_scanning_tools", [])
        if tools != [
            {
                "tool": "CodeQL",
                "security_alerts_threshold": expected["security"]["security_alerts_threshold"],
                "alerts_threshold": expected["security"]["alerts_threshold"],
            }
        ]:
            errors.append("all-severity CodeQL merge protection")
    if scope == "full":
        if observed.get("immutable", {}).get("enabled") is not True:
            errors.append("immutable releases")
        if observed.get("fixes", {}).get("enabled") is not True or observed.get("fixes", {}).get(
            "paused"
        ):
            errors.append("Dependabot security updates")
        for key in ("secret_scanning", "secret_scanning_push_protection"):
            if (
                repo.get("security_and_analysis", {}).get(key, {}).get("status")
                != expected["security"][key]
            ):
                errors.append(key)
        if observed.get("workflow_permissions") != expected["workflows"]:
            errors.append("least-privilege workflow defaults")
        environment = observed.get("environment", {})
        reviewers = [
            rule
            for rule in environment.get("protection_rules", [])
            if rule.get("type") == "required_reviewers"
        ]
        if not reviewers or not any(
            person.get("reviewer", {}).get("login") == expected["repository_name"].split("/")[0]
            for rule in reviewers
            for person in rule.get("reviewers", [])
        ):
            errors.append("release publication reviewer")
        branches = observed.get("environment_branches", {}).get("branch_policies", [])
        if [(item["name"], item["type"]) for item in branches] != [(expected["branch"], "branch")]:
            errors.append("release publication branch policy")
    return sorted(set(errors))


def observe(policy: dict[str, Any], scope: str) -> dict[str, Any]:
    name = policy["governance"]["repository_name"]
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", name):
        raise ValueError("invalid repository identity")
    prefix = "repos/" + name
    owner, repo = name.split("/")
    query = (
        'query{repository(owner:"'
        + owner
        + '",name:"'
        + repo
        + '"){issueCreationPolicy pullRequestCreationPolicy}}'
    )
    observed = {
        "repository": api(prefix),
        "creation": api("graphql", "-f", "query=" + query)["data"]["repository"],
        "rulesets": [],
    }
    for item in api(prefix + "/rulesets"):
        if item["enforcement"] == "active":
            observed["rulesets"].append(api(prefix + "/rulesets/" + str(item["id"])))
    if scope == "full":
        observed.update(
            immutable=api(prefix + "/immutable-releases"),
            fixes=api(prefix + "/automated-security-fixes"),
            workflow_permissions=api(prefix + "/actions/permissions/workflow"),
        )
        env = prefix + "/environments/" + policy["publication"]["environment"]
        observed["environment"] = api(env)
        observed["environment_branches"] = api(env + "/deployment-branch-policies")
    return observed


@invocation
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=["public", "full"], default="full")
    args = parser.parse_args()
    policy = read_toml(ROOT / "release.toml")
    try:
        errors = validate_controls(policy, observe(policy, args.scope), args.scope)
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired):
        raise SystemExit("repository audit could not read the required controls") from None
    if errors:
        raise SystemExit("\n".join(errors))
    print(
        json.dumps(
            {"passed": True, "scope": args.scope, "admin_controls_checked": args.scope == "full"}
        )
    )


if __name__ == "__main__":
    main()
