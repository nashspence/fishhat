"""Validate executable contracts and synthetic fixtures, without native effects."""

import json
from urllib.parse import urldefrag, urljoin

from fishhat_contracts.operations import validate_operation
from fishhat_contracts.schema_profile import pointer_tokens
from fishhat_contracts.validation import (
    SCHEMAS,
    strict_json,
    strict_yaml,
    validate,
    validate_app,
    validate_cli,
    validate_domain,
    validate_host,
    validate_plan,
)
from jsonschema import Draft202012Validator

from tests.support import fixture_path


def load(path):
    p = fixture_path(path)
    return (
        strict_yaml(p.read_text())
        if p.suffix == ".yaml"
        else strict_json(p.read_bytes(), max_bytes=32 * 1024 * 1024)
    )


def run():
    index = load("index.json")
    assert set(index["schemas"]) == set(SCHEMAS), "schema index mismatch"
    by_id = {s["$id"]: s for s in SCHEMAS.values()}

    def refs(value, base):
        if isinstance(value, dict):
            if "$ref" in value:
                uri, fragment = urldefrag(urljoin(base, value["$ref"]))
                assert uri in by_id, "nonlocal schema reference"
                target = by_id[uri]
                for key in pointer_tokens(fragment, code="invalid schema pointer"):
                    target = target[int(key)] if isinstance(target, list) else target[key]
            for child in value.values():
                refs(child, base)
        elif isinstance(value, list):
            for child in value:
                refs(child, base)

    for s in SCHEMAS.values():
        Draft202012Validator.check_schema(s)
        refs(s, s["$id"])
    for item in index["fixtures"]:
        value = load(item["path"])
        validate(item["schema"], value, item.get("definition"))
        if item["schema"] == "cli-output.schema.json":
            validate_cli(value)
        if item.get("definition") == "Plan":
            validate_plan(value)
        if item.get("definition") == "Operation":
            validate_operation(value)
    validate_domain(load("domain/domain.yaml"))
    validate_host(load("host-node-a/host.yaml"), load("host-node-a/secrets.yaml"))
    for name in ["demo-app", "stateless", "receipts-app"]:
        app = load(name + "/app.yaml")
        catalogue = load(name + "/secrets.yaml") if app["repository_secrets"] else None
        validate_app(app, catalogue)
    actions = load("contracts/actions.json")["actions"]
    assert {a["name"] for a in actions} == {
        x["properties"]["action"]["const"] for x in SCHEMAS["actions.schema.json"]["oneOf"]
    }
    methods = {m["name"] for m in load("contracts/ssh-methods.json")["methods"]}
    assert methods == {
        x["properties"]["method"]["const"] for x in SCHEMAS["ssh-request.schema.json"]["oneOf"]
    }
    assert methods == {
        x["properties"]["method"]["const"]
        for x in SCHEMAS["ssh-response.schema.json"]["oneOf"]
        if "const" in x["properties"]["method"]
    }
    for f in load("contracts/owner-cli.json")["forms"]:
        assert f["use_case"] == "static-help" or f["use_case"] in methods
    print(
        json.dumps(
            {
                "schemas": len(SCHEMAS),
                "fixture_bindings": len(index["fixtures"]),
                "actions": len(actions),
                "owner_methods": len(methods),
                "scope": "contract consistency only; native implementations not qualified",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    run()
