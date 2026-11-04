import copy
import datetime as dt
import json
import unittest
from pathlib import Path

from fishhat_contracts.validation import CATALOGUES, ContractError, strict_yaml
from fishhat_directory.projection import (
    NOW,
    WORKFLOWS,
    ReloadModel,
    allowed_request,
    catalogue,
    discover,
    load_directory,
    metadata,
    prepare_projection,
    validate_directory,
    validate_runtime,
    workflow,
)

from tests.support import fixture_path

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/directory.schema.json"
    ],
    "scope": "local directory projection/reference helpers",
    "relationship": "candidate",
    "reason": "Synthetic input, projection, origin and listener decisions; no running discovery service or network admission is qualified.",
    "claims": [],
}


R = Path(__file__).resolve().parents[1]


class Directory(unittest.TestCase):
    def setUp(self):
        self.v = load_directory(fixture_path("examples/directory/directory.yaml").read_text())
        self.runtime = strict_yaml(fixture_path("examples/directory/runtime.yaml").read_text())

    def test_valid(self):
        prepare_projection(self.v)
        validate_runtime(self.runtime)

    def test_no_owner_credentials(self):
        self.v["ssh_private_key"] = "secret"
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_only_two_sources(self):
        self.v["repositories"].append(copy.deepcopy(self.v["repositories"][0]))
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_distinct_source_ids(self):
        self.v["repositories"][1]["id"] = "fishhat"
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_clone_ssh_username_not_secret(self):
        validate_directory(self.v)

    def test_no_https_userinfo(self):
        self.v["repositories"][0]["clone_url"] = "https://token@forgejo.example.invalid/tools.git"
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_no_password_in_ssh_url(self):
        self.v["repositories"][0]["clone_url"] = (
            "ssh://git:secret@forgejo.example.invalid/tools.git"
        )
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_no_url_query_or_fragment(self):
        for suffix in ["?token=abc", "#ref"]:
            a = copy.deepcopy(self.v)
            a["repositories"][0]["clone_url"] += suffix
            with self.assertRaises(ContractError):
                validate_directory(a)

    def test_no_path_traversal(self):
        self.v["repositories"][0]["clone_url"] = (
            "ssh://git@forgejo.example.invalid/%2e%2e/tools.git"
        )
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_ref_hints_safe(self):
        self.v["repositories"][0]["ref_hint"] = "refs/heads/../../x"
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_no_unknown_network(self):
        with self.assertRaises(ContractError):
            discover(self.v, {"network": "wan"})

    def test_no_role_escalation_selector(self):
        with self.assertRaises(ContractError):
            discover(self.v, {"role": "administrator"})

    def test_filter_no_fallback(self):
        self.assertEqual(discover(self.v, {"network": "vpn"})["catalogue"]["owner_endpoints"], [])

    def test_empty_owners_valid(self):
        self.v["owner_endpoints"] = []
        prepare_projection(self.v)

    def test_duplicate_endpoint_rejected(self):
        self.v["owner_endpoints"].append(copy.deepcopy(self.v["owner_endpoints"][0]))
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_unsafe_alias(self):
        self.v["owner_endpoints"][0]["ssh_alias"] = "ops;whoami"
        with self.assertRaises(ContractError):
            validate_directory(self.v)

    def test_ipv6(self):
        self.v["owner_endpoints"][0]["host"] = "2001:db8::7"
        x = prepare_projection(self.v)
        self.assertIn("[2001:db8::7]", x["html"])

    def test_fresh(self):
        self.assertEqual(catalogue(self.v)["freshness"], "current")

    def test_stale(self):
        self.assertEqual(catalogue(self.v, NOW + dt.timedelta(days=2))["freshness"], "stale")

    def test_clock_uncertain(self):
        self.assertEqual(
            catalogue(self.v, NOW - dt.timedelta(hours=1))["freshness"], "clock-uncertain"
        )

    def test_no_timezone(self):
        with self.assertRaises(ContractError):
            catalogue(self.v, dt.datetime(2026, 10, 18))

    def test_reload_preserves_valid(self):
        text = fixture_path("examples/directory/directory.yaml").read_text()
        x = ReloadModel(text)
        before = copy.deepcopy(x.value)
        self.assertFalse(x.reload("invalid: true"))
        self.assertEqual(before, x.value)

    def test_bad_cold_start(self):
        with self.assertRaises(ContractError):
            ReloadModel("invalid: true")

    def test_duplicate_yaml(self):
        with self.assertRaises(ContractError):
            load_directory("format: first\nformat: second")

    def test_anchor_yaml(self):
        with self.assertRaises(ContractError):
            load_directory("value: &x a\nother: *x")

    def test_input_limit(self):
        with self.assertRaises(ContractError):
            load_directory(" " * 65537)

    def test_output_limit(self):
        with self.assertRaises(ContractError):
            prepare_projection(self.v, limit=1024)

    def test_html_escaped(self):
        self.v["display_name"] = "<script>bad</script>"
        self.v["recovery_hint"] = '" <b>not markup</b>'
        x = prepare_projection(self.v)["html"]
        self.assertNotIn("<script>", x)
        self.assertIn("&lt;script&gt;", x)
        self.assertNotIn("<b>", x)

    def test_no_outbound_addresses_in_args(self):
        with self.assertRaises(ContractError):
            discover(self.v, {"target": "http://169.254.169.254/"})

    def test_workflows_no_execute(self):
        for k in WORKFLOWS:
            self.assertFalse(workflow(k)["executes"])

    def test_unknown_workflow(self):
        with self.assertRaises(ContractError):
            workflow("deploy-now")

    def test_metadata_two_tools(self):
        x = metadata(self.v)
        self.assertEqual(len(x["tools"]), 2)
        self.assertTrue(all(t["name"].startswith("example_ops_") for t in x["tools"]))

    def test_public_schemas_self_contained(self):
        self.assertNotIn('"$ref"', json.dumps(metadata(self.v)))

    def test_metadata_compatibility_local_schema(self):
        from jsonschema import Draft202012Validator

        for t in metadata(self.v)["tools"]:
            Draft202012Validator.check_schema(t["inputSchema"])
            Draft202012Validator.check_schema(t["outputSchema"])

    def test_instructions_portable(self):
        x = " ".join(step for steps in WORKFLOWS.values() for step in steps)
        self.assertIn("virtual environment", x)
        self.assertNotIn("ssh domain-ops-home", x)
        resume = " ".join(workflow("resume")["steps"])
        base = "https://fishhat.invalid/contracts/"
        client = next(
            entry
            for entry in CATALOGUES[base + "client-commands.json"]["commands"]
            if entry["name"] == "workflow resume"
        )
        owner = next(
            entry
            for entry in CATALOGUES[base + "owner-cli.json"]["forms"]
            if entry["use_case"] == client["use_case"]
        )
        self.assertIn(client["use_case"], resume)
        self.assertIn(" ".join(owner["tokens"][1:]), resume)
        self.assertNotIn("workflow.lifecycle", resume)

    def test_native_request_allowed(self):
        self.assertTrue(
            allowed_request(
                self.runtime, remote_ip="192.0.2.2", host_header="directory.example.invalid:9443"
            )
        )

    def test_foreign_origin_denied(self):
        self.assertFalse(
            allowed_request(
                self.runtime,
                remote_ip="192.0.2.2",
                host_header="directory.example.invalid:9443",
                origin="https://evil.example",
            )
        )

    def test_null_origin_denied(self):
        self.assertFalse(
            allowed_request(
                self.runtime,
                remote_ip="192.0.2.2",
                host_header="directory.example.invalid:9443",
                origin="null",
            )
        )

    def test_bad_host_denied(self):
        self.assertFalse(
            allowed_request(self.runtime, remote_ip="192.0.2.2", host_header="localhost")
        )

    def test_wan_denied(self):
        self.assertFalse(
            allowed_request(
                self.runtime, remote_ip="198.51.100.1", host_header="directory.example.invalid:9443"
            )
        )

    def test_wildcard_listener(self):
        self.runtime["bind_addresses"] = ["0.0.0.0"]
        with self.assertRaises(ContractError):
            validate_runtime(self.runtime)

    def test_broad_network(self):
        self.runtime["allowed_cidrs"] = ["0.0.0.0/0"]
        with self.assertRaises(ContractError):
            validate_runtime(self.runtime)

    def test_wrong_listener_network(self):
        self.runtime["bind_addresses"] = ["198.51.100.1"]
        with self.assertRaises(ContractError):
            validate_runtime(self.runtime)
