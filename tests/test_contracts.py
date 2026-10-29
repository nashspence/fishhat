"""Current offline contract cases, not native acceptance."""

import copy
import io
import shlex
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame, select_target, ssh_command
from fishhat_contracts.secrets import MAX_ENTRY, build_tar, inspect_tar, select_asset
from fishhat_contracts.validation import (
    ContractError,
    canonical,
    digest,
    require_acyclic,
    strict_json,
    strict_yaml,
    validate,
    validate_app,
    validate_cli,
    validate_domain,
    validate_host,
    validate_plan,
)
from fishhat_contracts.witness import sign, verify
from fishhat_owner.journal import Journal

from tests.support import fixture_path

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": ["policy/interfaces.json#/python/fishhat_contracts"],
    "scope": "offline contract library candidates",
    "relationship": "candidate",
    "reason": "Reviewed parsing, schema, wire, secret and witness cases exercise local helpers. Public API shape is authoritative here; behavior beyond the exact fixtures lacks an independently bound sufficient oracle.",
    "claims": [],
}


def load(path):
    p = fixture_path(path)
    return strict_yaml(p.read_text()) if p.suffix == ".yaml" else strict_json(p.read_bytes())


def uid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "synthetic-test.invalid/" + name))


OWNER = {"tool": "app-ops", "id": uid("owner"), "epoch": uid("epoch")}
SUBJECT = load("examples/plan-input.json")["subject"]


def wb(subject):
    return {
        "format": "deployment-ops/witness/v1",
        "id": uid("witness"),
        "owner": OWNER,
        "kind": "plan",
        "subject_digest": subject,
        "workflow_id": None,
        "generation": 0,
        "state": "planned",
        "boot_id": None,
        "evidence_digests": [],
        "created_at": "2026-10-17T00:00:00Z",
        "key_id": "test-owner",
    }


def plan():
    p = {
        "format": "deployment-ops/record/v1",
        "kind": "Plan",
        "id": uid("plan"),
        "owner": OWNER,
        "subject": SUBJECT,
        "summary": "Restart the web component of demo-app using its accepted release.",
        "data_consequences": "Keep stored application data; normal writes may resume after restart.",
        "recovery_limits": "Inspect the accepted operation before retrying; restart does not undo writes.",
        "created_at": "2026-10-17T00:00:00Z",
        "expires_at": "2026-10-17T01:00:00Z",
        "input_digests": [digest(SUBJECT)],
        "preconditions": [
            {
                "owner": OWNER,
                "resource": SUBJECT["resource"],
                "generation": 0,
                "source_digests": [],
                "holds_digest": digest([]),
            }
        ],
        "effects": [
            {
                "step": "restart",
                "executor": OWNER,
                "resource": SUBJECT["resource"],
                "summary": "Restart the web component; leave other components running.",
                "action": "admitted-restart",
                "input_digest": digest(SUBJECT),
                "reconciliation": "inspect-runtime",
            }
        ],
        "checkpoint_required": False,
        "interruption": "One admitted component restart",
        "recovery": ["native-reconcile"],
        "blockers": [],
    }
    p["digest"] = digest(p)
    p["witness"] = sign(wb(p["digest"]), Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    return p


class Parsing(unittest.TestCase):
    def test_json_roundtrip(self):
        self.assertEqual(
            strict_json(canonical({"é": True, "z": [1, None]})), {"é": True, "z": [1, None]}
        )

    def test_duplicate_json(self):
        with self.assertRaises(ContractError):
            strict_json('{"a":1,"a":2}')

    def test_float(self):
        self.assertEqual(strict_json('{"a":1.1}'), {"a": 1.1})

    def test_nonfinite(self):
        for x in ["NaN", "Infinity", "-Infinity"]:
            with self.subTest(x=x), self.assertRaises(ContractError):
                strict_json(x)

    def test_large_int(self):
        with self.assertRaises(ContractError):
            canonical(9007199254740992)

    def test_surrogate(self):
        with self.assertRaises(ContractError):
            strict_json('"\\ud800"')

    def test_trailing_json(self):
        with self.assertRaises(ContractError):
            strict_json("{}{}")

    def test_size_limit(self):
        with self.assertRaises(ContractError):
            strict_json('"aaaa"', 3)

    def test_utf8(self):
        with self.assertRaises(ContractError):
            strict_json(b"\xff")

    def test_depth(self):
        v = 0
        for _ in range(66):
            v = [v]
        with self.assertRaises(ContractError):
            canonical(v)

    def test_canonical(self):
        self.assertEqual(canonical({"b": 1, "a": "é"}), b'{"a":"\xc3\xa9","b":1}')

    def test_yaml_duplicate(self):
        with self.assertRaises(ContractError):
            strict_yaml("x: 1\nx: 2\n")

    def test_yaml_alias(self):
        with self.assertRaises(ContractError):
            strict_yaml("x: &a [1]\ny: *a")

    def test_yaml_tag(self):
        with self.assertRaises(ContractError):
            strict_yaml("x: !!str 3")

    def test_yaml_directive(self):
        with self.assertRaises(ContractError):
            strict_yaml("%YAML 1.1\n---\nx: 2")

    def test_yaml_documents(self):
        with self.assertRaises(ContractError):
            strict_yaml("x: 1\n---\nx: 2")

    def test_yaml_complex(self):
        with self.assertRaises(ContractError):
            strict_yaml("? [x,y]\n: 1")

    def test_yaml_scalars(self):
        self.assertEqual(
            strict_yaml("x: yes\ny: true\nz: 0600"), {"x": "yes", "y": True, "z": "0600"}
        )

    def test_yaml_float(self):
        self.assertEqual(strict_yaml("x: 1.3"), {"x": 1.3})

    def test_yaml_error_redacted(self):
        with self.assertRaises(ContractError) as cm:
            validate("onboarding.schema.json", {"private": "SENTINEL"})
        self.assertNotIn("SENTINEL", str(cm.exception))


class Sources(unittest.TestCase):
    def setUp(self):
        self.app = load("examples/demo-app/app.yaml")
        self.cat = load("examples/demo-app/secrets.yaml")
        self.host = load("examples/host-node-a/host.yaml")
        self.hcat = load("examples/host-node-a/secrets.yaml")
        self.domain = load("examples/domain/domain.yaml")

    def test_all_fixtures(self):
        for f in load("contracts/index.json")["fixtures"]:
            with self.subTest(path=f["path"]):
                validate(f["schema"], load(f["path"]), f.get("definition"))

    def test_app_valid(self):
        validate_app(self.app, self.cat)

    def test_host_valid(self):
        validate_host(self.host, self.hcat)

    def test_domain_valid(self):
        validate_domain(self.domain)

    def test_duplicate_repo_alias(self):
        self.domain["sources"]["host-node-b"]["repository"] = copy.deepcopy(
            self.domain["sources"]["host-node-a"]["repository"]
        )
        with self.assertRaises(ContractError):
            validate_domain(self.domain)

    def test_shared_repository_has_independent_host_entrypoints(self):
        first = self.domain["sources"]["host-node-a"]
        second = self.domain["sources"]["host-node-b"]
        second["repository"] = copy.deepcopy(first["repository"])
        second["url"] = first["url"]
        first["entrypoint"] = "hosts/node-a/host.yaml"
        second["entrypoint"] = "hosts/node-b/host.yaml"
        validate_domain(self.domain)

    def test_branch_change_cannot_duplicate_host_identity(self):
        first = self.domain["sources"]["host-node-a"]
        second = self.domain["sources"]["host-node-b"]
        second["repository"] = copy.deepcopy(first["repository"])
        second["url"] = first["url"]
        second["ref"] = "refs/heads/proposal"
        with self.assertRaisesRegex(ContractError, "duplicate canonical host source"):
            validate_domain(self.domain)

    def test_host_operating_mode_is_an_expectation(self):
        host = self.domain["hosts"]["node-a"]
        for mode in ("always-on", "on-demand"):
            with self.subTest(mode=mode):
                host["operating_mode"] = mode
                validate_domain(self.domain)
        for observed in ("temporarily-offline", "sleeping", "unreachable"):
            with self.subTest(observed=observed), self.assertRaises(ContractError):
                host["operating_mode"] = observed
                validate_domain(self.domain)

    def test_old_availability_field_is_rejected(self):
        host = self.domain["hosts"]["node-a"]
        host["availability"] = host.pop("operating_mode")
        with self.assertRaises(ContractError):
            validate_domain(self.domain)

    def test_domain_source_name_and_reference_share_identifier_bound(self):
        name = "a" * 24
        self.domain["sources"][name] = self.domain["sources"].pop("host-node-a")
        self.domain["hosts"]["node-a"]["source"] = name
        validate_domain(self.domain)
        for unreachable_name in ("a" * 25, "trailing-"):
            invalid = copy.deepcopy(self.domain)
            invalid["sources"][unreachable_name] = copy.deepcopy(invalid["sources"][name])
            with self.subTest(name=unreachable_name), self.assertRaises(ContractError):
                validate_domain(invalid)
        referenced_maps = [
            (self.app, (field,))
            for field in ("components", "datasets", "hooks", "interfaces", "maintenance")
        ] + [
            (self.host, ("app_accounts",)),
            (self.host, ("grants",)),
            (self.host, ("concerns", "base", "services")),
        ]
        for source, path in referenced_maps:
            for label in ("a" * 24, "a" * 25, "trailing-"):
                candidate = copy.deepcopy(source)
                collection = candidate
                for part in path:
                    collection = collection[part]
                collection[label] = copy.deepcopy(next(iter(collection.values())))
                with self.subTest(kind=source["kind"], path=path, label=label):
                    if label == "a" * 24:
                        validate("source.schema.json", candidate)
                    else:
                        with self.assertRaises(ContractError):
                            validate("source.schema.json", candidate)

    def test_host_identity(self):
        with self.assertRaises(ContractError):
            validate_domain(self.domain, {"node-a": {"id": "wrong"}})

    def test_unknown_app_host(self):
        self.domain["apps"]["demo-app"]["host"] = "missing"
        with self.assertRaises(ContractError):
            validate_domain(self.domain)

    def test_unknown_secret_consumer(self):
        self.app["secret_bindings"]["database-password"]["component"] = "missing"
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_unknown_secret_entry(self):
        self.app["secret_bindings"]["database-password"]["entry"] = "missing"
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_missing_catalogue(self):
        with self.assertRaises(ContractError):
            validate_app(self.app, None)

    def test_unknown_hook(self):
        self.app["lifecycle"]["health"] = ["missing"]
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_private_export(self):
        self.app["interfaces"]["http"]["component"] = "database"
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_missing_capture(self):
        self.app["datasets"]["state"]["capture"] = "missing"
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_host_destination_collision(self):
        self.host["concerns"]["base"]["secret_files"]["agent-token"]["destination"] = "/etc/motd"
        with self.assertRaises(ContractError):
            validate_host(self.host, self.hcat)

    def test_secret_mode(self):
        self.host["concerns"]["base"]["secret_files"]["agent-token"]["mode"] = "0644"
        with self.assertRaises(ContractError):
            validate_host(self.host, self.hcat)

    def test_unknown_notify(self):
        self.host["concerns"]["base"]["secret_files"]["agent-token"]["notify"][0]["service"] = (
            "missing"
        )
        with self.assertRaises(ContractError):
            validate_host(self.host, self.hcat)

    def test_hook_borrows_secret(self):
        self.app["hooks"]["capture"]["secrets"] = ["database-password"]
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_unknown_source_field(self):
        self.app["auto_approve"] = True
        with self.assertRaises(ContractError):
            validate_app(self.app, self.cat)

    def test_hard_cycle(self):
        with self.assertRaises(ContractError):
            require_acyclic({"a": ["b"], "b": ["a"]})

    def test_missing_graph_node(self):
        with self.assertRaises(ContractError):
            require_acyclic({"a": ["z"]})

    def test_acyclic(self):
        require_acyclic({"a": ["b"], "b": []})


class Observations(unittest.TestCase):
    def setUp(self):
        self.observation = {
            "resource": {"kind": "host", "id": "node-a"},
            "owner": OWNER,
            "time": "2026-10-17T00:00:00Z",
            "origin": "owner-confirmed",
            "reachability": "reachable",
            "power_state": "awake",
            "activity": "active",
            "health_check": "supported",
            "health": "healthy",
            "protection": "unknown",
            "generation": 0,
            "source": None,
            "release_digest": None,
            "summary": "Synthetic host observation",
            "witness": None,
        }

    def check(self):
        validate("records.schema.json", self.observation, "Observation")

    def test_reachable_host_can_be_unhealthy(self):
        self.observation["health"] = "unhealthy"
        self.check()

    def test_unreachable_host_preserves_unknown_power_and_health(self):
        self.observation.update(
            origin="caller-reported",
            reachability="unreachable",
            power_state="unknown",
            activity="unknown",
            health_check="unknown",
            health="unknown",
        )
        self.check()

    def test_sleep_and_power_off_are_distinct_from_health(self):
        self.observation.update(reachability="unreachable", activity="inactive", health="unknown")
        for power in ("sleeping", "off"):
            with self.subTest(power=power):
                self.observation["power_state"] = power
                self.check()

    def test_connection_and_power_states_are_not_health_results(self):
        for state in ("unreachable", "sleeping", "unsupported"):
            with self.subTest(state=state), self.assertRaises(ContractError):
                self.observation["health"] = state
                self.check()

    def test_unavailable_health_check_cannot_claim_health(self):
        for support in ("unsupported", "unknown"):
            self.observation["health_check"] = support
            self.observation["health"] = "unknown"
            self.check()
            for result in ("healthy", "unhealthy"):
                with self.subTest(support=support, result=result), self.assertRaises(ContractError):
                    self.observation["health"] = result
                    self.check()

    def test_application_activity_is_not_machine_power(self):
        self.observation["resource"] = {"kind": "app", "id": "demo-app"}
        self.observation["power_state"] = "not-applicable"
        self.observation["activity"] = "inactive"
        self.check()
        for power in ("awake", "sleeping", "off", "unknown"):
            with self.subTest(power=power), self.assertRaises(ContractError):
                self.observation["power_state"] = power
                self.check()

    def test_host_power_cannot_be_not_applicable(self):
        self.observation["power_state"] = "not-applicable"
        with self.assertRaises(ContractError):
            self.check()

    def test_observation_dimensions_are_explicit(self):
        for field in ("reachability", "power_state", "health_check"):
            incomplete = copy.deepcopy(self.observation)
            del incomplete[field]
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate("records.schema.json", incomplete, "Observation")


class Transport(unittest.TestCase):
    def test_frame(self):
        self.assertEqual(read_frame(io.BytesIO(frame({"x": 1}))), {"x": 1})

    def test_small_reads(self):
        class Small(io.BytesIO):
            def read(self, n=-1):
                return super().read(min(n, 1))

        self.assertEqual(read_frame(Small(frame({"x": 1}))), {"x": 1})

    def test_truncated(self):
        with self.assertRaises(ContractError):
            read_frame(io.BytesIO(frame({"x": 1})[:-1]))

    def test_zero(self):
        with self.assertRaises(ContractError):
            read_frame(io.BytesIO(b"\0" * 4))

    def test_oversized(self):
        with self.assertRaises(ContractError):
            read_frame(io.BytesIO(struct.pack(">I", 1048577)))

    def test_nonobject(self):
        with self.assertRaises(ContractError):
            read_frame(io.BytesIO(struct.pack(">I", 2) + b"[]"))

    def test_argv_quoting(self):
        argv = ["app-ops", "source", "show", "a; touch /tmp/NO", "--json"]
        c = ssh_command("home", argv)
        self.assertEqual(shlex.split(c[-1]), argv)
        self.assertIn("-oForwardAgent=no", c)

    def test_alias_injection(self):
        with self.assertRaises(ContractError):
            ssh_command("-oProxyCommand=bad", ["app-ops", "status"])

    def test_bad_command(self):
        with self.assertRaises(ContractError):
            ssh_command("home", ["sh", "-c", "bad"])

    def test_config(self):
        self.assertIn(
            "/tmp/trusted-config", ssh_command("home", ["app-ops", "info"], "/tmp/trusted-config")
        )

    def test_config_relative(self):
        with self.assertRaises(ContractError):
            ssh_command("home", ["app-ops"], "config")

    def test_target_precedence(self):
        self.assertEqual(select_target("arg", "env", "profile"), "arg")

    def test_no_bad_fallback(self):
        with self.assertRaises(ContractError):
            select_target("", "good", "good")

    def test_environment_target(self):
        self.assertEqual(select_target(None, "env", "profile"), "env")

    def test_missing_target(self):
        with self.assertRaises(ContractError):
            select_target(None, None, None)


class Secrets(unittest.TestCase):
    def setUp(self):
        self.m = load("examples/bundle-manifest.json")
        self.v = {"db-password": b"synthetic-only"}
        self.tar = build_tar(self.m, self.v)

    def inspect(self, data):
        return inspect_tar(
            data, self.m["repository"], self.m["catalogue_digest"], self.m["entries"]
        )

    def test_roundtrip(self):
        self.assertEqual(self.inspect(self.tar), (self.m, self.v))

    def test_appended_garbage(self):
        with self.assertRaises(ContractError):
            self.inspect(self.tar + b"x" * 512)

    def test_appended_zeros(self):
        with self.assertRaises(ContractError):
            self.inspect(self.tar + b"\0" * 10240)

    def test_truncated(self):
        with self.assertRaises(ContractError):
            self.inspect(self.tar[:-1])

    def test_wrong_repository(self):
        with self.assertRaises(ContractError):
            inspect_tar(
                self.tar,
                {**self.m["repository"], "repository_id": 999},
                self.m["catalogue_digest"],
                self.m["entries"],
            )

    def test_catalogue_mismatch(self):
        with self.assertRaises(ContractError):
            inspect_tar(self.tar, self.m["repository"], digest({}), self.m["entries"])

    def test_entry_set(self):
        with self.assertRaises(ContractError):
            inspect_tar(self.tar, self.m["repository"], self.m["catalogue_digest"], ["other"])

    def test_value_set(self):
        with self.assertRaises(ContractError):
            build_tar(self.m, {"other": b"abc"})

    def test_manifest_path_alias(self):
        self.m["paths"] = {"db-password": "secrets/alias"}
        with self.assertRaises(ContractError):
            build_tar(self.m, self.v)

    def test_path_traversal(self):
        self.m["entries"] = ["../key"]
        with self.assertRaises(ContractError):
            build_tar(self.m, {"../key": b"abc"})

    def test_large_entry(self):
        with self.assertRaises(ContractError):
            build_tar(self.m, {"db-password": b"x" * (MAX_ENTRY + 1)})

    def test_nonregular(self):
        import tarfile

        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as t:
            i = tarfile.TarInfo("bundle.json")
            i.type = tarfile.SYMTYPE
            i.linkname = "/etc/passwd"
            t.addfile(i)
        with self.assertRaises(ContractError):
            self.inspect(b.getvalue())

    def test_asset_bool(self):
        with self.assertRaises(ContractError):
            select_asset([{"name": "secrets.tar.age", "id": True, "size": 10}])

    def test_asset_duplicates(self):
        with self.assertRaises(ContractError):
            select_asset([{"name": "secrets.tar.age", "id": 1, "size": 10}] * 2)

    def test_asset_missing(self):
        with self.assertRaises(ContractError):
            select_asset([])

    def test_asset_valid(self):
        self.assertEqual(select_asset([{"name": "secrets.tar.age", "id": 1, "size": 10}])["id"], 1)


class Evidence(unittest.TestCase):
    def test_plan(self):
        validate_plan(plan())

    def test_plan_digest(self):
        p = plan()
        p["interruption"] = "changed"
        with self.assertRaises(ContractError):
            validate_plan(p)

    def test_signature(self):
        k = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
        w = sign(wb(digest({})), k)
        verify(w, k.public_key(), OWNER, digest({}))

    def test_tamper(self):
        k = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
        w = sign(wb(digest({})), k)
        w["generation"] = 2
        with self.assertRaises(ContractError):
            verify(w, k.public_key(), OWNER, digest({}))

    def test_wrong_key(self):
        k = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
        w = sign(wb(digest({})), k)
        with self.assertRaises(ContractError):
            verify(
                w,
                Ed25519PrivateKey.from_private_bytes(b"\x12" * 32).public_key(),
                OWNER,
                digest({}),
            )

    def test_wrong_epoch(self):
        k = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
        w = sign(wb(digest({})), k)
        with self.assertRaises(ContractError):
            verify(w, k.public_key(), {**OWNER, "epoch": uid("new")}, digest({}))

    def test_wrong_subject(self):
        k = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
        w = sign(wb(digest({})), k)
        with self.assertRaises(ContractError):
            verify(w, k.public_key(), OWNER, digest([]))

    def test_cli_accepted_not_complete(self):
        x = {
            "format": "deployment-ops/cli/v1",
            "ok": True,
            "state": "accepted",
            "complete": True,
            "request_id": uid("req"),
            "location": "home",
            "result": None,
            "problem": None,
        }
        with self.assertRaises(ContractError):
            validate_cli(x)


class Durable(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "owner.sqlite"
        self.j = Journal(self.path, OWNER["id"], OWNER["epoch"], True)

    def tearDown(self):
        self.j.close()
        self.tmp.cleanup()

    def submit(self, request="r", **overrides):
        kw = {
            "principal": "operator",
            "authorized": True,
            "expected_epoch": OWNER["epoch"],
            "expected_generation": 0,
            "expires": 20,
            "now": 10,
        }
        kw.update(overrides)
        return self.j.submit(request, SUBJECT, **kw)

    def test_accept(self):
        self.assertEqual(self.submit()["state"], "accepted")

    def test_replay_new_actor(self):
        self.submit()
        self.assertEqual(self.submit(principal="owner")["principal"], "operator")

    def test_replay_expired_after_success(self):
        self.submit()
        self.j.transition("r", "running", "none")
        self.j.transition("r", "succeeded", "known")
        self.assertEqual(self.submit(now=50)["state"], "succeeded")

    def test_denied_replay(self):
        self.submit()
        with self.assertRaises(ContractError):
            self.submit(authorized=False)

    def test_payload_conflict(self):
        self.submit()
        with self.assertRaises(ContractError):
            self.submit(expires=30)

    def test_expired_new(self):
        with self.assertRaises(ContractError):
            self.submit(now=21)

    def test_wrong_epoch(self):
        with self.assertRaises(ContractError):
            self.submit(expected_epoch=uid("new"))

    def test_generation(self):
        with self.assertRaises(ContractError):
            self.submit(expected_generation=1)

    def test_busy(self):
        self.submit()
        with self.assertRaises(ContractError):
            self.submit("another")

    def test_quarantine_hold(self):
        self.submit()
        self.j.transition("r", "running", "none")
        self.j.transition("r", "quarantined", "unknown")
        with self.assertRaises(ContractError):
            self.submit("another")

    def test_success_needs_evidence(self):
        self.submit()
        self.j.transition("r", "running", "unknown")
        with self.assertRaises(ContractError):
            self.j.transition("r", "succeeded", "unknown")

    def test_illegal_transition(self):
        self.submit()
        with self.assertRaises(ContractError):
            self.j.transition("r", "succeeded", "known")

    def test_restart(self):
        self.submit()
        self.j.close()
        self.j = Journal(self.path, OWNER["id"], OWNER["epoch"])
        self.assertEqual(self.submit(now=99)["state"], "accepted")

    def test_missing_not_initialized(self):
        with self.assertRaises(ContractError):
            Journal(Path(self.tmp.name) / "missing", OWNER["id"], OWNER["epoch"])

    def test_wrong_store_epoch(self):
        with self.assertRaises(ContractError):
            Journal(self.path, OWNER["id"], uid("new"))

    def test_failed_effect_hold(self):
        self.submit()
        self.j.transition("r", "running", "unknown")
        self.j.transition("r", "failed", "unknown")
        with self.assertRaises(ContractError):
            self.submit("another")

    def test_cancelled_effect_hold(self):
        self.submit()
        self.j.transition("r", "running", "known")
        self.j.transition("r", "cancelled", "known")
        with self.assertRaises(ContractError):
            self.submit("another")

    def test_wal_settings(self):
        self.assertEqual(self.j.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.j.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")


if __name__ == "__main__":
    unittest.main()

CHECK_CLASS_PURPOSE = {
    "Durable": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "offline reference helper",
        "relationship": "candidate",
        "reason": "Local journal reference transitions and SQLite restart only; no native owner or effect reconciliation.",
        "claims": [],
    },
    "Transport": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-methods.json"
        ],
        "scope": "offline reference helper",
        "relationship": "candidate",
        "reason": "Local wire framing and SSH argv preparation only; no authenticated remote dispatch.",
        "claims": [],
    },
    "Secrets": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/bundle-manifest.schema.json"
        ],
        "scope": "offline reference helper",
        "relationship": "candidate",
        "reason": "Synthetic in-memory tar and asset selection only; no encrypted publication custodian.",
        "claims": [],
    },
    "Evidence": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json"
        ],
        "scope": "offline reference helper",
        "relationship": "candidate",
        "reason": "Synthetic digest/signature consistency and rejection only; no native plan or accepted effect.",
        "claims": [],
    },
    "Sources": {
        "purpose": "public-contract",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json"
        ],
        "scope": "offline source-schema and cross-reference candidates",
        "relationship": "candidate",
        "reason": "Source schema structure is exercised through local validators; cross-reference helper expectations need independently reviewed rule-level bindings before sufficient public-contract proof.",
        "claims": [],
    },
    "Observations": {
        "purpose": "public-contract",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Observation"
        ],
        "scope": "offline observation dimensions and schema rejection cases",
        "relationship": "candidate",
        "reason": "Schema cases distinguish reachability, power, activity, check support, and health. They do not establish native observation accuracy or authenticate reported evidence.",
        "claims": [],
    },
}
