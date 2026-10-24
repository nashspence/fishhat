"""Synthetic owner identities and installed-descriptor test inputs, never native evidence."""

import copy
import json
from pathlib import Path

from fishhat_adapters import Registry, runtime_binding_digest
from fishhat_contracts.validation import digest, strict_yaml

from tests.support import ROOT

D = "sha256:" + "a" * 64
OWNER = {
    "tool": "app-ops",
    "id": "00000000-0000-4000-8000-000000000001",
    "epoch": "00000000-0000-4000-8000-000000000002",
}
SCOPE = {"authority": OWNER["id"], "kind": "application", "handle": "demo"}
INCARNATION = "00000000-0000-4000-8000-000000000003"
SERVICE = "app-demo-web.service"
NAMESPACE = {"authority": OWNER["id"], "resource": SERVICE, "facet": "lifecycle"}


def identifier(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def descriptors() -> list[Path]:
    return sorted((ROOT / "some-implementations/fishhat").glob("*/*/src/*/descriptor.json"))


def runtime_registry() -> tuple[Registry, dict, dict]:
    # This is an authority-model test double, not the second supplied/native adapter.
    path = next(p for p in descriptors() if "podman-quadlet" in p.parts)
    descriptor = json.loads(path.read_text())
    descriptor["id"] = "independent-author.example-runtime"
    descriptor["implemented"] = [
        "runtime.activate",
        "runtime.deactivate",
        "runtime.observe",
        "runtime.inventory",
    ]
    installation = {
        "implementation": descriptor["id"],
        "artifact": {"digest": D, "media_type": "application/zip", "size_bytes": 100},
        "descriptor_digest": digest(descriptor),
        "enabled": True,
    }
    instance = {
        "id": "native-demo",
        "implementation": descriptor["id"],
        "installation_digest": D,
        "role": "runtime",
        "schema_digest": digest(descriptor["configuration_schema"]),
        "configuration": {"account": "app-demo"},
        "grants": [
            {
                "scope": SCOPE,
                "access": ["observe", "change"],
                "mutation": {"controller": "native-demo", "namespaces": [NAMESPACE]},
            }
        ],
        "generation": 1,
    }
    registry = Registry()
    registry.install(installation, descriptor, owner_approved=True)
    registry.enroll(instance, owner_approved=True)
    return registry, copy.deepcopy(descriptor), copy.deepcopy(instance)


def runtime_sources(registry: Registry) -> dict:
    """Synthetic owner-selected sources that agree with the enrolled runtime instance."""
    host = strict_yaml((ROOT / "tests/fixtures/host-node-a/host.yaml").read_text())
    host["app_accounts"] = {
        "demo": {
            "device_groups": [],
            "reason": "Synthetic app assignment",
            "resource_account": "app-demo",
            "runtime_instance": "native-demo",
        }
    }
    host["adapter_instances"] = {"native-demo": registry.inspect_instance("native-demo")}
    host["grants"] = {}
    app = strict_yaml((ROOT / "tests/fixtures/stateless/app.yaml").read_text())
    app["id"] = "demo"
    app["runtime"]["instance"] = "native-demo"
    return {"host": host, "app": app}


def service_instance(registry: Registry, *, controller: str = "native-demo") -> dict:
    """Install a service authority-model double and return its unenrolled instance."""
    path = next(p for p in descriptors() if "services" in p.parts and "systemd" in p.parts)
    descriptor = json.loads(path.read_text())
    descriptor["id"] = "independent-author.example-service"
    descriptor["implemented"] = ["service.set-activity"]
    installation_digest = "sha256:" + "b" * 64
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": {
                "digest": installation_digest,
                "media_type": "application/zip",
                "size_bytes": 100,
            },
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    return {
        "id": "service-demo",
        "implementation": descriptor["id"],
        "installation_digest": installation_digest,
        "role": "service",
        "schema_digest": digest(descriptor["configuration_schema"]),
        "configuration": {"manager_handle": "app-demo", "unit_scope": "app-demo"},
        "grants": [
            {
                "scope": copy.deepcopy(SCOPE),
                "access": ["observe", "change"],
                "mutation": {
                    "controller": controller,
                    "namespaces": [copy.deepcopy(NAMESPACE)],
                },
            }
        ],
        "generation": 1,
    }


def service_request(activity: str = "running") -> dict:
    return {
        "contract": "fishhat.service",
        "method": "set-activity",
        "input": {"scope": copy.deepcopy(SCOPE), "service": SERVICE, "activity": activity},
    }


def binding() -> dict:
    _, _, instance = runtime_registry()
    return {
        "subject": "demo",
        "instance": "native-demo",
        "generation": 1,
        "installation_digest": D,
        "configuration_digest": digest({"account": "app-demo"}),
        "scope": copy.deepcopy(SCOPE),
        "native_incarnation": INCARNATION,
        "admission_generation": 0,
        "instance_generation": 1,
        "instance_digest": digest(instance),
    }


def request(method: str = "activate") -> dict:
    return {
        "contract": "fishhat.runtime",
        "method": method,
        "input": {
            "scope": copy.deepcopy(SCOPE),
            "deployment": {
                "handle": "deployment:demo",
                "release_digest": D,
                "binding_digest": runtime_binding_digest(binding()),
                "projection_digest": D,
                "components": ["web"],
            },
        },
    }


def native_exclusion(scope: dict) -> str:
    """Synthetic continuously held native exclusion; never a native safety proof."""
    return identifier(90)


def observation(admission_generation: int = 0, *, barrier: dict | None = None) -> dict:
    return {
        "scope": copy.deepcopy(SCOPE),
        "generation": 1,
        "observed_at": "2026-01-01T00:00:00Z",
        "native_incarnation": INCARNATION,
        "coverage": "complete",
        "activity": "inactive",
        "health": "unknown",
        "health_check": "supported",
        "quiescence": "verified",
        "continuation": None,
        "instance": "native-demo",
        "installation_digest": D,
        "admission_generation": admission_generation,
        "barrier": copy.deepcopy(barrier),
    }


def fresh_observation(owner, subject: str = "demo", *, method: str = "observe") -> dict:
    query = owner.observation_request(subject, owner_approved=True, method=method)
    barrier = query["input"]["barrier"]
    return observation(barrier["admission_generation"], barrier=barrier)
