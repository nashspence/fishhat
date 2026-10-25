"""Synthetic independently approved source-target mappings; no native resolution."""

from __future__ import annotations

import copy
import json

from fishhat_adapters import Registry, instance_reference
from fishhat_contracts.validation import digest

from tests.adapter_support import OWNER, descriptors


def host_target(
    host,
    provider,
    source,
    *,
    registry=None,
    instance_id=None,
    namespace=None,
    scope=None,
    controller=None,
):
    descriptor = json.loads(next(p for p in descriptors() if provider in p.parts).read_text())
    role = descriptor["roles"][0]
    instance_id = instance_id or "selected-" + provider
    scope = scope or {"authority": OWNER["id"], "kind": role, "handle": instance_id}
    namespace = namespace or {
        "authority": OWNER["id"],
        "resource": instance_id + ":target",
        "facet": "lifecycle" if role == "service" else "software",
    }
    instance = {
        "id": instance_id,
        "implementation": descriptor["id"],
        "installation_digest": digest(descriptor),
        "role": role,
        "schema_digest": digest(descriptor["configuration_schema"]),
        "configuration": {
            key: "synthetic-target" for key in descriptor["configuration_schema"]["properties"]
        },
        "grants": [
            {
                "scope": scope,
                "access": ["observe", "change"],
                "mutation": {"controller": controller or instance_id, "namespaces": [namespace]},
            }
        ],
        "generation": 1,
    }
    registry = registry or Registry()
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": {
                "digest": instance["installation_digest"],
                "media_type": "application/zip",
                "size_bytes": 100,
            },
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    registry.enroll(instance, owner_approved=True)
    host["adapter_instances"][instance_id] = copy.deepcopy(instance)
    selection = {
        "instance": instance_id,
        "source_schema_digest": digest(descriptor["source_schema"]),
        "source": copy.deepcopy(source),
    }
    declaration = {
        "adapter": selection,
        "scope": copy.deepcopy(scope),
        "reason": "Synthetic target",
    }
    declaration.update(
        {"enabled": True, "activity": "running"}
        if role == "service"
        else {"version": "1", "held": False, "state": "present"}
    )
    target = {
        "selection": selection,
        "executor": instance_reference(instance, scope),
        "namespace": namespace,
    }
    registry.enroll_source_target(target, owner_approved=True)
    return registry, declaration, target
