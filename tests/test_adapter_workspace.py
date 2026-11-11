from __future__ import annotations

import ast
import json
import tomllib

from scripts.project_policy import ROOT, boundary_errors, components, workspace_projects
from tests.adapter_support import descriptors

CHECK_PURPOSE = {
    "purpose": "repository-policy",
    "authority": ["tests/test_adapter_workspace.py"],
    "scope": "workspace identity, supplied implementation separation and account-free qualification convention",
    "relationship": "no-product-claim",
    "reason": "Executable repository policy, not runtime qualification.",
    "claims": [],
}

# Explicit maintained contrasts. This does not assert that two unqualified scaffolds are native support.
CONTRASTS = {
    "bootstrap-source": {"forgejo-restic", "git-bundle"},
    "runtime": {"podman-quadlet", "docker-compose", "systemd-native"},
    "compute": {"systemd-cgroup", "delegated-cgroup"},
    "scheduler": {"slurm", "nomad"},
    "storage": {"xfs-project", "ext4-filesystem"},
    "capture": {"quiesced-files", "postgresql-capture"},
    "backup": {"restic", "sealed-archive"},
    "secret-source": {"forgejo-age", "openbao-kv"},
    "credential-issuer": {"postgresql-credential-issuer", "openbao-database"},
    "dns": {"dnsmasq-appliance", "bind-rfc2136"},
    "ingress": {"nginx", "caddy"},
    "network": {"nftables", "firewalld"},
    "software": {"apt", "homebrew", "archive-slots"},
    "service": {"systemd", "procd", "launchd"},
    "repository": {"forgejo", "git-ssh"},
    "build": {"buildah", "buildkit"},
    "report": {"forgejo-issues", "jsonl"},
}


def test_each_scaffold_has_a_distinct_identity_and_selected_native_contrast():
    grouped = {}
    identities = []
    for path in descriptors():
        d = json.loads(path.read_text())
        identities.append(d["id"])
        for role in d["roles"]:
            grouped.setdefault(role, set()).add(d["id"].removeprefix("fishhat."))
    assert len(set(identities)) == len(identities)
    assert grouped == CONTRASTS
    assert all(len(implementations) >= 2 for implementations in grouped.values())


def test_no_account_dependent_cloud_adapter_is_supplied():
    assert all("cloudflare" not in p.as_posix().lower() for p in descriptors())
    assert any("dnsmasq-appliance" in p.parts for p in descriptors())


def test_workspace_inventory_matches_actual_project_metadata():
    assert not boundary_errors()
    declared = {c["path"]: c for c in components()}
    assert set(declared) == {str(p.parent.relative_to(ROOT)) for p in workspace_projects()}
    for p in workspace_projects():
        config = tomllib.loads(p.read_text())
        current = declared[str(p.parent.relative_to(ROOT))]
        assert config["tool"]["fishhat"]["component"] == {
            k: current[k] for k in ("id", "module", "role")
        }


def test_public_packages_never_import_product_or_concrete_adapter_implementations():
    forbidden = {
        c["module"]
        for c in components()
        if c["role"]
        in {
            "adapter-implementation",
            "app-owner-scaffold",
            "host-owner-scaffold",
            "owner-state",
            "optional-discovery",
            "optional-reporting",
        }
    }
    for path in (ROOT / "packages").rglob("*.py"):
        if "build" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            modules = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else (
                    [node.module or ""]
                    if isinstance(node, ast.ImportFrom) and not node.level
                    else []
                )
            )
            assert not {m.split(".")[0] for m in modules} & forbidden, path


def test_concrete_packages_do_not_depend_on_unrelated_implementations():
    for component in components():
        if component["role"] == "adapter-implementation":
            assert component["distribution"].startswith("a-fishhat-")
            assert component["module"].startswith("a_fishhat_")
            assert not any(
                name.startswith("a-fishhat-") for name in component["internal_dependencies"]
            )


def test_native_configuration_does_not_belong_in_the_owner_runtime_switch():
    for directory in (ROOT / "fishhat/app-ops", ROOT / "fishhat/owner-support"):
        for path in directory.rglob("*.py"):
            assert "a_fishhat_" not in path.read_text()
