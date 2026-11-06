"""Portable application access projection from independently selected source inputs."""

from hashlib import sha256
from typing import Any

from .json_work import lexical
from .release_identity import validate_release, validate_source_closure
from .validation import ContractError, digest, strict_yaml, validate, validate_app, validate_domain


def _projection(
    value: dict[str, Any], fields: tuple[str, ...], sets: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {
        **{name: value[name] for name in fields},
        **{name: lexical(value[name]) for name in sets},
    }


def application_boundary(
    domain: dict[str, Any],
    host: dict[str, Any],
    app: dict[str, Any],
    catalogue: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the public preimage. Source or a computed digest cannot approve its own use."""
    validate_domain(domain)
    validate("source.schema.json", host, "Host")
    validate_app(app, catalogue)
    name = app["id"]
    placement = domain["apps"].get(name)
    account = host["app_accounts"].get(name)
    if not placement or placement["host"] != host["id"] or not account:
        raise ContractError("application boundary placement or account mismatch")
    if account["runtime_instance"] != app["runtime"]["instance"]:
        raise ContractError("application boundary runtime assignment mismatch")
    source = domain["sources"][placement["source"]]
    repository = _projection(source["repository"], ("instance", "repository_id"))
    secret_catalogue = None
    if app["secret_bindings"]:
        assert catalogue is not None  # validated with every bound entry above
        if _projection(catalogue["repository"], ("instance", "repository_id")) != repository:
            raise ContractError("application boundary secret repository mismatch")
        secret_catalogue = {
            "path": app["repository_secrets"],
            "source": catalogue["source"],
            "entries": {
                binding["entry"]: catalogue["entries"][binding["entry"]]
                for binding in app["secret_bindings"].values()
            },
        }
    return {
        "format": "fishhat.application-boundary/v1",
        "domain_id": domain["id"],
        "host_id": host["id"],
        "app_id": name,
        "repository": repository,
        "entrypoint": source["entrypoint"],
        "security_control": placement["security_control"],
        "platform_profile": host["platform_profile"],
        "account": _projection(
            account, ("resource_account", "runtime_instance"), ("device_groups",)
        ),
        "grants": {
            key: _projection(grant, ("type", "profile"), ("resources",))
            for key, grant in host["grants"].items()
            if grant["app"] == name
        },
        "components": {
            key: _projection(component, ("role", "profile"))
            for key, component in app["components"].items()
        },
        "interfaces": {
            key: _projection(
                item,
                ("component", "protocol", "port", "authentication", "readiness_hook"),
                ("compatibility",),
            )
            for key, item in app["interfaces"].items()
        },
        "dependencies": {
            key: _projection(
                item,
                ("provider_kind", "provider", "interface"),
                ("consumers", "compatibility", "phases"),
            )
            for key, item in app["dependencies"].items()
        },
        "datasets": {
            key: _projection(
                item,
                (
                    "custody",
                    "recovery",
                    "native_format",
                    "grant",
                    "owner",
                    "capture",
                    "restore",
                    "verify_restore",
                    "rebuild",
                    "verify_rebuild",
                ),
                ("readers", "writers"),
            )
            for key, item in app["datasets"].items()
        },
        "hooks": {
            key: _projection(
                item, ("component", "role", "mode", "network"), ("datasets", "secrets")
            )
            for key, item in app["hooks"].items()
        },
        "secret_bindings": app["secret_bindings"],
        "secret_catalogue": secret_catalogue,
    }


def validate_release_boundary(
    release: dict[str, Any],
    *,
    expected_release_digest: str,
    expected_app_instance: str,
    domain: dict[str, Any],
    host: dict[str, Any],
    app_source: dict[str, Any],
    pinned_files: dict[str, dict[str, str]],
    app_blob: bytes,
    catalogue_blob: bytes | None,
) -> None:
    """Join independent admitted domain/host policy and exact pinned Git material.

    The receiver resolves app_source and the complete regular-file manifest from
    the approved repository/ref under its own authority. A Release cannot choose
    its own commit or closure. The raw documents supplied here must be the Git
    blobs selected by that closure. Native approval and custody remain external.
    """
    validate_release(release, expected_digest=expected_release_digest)
    validate_source_closure(app_source, pinned_files)
    if release["app_instance"] != expected_app_instance:
        raise ContractError("release differs from approved application instance")

    def document(path: str, blob: bytes) -> dict[str, Any]:
        if pinned_files.get(path, {}).get("digest") != "sha256:" + sha256(blob).hexdigest():
            raise ContractError("application boundary document differs from pinned source")
        try:
            result = strict_yaml(blob.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ContractError("invalid application source encoding") from error
        if not isinstance(result, dict):
            raise ContractError("invalid application source document")
        return result

    app = document(app_source["entrypoint"], app_blob)
    validate("source.schema.json", app, "App")
    path = app["repository_secrets"]
    if (catalogue_blob is None) != (path is None):
        raise ContractError("application secret catalogue differs from pinned source")
    catalogue = document(path, catalogue_blob) if catalogue_blob is not None else None
    projection = application_boundary(domain, host, app, catalogue)
    if any(name not in app["components"] for name in release["runtime"]["components"]):
        raise ContractError("release selects a component outside the pinned application")
    placement = domain["apps"][app["id"]]
    identity = ("instance", "repository_id")
    if (
        app_source["source_id"] != placement["source"]
        or app_source["entrypoint"] != projection["entrypoint"]
        or _projection(app_source["repository"], identity) != projection["repository"]
        or [
            source
            for source in release["sources"]
            if source["source_id"] == app_source["source_id"]
            or (
                source["entrypoint"] == app_source["entrypoint"]
                and _projection(source["repository"], identity) == projection["repository"]
            )
        ]
        != [app_source]
    ):
        raise ContractError("release does not select the exact approved application source")
    boundary = digest(projection)
    if not boundary == placement["boundary_digest"] == release["boundary_digest"]:
        raise ContractError("application boundary differs from approved domain or release")
