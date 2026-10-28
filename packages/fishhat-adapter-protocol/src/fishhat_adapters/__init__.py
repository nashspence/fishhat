"""Public adapter data boundaries. No implementation discovery or native effects."""

from fishhat_contracts.adapter_observations import ObservationSequence
from fishhat_contracts.adapter_semantics import (
    ROLES,
    check_invocation,
    check_request,
    check_response,
    check_result,
)

from .protocol import (
    Registry,
    check_configuration,
    check_descriptor,
    check_schema,
    instance_reference,
    require_qualification,
    runtime_binding_digest,
)

__all__ = [
    "ROLES",
    "ObservationSequence",
    "Registry",
    "check_configuration",
    "check_descriptor",
    "check_invocation",
    "check_request",
    "check_response",
    "check_result",
    "check_schema",
    "instance_reference",
    "require_qualification",
    "runtime_binding_digest",
]
