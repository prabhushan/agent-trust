"""Explicit placeholders for AgentTrust gateway phases 4-6.

Production controls are intentionally not wired into the relay yet. The relay
supports static identities and a development-only local HS256 JWT verifier;
phase 4 replaces those HTTP credentials with OIDC/JWKS validation.
"""


class GatewayControlsNotImplemented(NotImplementedError):
    """Raised by future gateway adapters until their implementations exist."""


def authenticate_oidc_or_jwt(*_args: object, **_kwargs: object) -> None:
    """Phase 4 placeholder: validate production OIDC/JWKS credentials."""
    raise GatewayControlsNotImplemented("Production OIDC/JWKS authentication is not implemented")


def rate_limit_and_reload_policy(*_args: object, **_kwargs: object) -> None:
    """Phase 5 placeholder: enforce rate limits and atomically reload policies."""
    raise GatewayControlsNotImplemented("Rate limiting and policy hot reload are not implemented")


def configure_tls_termination(*_args: object, **_kwargs: object) -> None:
    """Phase 6 placeholder: configure in-process TLS or a trusted load balancer."""
    raise GatewayControlsNotImplemented("TLS termination is not implemented")
