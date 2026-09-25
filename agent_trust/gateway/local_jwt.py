"""Minimal, development-only HS256 JWT verification for the HTTP relay."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Mapping

from mcp.server.auth.provider import AccessToken

from ..core.policy import PolicyError


def _decode_segment(value: str, label: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"JWT {label} is not valid base64url") from exc


def _encode_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class LocalJwtVerifier:
    """Validate locally issued HS256 tokens and expose MCP access-token data.

    This intentionally small verifier is for development and controlled local
    deployments. Production deployments should use OIDC discovery and JWKS.
    """

    def __init__(self, secret: bytes, *, issuer: str, audience: str) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise PolicyError("Local JWT secret must contain at least 32 bytes")
        if not issuer or not audience:
            raise PolicyError("Local JWT issuer and audience must be non-empty")
        self._secret = secret
        self.issuer = issuer
        self.audience = audience

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = self.verify_claims(token)
        except PolicyError:
            return None
        scopes = claims.get("scope", [])
        if isinstance(scopes, str):
            scopes = scopes.split()
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            return None
        principal_id = claims.get("sub") or claims["name"]
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", principal_id)),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=self.audience,
            subject=str(principal_id),
            claims=dict(claims),
        )

    def verify_claims(self, token: str) -> Mapping[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise PolicyError("JWT must contain three segments")
        header_segment, payload_segment, signature_segment = parts
        try:
            header = json.loads(_decode_segment(header_segment, "header"))
            claims = json.loads(_decode_segment(payload_segment, "payload"))
        except json.JSONDecodeError as exc:
            raise PolicyError("JWT header and payload must be JSON objects") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise PolicyError("JWT header and payload must be JSON objects")
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise PolicyError("JWT must use HS256 with type JWT")
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        supplied = _decode_segment(signature_segment, "signature")
        if not hmac.compare_digest(expected, supplied):
            raise PolicyError("JWT signature is invalid")
        if claims.get("iss") != self.issuer:
            raise PolicyError("JWT issuer is invalid")
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self.audience not in audiences:
            raise PolicyError("JWT audience is invalid")
        now = int(time.time())
        if type(claims.get("exp")) not in {int, float} or int(claims["exp"]) <= now:
            raise PolicyError("JWT is expired or has no valid expiry")
        if "nbf" in claims and (type(claims["nbf"]) not in {int, float} or int(claims["nbf"]) > now):
            raise PolicyError("JWT is not yet valid")
        name = claims.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PolicyError("JWT name claim must be non-empty")
        groups = claims.get("groups")
        if not isinstance(groups, list) or not all(isinstance(group, str) and group.strip() for group in groups):
            raise PolicyError("JWT groups claim must be a list of non-empty strings")
        return claims


def mint_local_jwt(secret: bytes, claims: Mapping[str, Any]) -> str:
    """Mint an HS256 token for tests and controlled local development."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise PolicyError("Local JWT secret must contain at least 32 bytes")
    header = _encode_segment(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _encode_segment(json.dumps(dict(claims), separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _encode_segment(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"
