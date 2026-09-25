"""Mint short-lived local JWTs for AgentTrust development and demos."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

from ..core.policy import PolicyError
from ..gateway.local_jwt import mint_local_jwt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mint a development-only AgentTrust JWT")
    parser.add_argument("--secret-file", required=True, help="HS256 secret file shared with the relay")
    parser.add_argument("--issuer", default="agenttrust-local", help="Token issuer")
    parser.add_argument("--audience", required=True, help="Canonical MCP endpoint URL")
    parser.add_argument("--name", required=True, help="Principal name")
    parser.add_argument("--group", action="append", default=[], help="Principal group; repeat as needed")
    parser.add_argument("--lifetime-seconds", type=int, default=300, help="Token lifetime (default: 300)")
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.lifetime_seconds < 1:
            raise PolicyError("--lifetime-seconds must be positive")
        secret = Path(args.secret_file).read_bytes().strip()
        now = int(time.time())
        token = mint_local_jwt(
            secret,
            {
                "iss": args.issuer,
                "aud": args.audience,
                "iat": now,
                "exp": now + args.lifetime_seconds,
                "name": args.name,
                "groups": args.group,
            },
        )
    except (OSError, PolicyError) as exc:
        print(f"JWT generation failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(token)


if __name__ == "__main__":
    main()
