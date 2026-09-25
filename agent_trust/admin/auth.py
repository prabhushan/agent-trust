"""Local-only credentials for the Streamlit administration UI."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import os
from typing import Mapping


DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "password"


@dataclass(frozen=True)
class AdminCredentials:
    """Credentials loaded from the environment with explicit demo defaults."""

    username: str
    password: str
    uses_demo_defaults: bool

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "AdminCredentials":
        values = os.environ if environment is None else environment
        username = values.get("AGENTTRUST_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
        password = values.get("AGENTTRUST_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
        return cls(
            username=username,
            password=password,
            uses_demo_defaults=(
                username == DEFAULT_ADMIN_USERNAME and password == DEFAULT_ADMIN_PASSWORD
            ),
        )

    def authenticate(self, username: str, password: str) -> bool:
        """Compare both credential fields without data-dependent early returns."""
        username_matches = hmac.compare_digest(str(username), self.username)
        password_matches = hmac.compare_digest(str(password), self.password)
        return username_matches & password_matches
