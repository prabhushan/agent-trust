"""Launch the local AgentTrust Streamlit administrator on loopback."""

from __future__ import annotations

from pathlib import Path
import sys

from streamlit.web import cli as streamlit_cli


def main() -> None:
    app = Path(__file__).resolve().parents[1] / "admin" / "app.py"
    sys.argv = [
        "streamlit",
        "run",
        str(app),
        "--server.address=127.0.0.1",
    ]
    raise SystemExit(streamlit_cli.main())


if __name__ == "__main__":
    main()
