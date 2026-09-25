# Policy specifications

This directory contains human-reviewed, unsigned inputs to
`agent-trust-generate`. These files are controlled by the policy administrator,
not by the MCP servers they authorize.

`support_demo.json` approves the narrow subject, tool, and argument scope used
by the local synthetic support-server demonstration. Policies are default-deny;
explicit `deny` rules override matching `allow` rules.
