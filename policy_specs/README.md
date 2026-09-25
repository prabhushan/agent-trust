# Policy specifications

This directory contains human-reviewed, unsigned inputs to
`agent-trust-generate`. These files are controlled by the policy administrator,
not by the MCP servers they authorize.

`support_demo.json` approves the narrow subject, tool, and argument scope used
by the local synthetic support-server demonstration. Policies are default-deny;
explicit `deny` rules override matching `allow` rules.

The local Streamlit administrator creates `admin_policy.json` after its first
successful MCP addition. That file is the UI's complete unsigned source for
policy metadata, stdio launch descriptors, and tool rules. The UI refuses to
write when this manifest differs from the currently signed policy.

For the local demo, launch commands and working directories are stored relative
to the `agent-trust` root. Start both the admin UI and relay from that directory.
