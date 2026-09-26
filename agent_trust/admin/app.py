"""Streamlit UI for trusted, local AgentTrust policy administration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

import streamlit as st

from agent_trust.admin.auth import AdminCredentials
from agent_trust.admin.service import (
    AdminPaths,
    append_mcp_server,
    delete_mcp_server,
    load_audit_events,
    load_policy_snapshot,
    update_mcp_server,
)
from agent_trust.core.policy import PolicyError, SubjectSelector, ToolRule, thaw_json


def _relative_path(value: str, base: str | Path) -> str:
    """Render a policy path without exposing the local home-directory name."""
    try:
        path = Path(value)
        if not path.is_absolute():
            return os.path.normpath(value)
        relative = os.path.relpath(path, Path(base).absolute())
        if relative == ".." or relative.startswith(f"..{os.sep}"):
            return Path(value).name
        return relative
    except (OSError, ValueError):
        return Path(value).name


def _safe_error(value: object) -> str:
    """Redact repository and home prefixes from errors shown in the browser."""
    message = str(value)
    replacements = sorted(
        {str(Path.cwd().resolve()): ".", str(Path.home().resolve()): "~"},
        key=len,
        reverse=True,
    )
    for prefix in replacements:
        message = message.replace(prefix, "." if prefix == str(Path.cwd().resolve()) else "~")
    return message


def _display_policy_json(policy: Any, project_root: Path) -> str:
    """Serialize the complete policy with privacy-safe display paths."""
    value = policy.to_dict()
    for server in value["approved_servers"]:
        descriptor = server["descriptor"]
        original_cwd = descriptor["cwd"]
        descriptor["command"] = _relative_path(descriptor["command"], original_cwd)
        descriptor["cwd"] = _relative_path(original_cwd, project_root)
    return json.dumps(value, indent=2, sort_keys=True)


def _csv_values(value: Any) -> tuple[str, ...]:
    return tuple(item.strip() for item in str(value or "").split(",") if item.strip())


def parse_tool_rows(
    rows: Sequence[Mapping[str, Any]],
    argument_schema_text: str | None = None,
) -> tuple[ToolRule, ...]:
    """Convert editable UI rows into strict policy tool rules."""
    shared_schema: Any | None = None
    if argument_schema_text is not None:
        try:
            shared_schema = json.loads(argument_schema_text or "{}")
        except json.JSONDecodeError as exc:
            raise PolicyError(f"Tool argument schema is invalid JSON: {exc}") from exc
    rules: list[ToolRule] = []
    for row in rows:
        name = str(row.get("Tool name", "") or "").strip()
        principals_text = str(row.get("Principals", "") or "").strip()
        groups_text = str(row.get("Groups", "") or "").strip()
        schema_text = str(row.get("Argument schema", "") or "").strip()
        if not name and not principals_text and not groups_text:
            continue
        if shared_schema is None:
            try:
                schema = json.loads(schema_text or "{}")
            except json.JSONDecodeError as exc:
                raise PolicyError(
                    f"Tool {name or '<unnamed>'} has invalid argument-schema JSON: {exc}"
                ) from exc
        else:
            schema = shared_schema
        rules.append(
            ToolRule(
                name=name,
                effect=str(row.get("Effect", "allow") or "allow"),
                subjects=SubjectSelector(
                    principals=_csv_values(principals_text),
                    groups=_csv_values(groups_text),
                ),
                arguments_schema=schema,
            )
        )
    if not rules:
        raise PolicyError("Add at least one tool rule")
    return tuple(rules)


def _render_login(credentials: AdminCredentials) -> None:
    st.title("AgentTrust Admin")
    st.caption("Local signed MCP policy administration")
    with st.form("agenttrust-login", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", type="primary")
    if submitted:
        if credentials.authenticate(username, password):
            st.session_state["agenttrust_authenticated"] = True
            st.rerun()
        st.error("Invalid username or password")


def _render_header() -> None:
    title, logout = st.columns([5, 1])
    with title:
        st.title("AgentTrust Admin")
        st.caption("Verified MCP policy and server administration")
    with logout:
        if st.button("Log out"):
            st.session_state.pop("agenttrust_authenticated", None)
            st.rerun()


def _delete_server(paths: AdminPaths, snapshot: Any, server_id: str) -> None:
    policy = snapshot.policy
    try:
        saved = delete_mcp_server(
            paths=paths,
            expected_signature=policy.signature,
            server_id=server_id,
        )
    except (PolicyError, OSError) as exc:
        st.error(_safe_error(exc))
        return
    st.session_state["agenttrust_save_result"] = {
        "operation": "Deleted",
        "server_id": server_id,
        "expires_at": saved.policy.expires_at,
        "server_count": len(saved.policy.approved_servers),
    }
    st.session_state.pop("agenttrust_delete_candidate", None)
    st.rerun()


def _render_policy(paths: AdminPaths, snapshot: Any) -> None:
    policy = snapshot.policy
    project_root = Path.cwd().resolve()
    server_ids = {server.server_id for server in policy.approved_servers}
    if st.session_state.get("agenttrust_delete_candidate") not in server_ids:
        st.session_state.pop("agenttrust_delete_candidate", None)
    st.subheader("Approved MCP servers")
    for index, server in enumerate(policy.approved_servers):
        delete_candidate = st.session_state.get("agenttrust_delete_candidate")
        with st.expander(
            server.server_id,
            expanded=len(policy.approved_servers) == 1 or delete_candidate == server.server_id,
        ):
            field_prefix = f"server-{index}-{server.server_id}"
            spacer, delete_control = st.columns([20, 1])
            with delete_control:
                if st.button(
                    "🗑️",
                    key=f"{field_prefix}-delete",
                    help=(
                        "Delete this MCP server"
                        if len(policy.approved_servers) > 1
                        else "A policy must retain at least one MCP server"
                    ),
                    disabled=len(policy.approved_servers) == 1,
                ):
                    st.session_state["agenttrust_delete_candidate"] = server.server_id
                    st.rerun()
            st.text_input("Transport", value="stdio", disabled=True, key=f"{field_prefix}-transport")
            st.caption(f"Descriptor SHA-256 (recomputed automatically on save): `{server.descriptor_sha256}`")

            tool_rows = [
                {
                    "Effect": tool.effect,
                    "Tool name": tool.name,
                    "Principals": ", ".join(tool.subjects.principals),
                    "Groups": ", ".join(tool.subjects.groups),
                    "Argument schema": json.dumps(thaw_json(tool.arguments_schema), sort_keys=True),
                }
                for tool in server.tools
            ]
            with st.form(f"{field_prefix}-edit-form"):
                cwd_value = st.text_input(
                    "Working directory",
                    value=_relative_path(server.descriptor.cwd or str(project_root), project_root),
                    key=f"{field_prefix}-cwd",
                )
                command_value = st.text_input(
                    "Command",
                    value=_relative_path(server.descriptor.command, server.descriptor.cwd or project_root),
                    key=f"{field_prefix}-command",
                )
                args_text = st.text_area(
                    "Launch arguments (one per line, in order)",
                    value="\n".join(server.descriptor.args),
                    key=f"{field_prefix}-args",
                    height=100,
                )
                st.markdown("#### Tool authorization rules")
                edited_rows = st.data_editor(
                    tool_rows,
                    num_rows="dynamic",
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "Effect": st.column_config.SelectboxColumn(
                            "Effect", options=["allow", "deny"], required=True
                        ),
                        "Tool name": st.column_config.TextColumn("Tool name", required=True),
                        "Principals": st.column_config.TextColumn("Principals (comma-separated)"),
                        "Groups": st.column_config.TextColumn("Groups (comma-separated)"),
                        "Argument schema": st.column_config.TextColumn("Argument schema (JSON)"),
                    },
                    key=f"{field_prefix}-tools",
                )
                save_submitted = st.form_submit_button("Save changes", type="primary")

            if save_submitted:
                try:
                    rule_rows = edited_rows.to_dict("records") if hasattr(edited_rows, "to_dict") else edited_rows
                    tools = parse_tool_rows(rule_rows)
                    saved = update_mcp_server(
                        paths=paths,
                        expected_signature=policy.signature,
                        server_id=server.server_id,
                        command=command_value.strip(),
                        args=tuple(line for line in args_text.splitlines() if line != ""),
                        cwd=cwd_value.strip(),
                        tools=tools,
                    )
                except (PolicyError, OSError) as exc:
                    st.error(_safe_error(exc))
                else:
                    st.session_state["agenttrust_save_result"] = {
                        "operation": "Updated",
                        "server_id": server.server_id,
                        "expires_at": saved.policy.expires_at,
                        "server_count": len(saved.policy.approved_servers),
                    }
                    st.rerun()

            if delete_candidate == server.server_id:
                st.warning(
                    f"Delete {server.server_id}? This regenerates and re-signs the policy."
                )
                confirm, cancel, remainder = st.columns([1, 1, 6])
                with confirm:
                    if st.button(
                        "Confirm delete",
                        type="primary",
                        key=f"{field_prefix}-confirm-delete",
                    ):
                        _delete_server(paths, snapshot, server.server_id)
                with cancel:
                    if st.button("Cancel", key=f"{field_prefix}-cancel-delete"):
                        st.session_state.pop("agenttrust_delete_candidate", None)
                        st.rerun()

    st.subheader("Signed policy")
    first, second, third = st.columns(3)
    first.metric("Policy ID", policy.policy_id)
    second.metric("Signature", "Verified")
    third.metric("MCP servers", len(policy.approved_servers))
    issuer, key_id = st.columns(2)
    issuer.text_input("Issuer", value=policy.issuer, disabled=True, key="policy-issuer")
    key_id.text_input("Signing key ID", value=policy.key_id, disabled=True, key="policy-key-id")
    issued, expires = st.columns(2)
    issued.text_input("Issued at", value=policy.issued_at, disabled=True, key="policy-issued-at")
    expires.text_input("Expires at", value=policy.expires_at, disabled=True, key="policy-expires-at")

    st.subheader("Full policy JSON (read-only)")
    st.caption(
        "Display-only view. Relative executable and working-directory paths are resolved "
        "from the AgentTrust repository when the relay starts."
    )
    st.code(_display_policy_json(policy, project_root), language="json", line_numbers=True)


def _render_add_server(paths: AdminPaths, snapshot: Any) -> None:
    st.subheader("Add MCP server")
    st.caption(
        "The server is appended to the unsigned admin manifest and the complete policy is re-signed."
    )
    with st.form("add-mcp-server"):
        server_id = st.text_input("Server ID", placeholder="billing-mcp")
        command = st.text_input(
            "Executable path or command name",
            placeholder="uv, .venv/bin/python, or /absolute/path/to/python",
            help=(
                "Command names are resolved from PATH. Path-like relative commands are resolved "
                "from the directory where the relay starts and stored as relative values."
            ),
        )
        args_text = st.text_area(
            "Launch arguments (one per line, in order)",
            placeholder="-m\npackage.server",
        )
        cwd = st.text_input(
            "Working directory",
            placeholder=". or a path relative to the AgentTrust repository",
        )
        st.caption(
            "Local-only path input: relative values are stored for signing, but the UI does not "
            "validate whether the command or working directory exists."
        )
        schema_text = st.text_area(
            "Tool argument schema (JSON)",
            value=json.dumps(
                {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
                indent=2,
            ),
            height=180,
            help="This schema is applied to every authorization rule in the table below.",
        )
        st.markdown("#### Tool authorization rules")
        st.caption(
            "Add one row per allow or deny rule. The argument schema above applies to every row."
        )
        rules = st.data_editor(
            [
                {
                    "Effect": "allow",
                    "Tool name": "",
                    "Principals": "",
                    "Groups": "",
                }
            ],
            num_rows="dynamic",
            width="stretch",
            hide_index=True,
            column_config={
                "Effect": st.column_config.SelectboxColumn(
                    "Effect", options=["allow", "deny"], required=True
                ),
                "Tool name": st.column_config.TextColumn("Tool name", required=True),
                "Principals": st.column_config.TextColumn("Principals (comma-separated)"),
                "Groups": st.column_config.TextColumn("Groups (comma-separated)"),
            },
            key="agenttrust-tool-rules",
        )
        submitted = st.form_submit_button("Add and sign MCP server", type="primary")

    if not submitted:
        return
    try:
        rule_rows = rules.to_dict("records") if hasattr(rules, "to_dict") else rules
        tools = parse_tool_rows(rule_rows, schema_text)
        saved = append_mcp_server(
            paths=paths,
            expected_signature=snapshot.policy.signature,
            server_id=server_id.strip(),
            command=command.strip(),
            args=tuple(line for line in args_text.splitlines() if line != ""),
            cwd=cwd.strip(),
            tools=tools,
        )
    except (PolicyError, OSError) as exc:
        st.error(_safe_error(exc))
        return
    st.session_state["agenttrust_save_result"] = {
        "operation": "Added",
        "server_id": server_id.strip(),
        "expires_at": saved.policy.expires_at,
        "server_count": len(saved.policy.approved_servers),
    }
    st.rerun()


def _render_audit_logs(paths: AdminPaths) -> None:
    st.subheader("Audit logs")
    controls, refresh = st.columns([5, 1])
    with controls:
        limit = st.selectbox(
            "Entries to load",
            options=[100, 500, 1000],
            index=1,
            key="agenttrust-audit-limit",
        )
    with refresh:
        st.write("")
        if st.button("Refresh", key="agenttrust-audit-refresh"):
            st.rerun()

    if not paths.audit_log.exists():
        st.info("No audit log exists yet. Relay authorization decisions will appear here.")
        return
    try:
        events = load_audit_events(paths.audit_log, limit=limit)
    except PolicyError as exc:
        st.error(_safe_error(exc))
        return
    if not events:
        st.info("The audit log is empty.")
        return

    allowed_count = sum(event.get("allowed") is True for event in events)
    denied_count = sum(event.get("allowed") is False for event in events)
    loaded, allowed, denied = st.columns(3)
    loaded.metric("Entries loaded", len(events))
    allowed.metric("Allowed", allowed_count)
    denied.metric("Denied", denied_count)

    rows = []
    for event in reversed(events):
        groups = event.get("principal_groups", [])
        rows.append(
            {
                "Decided at": event.get("decided_at", ""),
                "Allowed": event.get("allowed", ""),
                "Principal": event.get("principal_id", ""),
                "Groups": ", ".join(groups) if isinstance(groups, list) else str(groups),
                "Server": event.get("server_id", ""),
                "Tool": event.get("tool_name", ""),
                "Code": event.get("code", ""),
                "Reason": event.get("reason", ""),
                "Arguments": json.dumps(event.get("arguments", {}), sort_keys=True),
            }
        )
    st.caption("Newest authorization decisions are shown first.")
    st.dataframe(rows, width="stretch", hide_index=True)


def main() -> None:
    st.set_page_config(page_title="AgentTrust Admin", page_icon="🔐", layout="wide")
    credentials = AdminCredentials.from_environment()
    if not st.session_state.get("agenttrust_authenticated", False):
        _render_login(credentials)
        return

    _render_header()
    result = st.session_state.pop("agenttrust_save_result", None)
    if result:
        st.success(
            f"{result['operation']} {result['server_id']} and verified the new policy. "
            f"The policy expires at {result['expires_at']}."
        )
        st.warning("Restart the relay to load this policy; hot reload is not implemented.")
        if result["server_count"] > 1:
            st.info("The policy contains multiple servers. Start the relay with --server-id.")

    paths = AdminPaths.from_environment()
    try:
        snapshot = load_policy_snapshot(paths)
    except (PolicyError, OSError) as exc:
        st.error(f"Policy verification failed: {_safe_error(exc)}")
        st.info("Policy changes are disabled until the policy and keyring are valid.")
        return
    policy_tab, add_tab, audit_tab = st.tabs(
        ["Policy and MCP servers", "➕ Add MCP server", "Audit logs"]
    )
    with policy_tab:
        _render_policy(paths, snapshot)
    with add_tab:
        _render_add_server(paths, snapshot)
    with audit_tab:
        _render_audit_logs(paths)


if __name__ == "__main__":
    main()
