
"""Policy Enforcement Point (PEP) for the Day24 governance lab."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


PRINCIPALS_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "principals.json"
)


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _deny(reason: str) -> tuple[bool, str]:
    """Return a deny decision with a non-empty audit reason."""
    return False, reason


def _load_principals() -> dict:
    """Load the lab's trusted mock principal registry."""
    try:
        data = json.loads(
            PRINCIPALS_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return {}

    return data if isinstance(data, dict) else {}


def _is_unexpired(expires_at: str) -> bool:
    """Accept an ISO-8601 timestamp only when it has a timezone."""
    if not isinstance(expires_at, str) or not expires_at.strip():
        return False

    value = expires_at.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        expiry = datetime.fromisoformat(value)
    except ValueError:
        return False

    if expiry.tzinfo is None or expiry.utcoffset() is None:
        return False

    return expiry.astimezone(timezone.utc) > datetime.now(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    """Evaluate policy before a tool is allowed to execute."""

    # Mandatory rule: restricted data must never cross an enabled
    # egress boundary, even if every other authorization check passes.
    if (
        context.data_classification == "restricted"
        and context.egress_enabled is True
    ):
        return _deny(
            "restricted data is not allowed when egress is enabled"
        )

    if context.data_classification not in {
        "public",
        "internal",
        "restricted",
    }:
        return _deny("unknown or invalid data classification")

    if context.delegation_depth < 0:
        return _deny("invalid negative delegation depth")

    if not context.principal_id:
        return _deny("missing principal identity")

    if not context.requested_tool:
        return _deny("missing requested tool")

    principals = _load_principals()
    principal = principals.get(context.principal_id)

    if not isinstance(principal, dict):
        return _deny("unknown principal")

    allowed_tools = principal.get("allowed_tools")
    allowed_purposes = principal.get("purposes")

    if not isinstance(allowed_tools, list):
        return _deny("principal has no valid allowed_tools policy")

    if not isinstance(allowed_purposes, list):
        return _deny("principal has no valid purposes policy")

    if context.request_purpose not in allowed_purposes:
        return _deny("request purpose is not allowed for this principal")

    if not _is_unexpired(context.expires_at):
        return _deny("authorization has expired or has an invalid expiry")

    if context.requested_tool not in allowed_tools:
        return _deny("requested tool is outside principal permissions")

    if context.requested_tool not in context.agent_scopes:
        return _deny("requested tool is outside agent scopes")

    if context.delegation_depth > 0:
        if context.requested_tool not in context.parent_scopes:
            return _deny("requested tool is outside parent delegation scopes")

    # http_post crosses the egress boundary. It cannot run when the
    # current run has egress disabled.
    if (
        context.requested_tool == "http_post"
        and context.egress_enabled is not True
    ):
        return _deny("egress is disabled for this run")

    return True, "allowed by principal, purpose, scopes, and expiry"
