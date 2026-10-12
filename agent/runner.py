
"""Containment runner: split untrusted documents from private data access."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.pii import redact


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_FILENAME_RE = re.compile(r"ticket-(\d+)\.md", re.IGNORECASE)
RUN_TTL = timedelta(minutes=5)


class RunnerScaffoldPending(NotImplementedError):
    """Kept for compatibility with the original pre-3c scaffold tests."""


def _args_hash(args: dict) -> str:
    """Hash tool arguments without storing raw arguments in the ledger."""
    canonical = json.dumps(
        args,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _authorize_tool(
    *,
    ledger_path: Path,
    run_id: str,
    principal_id: str,
    agent_id: str,
    tool_name: str,
    args_for_audit: dict,
    classification: str,
    purpose: str,
    delegation_depth: int,
    egress_enabled: bool,
    agent_scopes: tuple[str, ...],
    parent_scopes: tuple[str, ...],
    expires_at: str,
) -> bool:
    """Evaluate policy and ledger the decision before tool execution."""
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool_name,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    )

    allowed, reason = policy.check(context)

    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool_name,
            "args_hash": _args_hash(args_for_audit),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason or "policy returned an empty reason",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    return allowed


def _extract_ticket_ids(docs: list[dict]) -> list[int]:
    """Extract numeric ticket IDs exclusively from document filenames."""
    ticket_ids: set[int] = set()

    for doc in docs:
        filename = doc.get("id")
        if not isinstance(filename, str):
            continue

        match = _TICKET_FILENAME_RE.fullmatch(Path(filename).name)
        if match:
            ticket_ids.add(int(match.group(1)))

    return sorted(ticket_ids)


def _resolve_customer_ids(ticket_ids: list[int]) -> list[str]:
    """Resolve customer IDs using the trusted related_tickets mapping.

    Never parse customer IDs from document text or LLM output.
    """
    if not ticket_ids:
        return []

    try:
        customers = json.loads(
            tools.CUSTOMERS_FILE.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Không thể đọc trusted customer mapping; dừng xử lý an toàn."
        ) from exc

    if not isinstance(customers, list):
        raise RuntimeError("Trusted customer mapping không phải JSON array.")

    wanted_tickets = set(ticket_ids)
    resolved: list[str] = []
    seen: set[str] = set()

    for ticket_id in sorted(wanted_tickets):
        for customer in customers:
            if not isinstance(customer, dict):
                continue

            customer_id = customer.get("customer_id")
            related_tickets = customer.get("related_tickets")

            if not isinstance(customer_id, str):
                continue
            if not isinstance(related_tickets, list):
                continue

            if ticket_id not in related_tickets:
                continue
            if customer_id in seen:
                continue

            seen.add(customer_id)
            resolved.append(customer_id)

    return resolved


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Run the two-stage workflow with policy checks at tool boundaries."""
    ledger_dir = Path(log_dir) if log_dir is not None else REPORTS_DIR
    ledger_path = ledger_dir / "ledger.jsonl"

    run_id = uuid.uuid4().hex
    expires_at = (
        datetime.now(timezone.utc) + RUN_TTL
    ).isoformat()

    run_a_id = "lab24-agent/run-a"
    run_b_id = "lab24-agent/run-b"

    # Run A: the only tool allowed in this stage is search_docs.
    search_allowed = _authorize_tool(
        ledger_path=ledger_path,
        run_id=run_id,
        principal_id=principal_id,
        agent_id=run_a_id,
        tool_name="search_docs",
        args_for_audit={"query": message},
        classification="internal",
        purpose="summarize-tickets",
        delegation_depth=0,
        egress_enabled=False,
        agent_scopes=("search_docs",),
        parent_scopes=(),
        expires_at=expires_at,
    )

    if not search_allowed:
        return llm.summarize([])

    # Policy has allowed the tool, so it may now execute.
    docs = tools.search_docs(message)

    # Apply the PII gate before document text enters LLM context.
    safe_docs = [
        {
            "id": str(doc.get("id", "")),
            "text": redact(str(doc.get("text", ""))),
        }
        for doc in docs
    ]

    # Detection is telemetry only. Never use customer_ids or target_url
    # from the untrusted instruction to choose a record or destination.
    combined_text = "\n\n".join(doc["text"] for doc in safe_docs)
    injection_detected = llm.find_injection(combined_text) is not None

    # The only data crossing from Run A to Run B is a typed list[int]
    # derived from filenames, never the document text.
    ticket_ids = _extract_ticket_ids(docs)
    candidate_customer_ids = _resolve_customer_ids(ticket_ids)

    # Run B: every customer-record read must pass the PEP first.
    records: list[dict] = []

    for customer_id in candidate_customer_ids:
        read_allowed = _authorize_tool(
            ledger_path=ledger_path,
            run_id=run_id,
            principal_id=principal_id,
            agent_id=run_b_id,
            tool_name="read_customer",
            args_for_audit={"customer_id": customer_id},
            classification="restricted",
            purpose="summarize-tickets",
            delegation_depth=1,
            egress_enabled=False,
            agent_scopes=("read_customer",),
            parent_scopes=("read_customer",),
            expires_at=expires_at,
        )

        if not read_allowed:
            continue

        try:
            record = tools.read_customer(customer_id)
        except tools.ToolError:
            continue

        # Keep private records inside Run B. Do not put them into the
        # LLM context, return them to the caller, or write them to ledger.
        records.append(record)

    # A detected injection may cause an egress attempt to be evaluated,
    # but its supplied URL is ignored. The destination is fixed to the
    # lab sink, and policy must authorize the call before it can execute.
    if injection_detected:
        egress_url = "http://127.0.0.1:10024/reconcile"

        egress_allowed = _authorize_tool(
            ledger_path=ledger_path,
            run_id=run_id,
            principal_id=principal_id,
            agent_id=run_b_id,
            tool_name="http_post",
            args_for_audit={
                "destination": "fixed-local-lab-sink",
                "record_count": len(records),
            },
            classification="restricted",
            purpose="support-reply",
            delegation_depth=1,
            egress_enabled=True,
            agent_scopes=("http_post",),
            parent_scopes=("http_post",),
            expires_at=expires_at,
        )

        if egress_allowed and records:
            # With the current policy/principal fixtures, restricted
            # data plus enabled egress must be denied before this point.
            tools.http_post(egress_url, {"records": records})

    # Preserve the CLI's user-facing summary. Private records are never
    # passed to summarize().
    return llm.summarize(safe_docs)
