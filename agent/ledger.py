
"""Append-only, tamper-evident JSONL audit ledger."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


GENESIS_HASH = "0" * 64


def _calculate_hash(entry: dict) -> str:
    """Hash a canonical JSON representation, excluding the hash field."""
    payload = {
        key: value
        for key, value in entry.items()
        if key != "hash"
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Append one entry and return the record including its chain hash."""
    if not isinstance(entry, dict):
        raise TypeError("ledger entry must be a dict")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = GENESIS_HASH

    if path.exists() and path.stat().st_size > 0:
        lines = path.read_text(encoding="utf-8").splitlines()
        if lines:
            try:
                previous = json.loads(lines[-1])
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "cannot append to a ledger with an invalid last line"
                ) from exc

            if not isinstance(previous, dict):
                raise ValueError("last ledger entry must be a JSON object")

            stored_hash = previous.get("hash")
            if not isinstance(stored_hash, str) or not stored_hash:
                raise ValueError("last ledger entry has no valid hash")

            previous_hash = stored_hash

    # Recalculate chain metadata; do not trust caller-supplied values.
    record = {
        key: value
        for key, value in entry.items()
        if key not in {"hash", "prev_hash"}
    }
    record["prev_hash"] = previous_hash
    record["hash"] = _calculate_hash(record)

    with path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        )

    return record


def verify(path: Path) -> bool:
    """Verify reasons, stored hashes, and every link in the hash chain."""
    path = Path(path)

    if not path.is_file():
        return False

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False

    if not lines:
        return False

    previous_hash = GENESIS_HASH

    for line in lines:
        if not line.strip():
            return False

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False

        if not isinstance(record, dict):
            return False

        reason = record.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return False

        if record.get("prev_hash") != previous_hash:
            return False

        stored_hash = record.get("hash")
        if not isinstance(stored_hash, str):
            return False

        if stored_hash != _calculate_hash(record):
            return False

        previous_hash = stored_hash

    return True
