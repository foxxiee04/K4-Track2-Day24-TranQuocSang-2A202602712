
"""PII detection and redaction for the Day24 governance lab."""
from __future__ import annotations

import re


# Email thông dụng; cho phép dấu chấm kết thúc câu đứng ngoài email.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)

# Bắt các chuỗi số dài 8–16 chữ số, cho phép cách nhau bằng
# dấu cách hoặc dấu gạch ngang. Phân loại bằng độ dài và ngữ cảnh.
_NUMBER_RE = re.compile(
    r"(?<![\w.@+-])\d(?:[ \t-]?\d){7,15}(?![\w@])"
)

_CONTEXT_PATTERNS = (
    ("VN_CCCD", re.compile(r"\bCCCD\b", re.IGNORECASE)),
    (
        "VN_BANK_ACCOUNT",
        re.compile(
            r"(?:số\s+tài\s+khoản|tài\s+khoản|\bSTK\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "VN_PHONE",
        re.compile(
            r"(?:\bSĐT\b|\bSDT\b|số\s+điện\s+thoại|điện\s+thoại)",
            re.IGNORECASE,
        ),
    ),
)


def _nearest_context(text: str, start: int) -> str | None:
    """Trả về loại nhãn gần nhất đứng trước chuỗi số."""
    prefix = text[max(0, start - 70):start]
    nearest_type = None
    nearest_end = -1

    for entity_type, pattern in _CONTEXT_PATTERNS:
        for match in pattern.finditer(prefix):
            if match.end() > nearest_end:
                nearest_end = match.end()
                nearest_type = entity_type

    return nearest_type


def detect(text: str) -> list[dict]:
    """Phát hiện CCCD, điện thoại, số tài khoản và email."""
    entities: list[dict] = []

    for match in _EMAIL_RE.finditer(text):
        entities.append({
            "type": "EMAIL",
            "start": match.start(),
            "end": match.end(),
        })

    for match in _NUMBER_RE.finditer(text):
        raw_value = match.group(0)
        digits = re.sub(r"\D", "", raw_value)
        context = _nearest_context(text, match.start())
        entity_type = None

        # Ưu tiên nhãn ngữ cảnh để tránh nhầm CCCD với STK,
        # hoặc nhầm số điện thoại với một loại số khác.
        if context == "VN_BANK_ACCOUNT":
            if 8 <= len(digits) <= 16:
                entity_type = "VN_BANK_ACCOUNT"

        elif context == "VN_CCCD":
            if len(digits) == 12:
                entity_type = "VN_CCCD"

        elif context == "VN_PHONE":
            if len(digits) in (10, 11) and digits.startswith("0"):
                entity_type = "VN_PHONE"

        else:
            # Hỗ trợ trường hợp không có nhãn đi kèm.
            if len(digits) == 12:
                entity_type = "VN_CCCD"
            elif len(digits) in (10, 11) and digits.startswith("0"):
                entity_type = "VN_PHONE"

        if entity_type is not None:
            entities.append({
                "type": entity_type,
                "start": match.start(),
                "end": match.end(),
            })

    return sorted(
        entities,
        key=lambda entity: (entity["start"], entity["end"]),
    )


def redact(text: str) -> str:
    """Thay các entity được phát hiện bằng placeholder tương ứng."""
    entities = detect(text)
    if not entities:
        return text

    # Nếu có entity chồng lấn, giữ span dài hơn.
    non_overlapping: list[dict] = []

    for entity in sorted(
        entities,
        key=lambda item: (
            -(item["end"] - item["start"]),
            item["start"],
        ),
    ):
        overlaps = any(
            entity["start"] < chosen["end"]
            and chosen["start"] < entity["end"]
            for chosen in non_overlapping
        )
        if not overlaps:
            non_overlapping.append(entity)

    # Thay từ phải sang trái để offset ban đầu không bị lệch.
    for entity in sorted(
        non_overlapping,
        key=lambda item: item["start"],
        reverse=True,
    ):
        start = entity["start"]
        end = entity["end"]
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[:start] + replacement + text[end:]

    return text
