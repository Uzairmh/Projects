
import re
from typing import Dict, List, Pattern, Callable

class Detector:
    def __init__(self, name: str, pattern: str, severity: str, mask_func: Callable[[str], str]):
        self.name = name
        self.regex: Pattern = re.compile(pattern, flags=re.IGNORECASE)
        self.severity = severity
        self.mask_func = mask_func

def _mask_email(s: str) -> str:
    # Keep domain for utility
    if "@" in s:
        local, domain = s.split("@", 1)
        return "***@" + domain
    return "***"

def _mask_phone(s: str) -> str:
    digits = [c for c in s if c.isdigit()]
    if len(digits) <= 3:
        return "*" * len(s)
    # Keep last 3 digits
    keep = digits[-3:]
    masked = []
    di = len(digits) - 1
    for ch in reversed(s):
        if ch.isdigit():
            if keep and ch == keep[-1]:
                masked.append(keep.pop())
            else:
                masked.append("*")
        else:
            masked.append(ch)
    return "".join(reversed(masked))

def _mask_constant(tag: str):
    def _inner(_: str) -> str:
        return f"{tag}-REDACTED"
    return _inner

DETECTORS: List[Detector] = [
    # Email
    Detector(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        severity="medium",
        mask_func=_mask_email,
    ),
    # UK mobile phone numbers (simple heuristic for 07xxx xxxxxx or +44 7xxx xxxxxx)
    Detector(
        name="uk_phone",
        pattern=r"(?:\+44\s?7\d{3}|\(?07\d{3}\)?)\s?\d{3}\s?\d{3}",
        severity="medium",
        mask_func=_mask_phone,
    ),
    # UK postcode (broad, not exhaustive validation)
    Detector(
        name="uk_postcode",
        pattern=r"\b([A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b",
        severity="low",
        mask_func=_mask_constant("POSTCODE"),
    ),
    # UK National Insurance number (approximate, avoids invalid prefixes)
    Detector(
        name="ni_number",
        pattern=r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        severity="high",
        mask_func=_mask_constant("NI"),
    ),
    # NHS number (10 digits, often spaced 3-3-4) - approximate
    Detector(
        name="nhs_number",
        pattern=r"\b\d{3}\s?\d{3}\s?\d{4}\b",
        severity="high",
        mask_func=_mask_constant("NHS"),
    ),
]
