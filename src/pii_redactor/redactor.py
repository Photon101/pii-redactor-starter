from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Finding:
    label: str
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class RedactionResult:
    redacted_text: str
    findings: tuple[Finding, ...]
    review_required: bool

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted({finding.label for finding in self.findings}))


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("phone_uk", re.compile(r"(?<!\w)(?:\+44\s?|\(?0)(?:\d[\s().-]?){9,12}\d(?!\w)")),
    ("postcode_uk", re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b", re.IGNORECASE)),
    ("national_insurance", re.compile(r"\b(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.IGNORECASE)),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
)

CARD_CANDIDATE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
HIGH_RISK_LABELS = {"credit_card", "national_insurance"}


def luhn_valid(value: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", value)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _overlaps(candidate: Finding, accepted: list[Finding]) -> bool:
    return any(candidate.start < item.end and item.start < candidate.end for item in accepted)


def _collect_findings(text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            finding = Finding(label, match.start(), match.end(), f"[REDACTED_{label.upper()}]")
            if not _overlaps(finding, findings):
                findings.append(finding)

    for match in CARD_CANDIDATE.finditer(text):
        if luhn_valid(match.group(0)):
            finding = Finding("credit_card", match.start(), match.end(), "[REDACTED_CREDIT_CARD]")
            if not _overlaps(finding, findings):
                findings.append(finding)

    return tuple(sorted(findings, key=lambda item: (item.start, item.end)))


def redact_text(text: str, review_threshold: int = 3) -> RedactionResult:
    findings = _collect_findings(text)
    if not findings:
        return RedactionResult(text, (), False)

    parts: list[str] = []
    cursor = 0
    for finding in findings:
        parts.append(text[cursor:finding.start])
        parts.append(finding.replacement)
        cursor = finding.end
    parts.append(text[cursor:])

    labels = {finding.label for finding in findings}
    review_required = bool(labels & HIGH_RISK_LABELS) or len(findings) >= review_threshold
    return RedactionResult("".join(parts), findings, review_required)
