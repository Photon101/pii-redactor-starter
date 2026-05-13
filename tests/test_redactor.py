from pii_redactor import redact_text
from pii_redactor.redactor import luhn_valid


def test_redacts_common_pii() -> None:
    result = redact_text("Email alice@example.com, phone +44 20 7946 0958, postcode BR1 2EJ.")

    assert "[REDACTED_EMAIL]" in result.redacted_text
    assert "[REDACTED_PHONE_UK]" in result.redacted_text
    assert "[REDACTED_POSTCODE_UK]" in result.redacted_text
    assert result.labels == ("email", "phone_uk", "postcode_uk")
    assert result.review_required is True


def test_redacts_high_risk_identifiers() -> None:
    result = redact_text("NI AB 12 34 56 C and card 4111 1111 1111 1111.")

    assert "[REDACTED_NATIONAL_INSURANCE]" in result.redacted_text
    assert "[REDACTED_CREDIT_CARD]" in result.redacted_text
    assert result.review_required is True


def test_rejects_invalid_luhn_candidates() -> None:
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")
    assert "[REDACTED_CREDIT_CARD]" not in redact_text("4111 1111 1111 1112").redacted_text


def test_preserves_clean_text() -> None:
    result = redact_text("No sensitive values in this note.")

    assert result.redacted_text == "No sensitive values in this note."
    assert result.findings == ()
    assert result.review_required is False
