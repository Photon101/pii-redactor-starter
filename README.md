# PII Redactor Starter

Small deterministic starter for redacting common personal data from CSV text fields. It produces:

- redacted CSV output
- per-row labels and review flags
- JSON audit counts without storing the original sensitive values

It is intentionally simple enough to inspect and adapt for client-specific policies before adding OCR, LLM review, or platform integrations.

## Quick Start

```bash
uv run --extra dev pytest
uv run pii-redactor examples/sample_texts.csv /tmp/redacted.csv --audit /tmp/audit.json
```

Without installing the package:

```bash
PYTHONPATH=src python -m pii_redactor.cli examples/sample_texts.csv /tmp/redacted.csv --audit /tmp/audit.json
```

## Detectors

- email addresses
- UK-style phone numbers
- UK postcodes
- UK National Insurance numbers
- credit/debit card numbers with Luhn validation
- IPv4 addresses

## CSV Format

Default input columns:

- `id`
- `text`

The column names can be changed:

```bash
uv run pii-redactor input.csv output.csv --id-column ticket_id --text-column body --audit audit.json
```

## Output

The output CSV adds:

- `redacted_text`
- `findings_count`
- `labels`
- `review_required`

The audit JSON contains label totals and row-level counts, but not the matched sensitive values.
