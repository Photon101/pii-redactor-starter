# PII Redaction And Privacy Audit Skill

Use this skill when a task involves redacting personal data from CSV exports, support logs, form submissions, policy-review evidence, or document-extraction output while keeping a useful audit trail.

## What This Skill Provides

- Deterministic PII detection for emails, phone numbers, UK National Insurance numbers, credit cards, IP addresses, and address-like fragments.
- CSV-to-CSV redaction that preserves row shape and replaces sensitive values with labels such as `[EMAIL]` or `[PHONE]`.
- JSON audit output with per-row finding counts, review flags, and type summaries without storing the original sensitive values.
- A small Python codebase that is easy to adapt for client-specific fields, redaction labels, and high-risk routing rules.

## Best Fit

- Support-ticket exports before sharing with contractors or LLM tools.
- Lead-form spam and privacy review queues.
- Legal, policy, or HR document triage where raw personal data must not leak into reports.
- Data-cleaning pipelines that need reproducible privacy checks before downstream analysis.

## Repository

Source and runnable examples:

https://github.com/Photon101/pii-redactor-starter

## Quick Start

```bash
git clone https://github.com/Photon101/pii-redactor-starter
cd pii-redactor-starter
PYTHONPATH=src python3 -m pii_redactor.cli examples/sample_texts.csv /tmp/pii-redacted.csv --audit /tmp/pii-audit.json
```

For development validation:

```bash
uv run --extra dev python -m pytest
```

## Agent Workflow

1. Inspect the input schema and identify fields that may contain free text or contact data.
2. Run the redactor on a sample export.
3. Review the JSON audit for high-risk rows and missing detector types.
4. Add project-specific detectors or allow-list rules only when the sample shows a real gap.
5. Deliver redacted output plus the audit summary, not the unredacted source data.

## Safety Rules

- Do not paste raw client PII into public issues, public PRs, marketplace listings, or chat transcripts.
- Do not include original sensitive values in the JSON audit.
- Keep client-specific sample data out of the repository unless it is synthetic.
- Prefer deterministic local redaction before sending text to any LLM or external API.

