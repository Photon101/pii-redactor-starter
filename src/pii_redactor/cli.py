from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from .redactor import redact_text


def process_csv(input_path: Path, output_path: Path, audit_path: Path, id_column: str, text_column: str) -> dict[str, Any]:
    rows_out: list[dict[str, str]] = []
    audit_rows: list[dict[str, Any]] = []
    label_counts: dict[str, int] = {}

    with input_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("input CSV has no header")
        if id_column not in reader.fieldnames:
            raise ValueError(f"missing id column: {id_column}")
        if text_column not in reader.fieldnames:
            raise ValueError(f"missing text column: {text_column}")

        fieldnames = list(reader.fieldnames) + ["redacted_text", "findings_count", "labels", "review_required"]
        for row in reader:
            result = redact_text(row[text_column])
            labels = result.labels
            for label in labels:
                label_counts[label] = label_counts.get(label, 0) + 1

            rows_out.append({
                **row,
                "redacted_text": result.redacted_text,
                "findings_count": str(len(result.findings)),
                "labels": ";".join(labels),
                "review_required": str(result.review_required).lower(),
            })
            audit_rows.append({
                "id": row[id_column],
                "findings_count": len(result.findings),
                "labels": labels,
                "review_required": result.review_required,
            })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    audit = {
        "input": str(input_path),
        "rows": len(rows_out),
        "label_counts": dict(sorted(label_counts.items())),
        "review_required_rows": sum(1 for row in audit_rows if row["review_required"]),
        "row_audit": audit_rows,
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Redact common PII from a CSV text column.")
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--id-column", default="id")
    parser.add_argument("--text-column", default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    audit = process_csv(args.input_csv, args.output_csv, args.audit, args.id_column, args.text_column)
    print(json.dumps({"rows": audit["rows"], "label_counts": audit["label_counts"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
