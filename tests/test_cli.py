import csv
import json
from pathlib import Path

from pii_redactor.cli import main


def test_cli_writes_redacted_csv_and_audit(tmp_path: Path) -> None:
    input_csv = tmp_path / "input.csv"
    output_csv = tmp_path / "output.csv"
    audit_json = tmp_path / "audit.json"
    input_csv.write_text("id,text\n1,alice@example.com lives at BR1 2EJ\n", encoding="utf-8")

    assert main([str(input_csv), str(output_csv), "--audit", str(audit_json)]) == 0

    with output_csv.open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))

    assert row["redacted_text"] == "[REDACTED_EMAIL] lives at [REDACTED_POSTCODE_UK]"
    assert row["findings_count"] == "2"
    assert row["labels"] == "email;postcode_uk"

    audit = json.loads(audit_json.read_text(encoding="utf-8"))
    assert audit["rows"] == 1
    assert audit["label_counts"] == {"email": 1, "postcode_uk": 1}
    assert audit["row_audit"][0]["id"] == "1"
