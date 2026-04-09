#!/usr/bin/env python3
"""Extraction coverage report — extracted vs. stub-only documents per body/session.

A document row is created as a *stub* by import_undl_votes.py for every meeting
referenced in the UNDL voting CSVs, even when the PDF has not been processed yet.
A document is considered *extracted* when it has at least one speech in the
``speeches`` table.

Usage
-----
    python scripts/coverage_report.py
    python scripts/coverage_report.py --db postgresql://user:pass@host/db
    python scripts/coverage_report.py --body GA
    python scripts/coverage_report.py --body SC
    python scripts/coverage_report.py --csv report.csv
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402

from src.db.database import get_engine  # noqa: E402

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

_QUERY = """
SELECT
    d.body,
    d.session,
    COUNT(*)                                                        AS total,
    COUNT(CASE WHEN sq.speech_count > 0 THEN 1 END)                AS extracted,
    COUNT(CASE WHEN sq.speech_count = 0 OR sq.speech_count IS NULL
               THEN 1 END)                                          AS stub_only
FROM documents d
LEFT JOIN (
    SELECT document_id, COUNT(*) AS speech_count
    FROM   speeches
    GROUP  BY document_id
) sq ON d.id = sq.document_id
WHERE (:body IS NULL OR d.body = :body)
GROUP BY d.body, d.session
ORDER BY d.body, d.session NULLS LAST
"""


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _pct(part: int, total: int) -> str:
    if total == 0:
        return "  n/a"
    return f"{100 * part / total:5.1f}%"


def _print_table(rows: list[dict]) -> None:
    """Print a human-readable ASCII table to stdout."""
    # Group by body for sub-totals
    bodies: dict[str, list[dict]] = {}
    for row in rows:
        bodies.setdefault(row["body"], []).append(row)

    col_widths = {
        "session": 9,
        "total": 7,
        "extracted": 10,
        "stub_only": 9,
        "coverage": 9,
    }
    header = (
        f"{'Session':>{col_widths['session']}}"
        f"  {'Total':>{col_widths['total']}}"
        f"  {'Extracted':>{col_widths['extracted']}}"
        f"  {'Stub-only':>{col_widths['stub_only']}}"
        f"  {'Coverage':>{col_widths['coverage']}}"
    )
    sep = "-" * len(header)

    for body, body_rows in bodies.items():
        body_total     = sum(r["total"]     for r in body_rows)
        body_extracted = sum(r["extracted"] for r in body_rows)
        body_stub      = sum(r["stub_only"] for r in body_rows)

        print(f"\n{'═' * len(header)}")
        print(f"  Body: {body}    ({body_extracted}/{body_total} meetings extracted"
              f", {_pct(body_extracted, body_total).strip()} coverage)")
        print(f"{'═' * len(header)}")
        print(header)
        print(sep)

        for row in body_rows:
            session_label = str(row["session"]) if row["session"] is not None else "(none)"
            print(
                f"{session_label:>{col_widths['session']}}"
                f"  {row['total']:>{col_widths['total']}}"
                f"  {row['extracted']:>{col_widths['extracted']}}"
                f"  {row['stub_only']:>{col_widths['stub_only']}}"
                f"  {_pct(row['extracted'], row['total']):>{col_widths['coverage']}}"
            )

        print(sep)
        print(
            f"{'TOTAL':>{col_widths['session']}}"
            f"  {body_total:>{col_widths['total']}}"
            f"  {body_extracted:>{col_widths['extracted']}}"
            f"  {body_stub:>{col_widths['stub_only']}}"
            f"  {_pct(body_extracted, body_total):>{col_widths['coverage']}}"
        )


def _write_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["body", "session", "total", "extracted", "stub_only", "coverage_pct"],
        )
        writer.writeheader()
        for row in rows:
            pct = round(100 * row["extracted"] / row["total"], 2) if row["total"] else None
            writer.writerow({**row, "coverage_pct": pct})
    print(f"CSV written to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print per-body/session extraction coverage from the database."
    )
    parser.add_argument("--db", metavar="URL", help="PostgreSQL connection URL (overrides DATABASE_URL)")
    parser.add_argument("--body", metavar="BODY", help="Filter to a single body: GA or SC")
    parser.add_argument("--csv", metavar="FILE", help="Also write results to a CSV file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s  %(message)s",
    )

    engine = get_engine(args.db)

    with engine.connect() as conn:
        result = conn.execute(
            text(_QUERY),
            {"body": args.body.upper() if args.body else None},
        )
        rows = [
            {
                "body":      row.body,
                "session":   row.session,
                "total":     row.total,
                "extracted": row.extracted,
                "stub_only": row.stub_only,
            }
            for row in result
        ]

    if not rows:
        print("No documents found (is DATABASE_URL set correctly?)")
        sys.exit(1)

    _print_table(rows)

    if args.csv:
        _write_csv(rows, args.csv)


if __name__ == "__main__":
    main()
