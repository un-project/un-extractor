#!/usr/bin/env python3
"""Backfill GA vote tally counts from Voeten et al. Harvard Dataverse dataset.

The UNDL voting CSV only populates yes/no/abstain tally counts for recent
sessions.  The Voeten et al. dataset (doi:10.7910/DVN/LEJUQZ) covers all GA
recorded votes from 1946–present and includes per-resolution totals.

This script reads the already-cached ``data/undl/ga_voting.csv`` (downloaded
by ``import_undl_votes.py``) and backfills NULL tally columns in the ``votes``
table for GA votes.

Matching strategy (in order):
  1. ``votes.undl_id = csv.undl_id``           (direct, most reliable)
  2. ``resolutions.undl_id = csv.undl_id``     (via resolution FK)
  3. ``resolutions.adopted_symbol`` matches the CSV ``resolution`` field
     (both ``A/RES/57/60`` and short form ``57/60`` are tried)

Only rows where ``yes_count IS NULL`` are updated.

Usage
-----
    python scripts/import_harvard_ga_votes.py
    python scripts/import_harvard_ga_votes.py --db postgresql://...
    python scripts/import_harvard_ga_votes.py --csv data/undl/ga_voting.csv
    python scripts/import_harvard_ga_votes.py --dry-run
    python scripts/import_harvard_ga_votes.py --verbose

Source
------
  Voeten, E., Strezhnev, A., & Bailey, M. (2009). United Nations General
  Assembly Voting Data. Harvard Dataverse.
  https://doi.org/10.7910/DVN/LEJUQZ
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402

from src.db.database import get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_DEFAULT_CSV = Path(__file__).resolve().parents[1] / "data" / "undl" / "ga_voting.csv"


# ---------------------------------------------------------------------------
# Load tallies from CSV
# ---------------------------------------------------------------------------


def _load_tallies(
    csv_path: Path,
) -> tuple[dict[str, tuple[int | None, ...]], dict[str, tuple[int | None, ...]]]:
    """Parse the CSV and return two lookup dicts.

    Returns:
        by_undl_id:  {undl_id_str: (yes, no, abstain, non_voting, total_ms)}
        by_symbol:   {adopted_symbol: (yes, no, abstain, non_voting, total_ms)}
                     Keys include both full form (``A/RES/57/60``) and short
                     form (``57/60``) so callers can probe either.
    """
    by_undl_id: dict[str, tuple[int | None, ...]] = {}
    by_symbol: dict[str, tuple[int | None, ...]] = {}

    def _safe_int(val: str) -> int | None:
        try:
            f = float(val)
            return int(f)
        except (ValueError, TypeError):
            return None

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            undl_id = row.get("undl_id", "").strip()
            if not undl_id or undl_id in by_undl_id:
                continue  # deduplicate — tally is same for all country rows

            yes = _safe_int(row.get("total_yes", ""))
            no = _safe_int(row.get("total_no", ""))
            abstain = _safe_int(row.get("total_abstentions", ""))
            non_voting = _safe_int(row.get("total_non_voting", ""))
            total_ms = _safe_int(row.get("total_ms", ""))

            if yes is None and no is None:
                continue  # no useful tally data

            tally = (yes, no, abstain, non_voting, total_ms)
            by_undl_id[undl_id] = tally

            # Build symbol lookup (full form and short form)
            resolution = row.get("resolution", "").strip()
            if resolution:
                by_symbol[resolution] = tally
                # A/RES/57/60 → 57/60
                if resolution.startswith("A/RES/"):
                    by_symbol[resolution[len("A/RES/"):]] = tally

    return by_undl_id, by_symbol


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def backfill_tallies(
    db_url: str | None = None,
    csv_path: Path | None = None,
    dry_run: bool = False,
) -> None:
    if csv_path is None:
        csv_path = _DEFAULT_CSV

    if not csv_path.exists():
        log.error(
            "CSV not found at %s — run import_undl_votes.py first to download it.",
            csv_path,
        )
        sys.exit(1)

    log.info("Loading tallies from %s …", csv_path)
    by_undl_id, by_symbol = _load_tallies(csv_path)
    log.info(
        "Loaded %d resolution tally records (%d symbol keys).",
        len(by_undl_id),
        len(by_symbol),
    )

    engine = get_engine(db_url)

    with get_session(engine) as session:
        # Fetch all GA votes missing tally counts, with join data for matching
        rows = session.execute(
            text(
                """
                SELECT v.id, v.undl_id, r.undl_id AS r_undl_id, r.adopted_symbol
                FROM votes v
                JOIN resolutions r ON r.id = v.resolution_id
                WHERE r.body = 'GA'
                  AND v.yes_count IS NULL
                ORDER BY v.id
                """
            )
        ).fetchall()

    log.info("Found %d GA votes with missing tally counts.", len(rows))

    updated = skipped = 0

    with get_session(engine) as session:
        for vote_id, vote_undl_id, res_undl_id, adopted_symbol in rows:
            tally = None

            # 1. Direct match via votes.undl_id
            if vote_undl_id:
                tally = by_undl_id.get(str(vote_undl_id))

            # 2. Match via resolutions.undl_id
            if tally is None and res_undl_id:
                tally = by_undl_id.get(str(res_undl_id))

            # 3. Match via adopted_symbol (full and short form)
            if tally is None and adopted_symbol:
                tally = by_symbol.get(adopted_symbol)

            if tally is None:
                log.debug("No tally match for vote id=%d symbol=%s", vote_id, adopted_symbol)
                skipped += 1
                continue

            yes, no, abstain, non_voting, total_ms = tally

            if not dry_run:
                session.execute(
                    text(
                        """
                        UPDATE votes SET
                            yes_count        = :yes,
                            no_count         = :no,
                            abstain_count    = :abstain,
                            total_non_voting = :non_voting,
                            total_ms         = :total_ms
                        WHERE id = :id
                        """
                    ),
                    {
                        "yes": yes,
                        "no": no,
                        "abstain": abstain,
                        "non_voting": non_voting,
                        "total_ms": total_ms,
                        "id": vote_id,
                    },
                )

            updated += 1

        if not dry_run:
            session.commit()

    action = "Would update" if dry_run else "Updated"
    log.info(
        "%s %d votes with tally counts; %d had no match in CSV.",
        action,
        updated,
        skipped,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description="Backfill GA vote tally counts from Voeten et al. Harvard Dataverse.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--csv",
        default=None,
        metavar="PATH",
        help="Path to ga_voting.csv (default: data/undl/ga_voting.csv)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Match and log without writing to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    backfill_tallies(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
