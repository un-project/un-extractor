#!/usr/bin/env python3
"""Compute pairwise country voting-alignment time series from GA recorded votes.

For each pair of countries (A, B) and each year, computes the fraction of
resolutions where both countries cast the same vote (yes/no/abstain).
Non-voting / absent ballots are excluded from both numerator and denominator,
following the standard IR-literature convention.

    agreement_rate = matching_votes / co_votes

Results are stored in ``country_alignment_series``:

    country_id_a   INTEGER  -- lower id of the pair (A < B always)
    country_id_b   INTEGER  -- higher id of the pair
    year           INTEGER
    agreement_rate FLOAT    -- in [0, 1]
    n_votes        INTEGER  -- number of resolutions both voted on

Only pairs with at least ``--min-votes`` co-votes in a year are stored
(default: 10), to avoid noisy rates from thin data.

The table is populated incrementally: re-running the script is safe
(``ON CONFLICT DO UPDATE``).  Use ``--year`` to recompute a single year.

Usage
-----
    python scripts/compute_alignment_series.py
    python scripts/compute_alignment_series.py --db postgresql://...
    python scripts/compute_alignment_series.py --year 2022
    python scripts/compute_alignment_series.py --min-votes 20
    python scripts/compute_alignment_series.py --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_DEFAULT_MIN_VOTES = 10


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS country_alignment_series (
                id             SERIAL PRIMARY KEY,
                country_id_a   INTEGER NOT NULL REFERENCES countries(id) ON DELETE CASCADE,
                country_id_b   INTEGER NOT NULL REFERENCES countries(id) ON DELETE CASCADE,
                year           INTEGER NOT NULL,
                agreement_rate DOUBLE PRECISION NOT NULL,
                n_votes        INTEGER NOT NULL,
                UNIQUE (country_id_a, country_id_b, year),
                CHECK (country_id_a < country_id_b)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_cas_a_year "
            "ON country_alignment_series (country_id_a, year)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_cas_b_year "
            "ON country_alignment_series (country_id_b, year)"
        )
    )
    session.commit()
    log.info("country_alignment_series schema ready.")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _available_years(session: Session) -> list[int]:
    rows = session.execute(
        text(
            """
            SELECT DISTINCT EXTRACT(YEAR FROM d.date)::INTEGER AS yr
            FROM country_votes cv
            JOIN votes v ON v.id = cv.vote_id
            JOIN resolutions r ON r.id = v.resolution_id
            JOIN documents d ON d.id = v.document_id
            WHERE r.body = 'GA'
              AND cv.vote_position != 'non_voting'
              AND d.date IS NOT NULL
            ORDER BY yr
            """
        )
    ).fetchall()
    return [r[0] for r in rows if r[0] is not None]


def _compute_year(
    session: Session,
    year: int,
    min_votes: int,
    dry_run: bool,
) -> int:
    """Compute and upsert alignment rows for one year. Returns row count."""
    upsert_sql = text(
        """
        INSERT INTO country_alignment_series
            (country_id_a, country_id_b, year, agreement_rate, n_votes)
        SELECT
            LEAST(cv1.country_id, cv2.country_id)    AS country_id_a,
            GREATEST(cv1.country_id, cv2.country_id) AS country_id_b,
            :year,
            SUM(CASE WHEN cv1.vote_position = cv2.vote_position
                     THEN 1 ELSE 0 END)::DOUBLE PRECISION / COUNT(*),
            COUNT(*)
        FROM country_votes cv1
        JOIN country_votes cv2
            ON  cv2.vote_id = cv1.vote_id
            AND cv2.country_id != cv1.country_id
        JOIN votes v  ON v.id  = cv1.vote_id
        JOIN resolutions r ON r.id = v.resolution_id
        JOIN documents   d ON d.id = v.document_id
        WHERE r.body = 'GA'
          AND cv1.vote_position != 'non_voting'
          AND cv2.vote_position != 'non_voting'
          AND EXTRACT(YEAR FROM d.date)::INTEGER = :year
        GROUP BY country_id_a, country_id_b
        HAVING COUNT(*) >= :min_votes
        ON CONFLICT (country_id_a, country_id_b, year) DO UPDATE
            SET agreement_rate = EXCLUDED.agreement_rate,
                n_votes        = EXCLUDED.n_votes
        """
    )

    count_sql = text(
        """
        SELECT COUNT(DISTINCT (
            LEAST(cv1.country_id, cv2.country_id),
            GREATEST(cv1.country_id, cv2.country_id)
        ))
        FROM country_votes cv1
        JOIN country_votes cv2
            ON  cv2.vote_id = cv1.vote_id
            AND cv2.country_id != cv1.country_id
        JOIN votes v  ON v.id  = cv1.vote_id
        JOIN resolutions r ON r.id = v.resolution_id
        JOIN documents   d ON d.id = v.document_id
        WHERE r.body = 'GA'
          AND cv1.vote_position != 'non_voting'
          AND cv2.vote_position != 'non_voting'
          AND EXTRACT(YEAR FROM d.date)::INTEGER = :year
        GROUP BY LEAST(cv1.country_id, cv2.country_id),
                 GREATEST(cv1.country_id, cv2.country_id)
        HAVING COUNT(*) >= :min_votes
        """
    )

    params = {"year": year, "min_votes": min_votes}

    if dry_run:
        rows = session.execute(count_sql, params).fetchall()
        return len(rows)

    result = session.execute(upsert_sql, params)
    return result.rowcount  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def compute_alignment_series(
    db_url: str | None = None,
    only_year: int | None = None,
    min_votes: int = _DEFAULT_MIN_VOTES,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)
        years = _available_years(session)

    if only_year is not None:
        if only_year not in years:
            log.error("No GA vote data found for year %d.", only_year)
            sys.exit(1)
        years = [only_year]

    log.info(
        "Computing alignment series for %d year(s) (min_votes=%d)%s.",
        len(years),
        min_votes,
        " [dry-run]" if dry_run else "",
    )

    total_rows = 0

    with get_session(engine) as session:
        for year in years:
            n = _compute_year(session, year, min_votes, dry_run)
            log.info("  %d: %d pairs", year, n)
            total_rows += n
            if not dry_run:
                session.commit()

    action = "Would write" if dry_run else "Wrote"
    log.info("%s %d country-pair-year rows total.", action, total_rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Compute pairwise country voting-alignment time series "
            "from GA recorded votes."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--year",
        type=int,
        default=None,
        metavar="YYYY",
        help="Compute only this year",
    )
    p.add_argument(
        "--min-votes",
        type=int,
        default=_DEFAULT_MIN_VOTES,
        metavar="N",
        help="Minimum co-votes required to store a pair",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute counts without writing to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    compute_alignment_series(
        db_url=args.db,
        only_year=args.year,
        min_votes=args.min_votes,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
